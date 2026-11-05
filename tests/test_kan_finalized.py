import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


finalized = load('finalized', 'kan-finalized.py')
project = load('project', 'kan-project.py')


class Finalization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.profile = self.root / 'profile.json'
        finalized.create(self.profile, {'source': 'proof:synthetic', 'reader_config': '/private/reader.json',
                                      'signing_key': '/private/key', 'allowed_worktrees': [str(self.root)]})
        self.p = SimpleNamespace(runtime=self.root, binary=Path('/private/kan'),
                                 private_directory=project.Project.private_directory,
                                 private_json=project.Project.private_json,
                                 c={'consolidation': {'profile': str(self.profile), 'recipes': ['session-brief'], 'max_jobs': 2}})
        self.record = {'hook_event': 'SessionEnd', 'status': 'acknowledged', 'session_sha256': 'a' * 64,
                       'capture': {'transcript': {'health': {'attempt': 'b' * 64, 'recording_gap': False, 'observed': 3}}}}

    def rows(self, sequences=(10, 11, 12)):
        return [{'record': {'sequence': str(sequence)}, 'description': {'attempt': 'b' * 64, 'ordinal': str(n)}}
                for n, sequence in enumerate(sequences)]

    def test_disabled_and_nonterminal_never_enqueue_or_execute(self):
        self.p.c.clear()
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'disabled')
        self.assertFalse((self.root / 'consolidation').exists())
        self.p.c['consolidation'] = {'profile': str(self.profile), 'recipes': ['session-brief'], 'max_jobs': 1}
        self.record['hook_event'] = 'Stop'
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'not-finalization')

    def test_duplicate_events_and_lifetime_job_quota(self):
        first = finalized.queue(self.p, self.record)
        self.assertEqual(first['state'], 'queued')
        self.assertEqual(finalized.queue(self.p, self.record), {'state': 'already-queued', 'id': first['id']})
        self.record['capture']['transcript']['health']['attempt'] = 'c' * 64
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'queued')
        self.record['capture']['transcript']['health']['attempt'] = 'd' * 64
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'quota-exhausted')
        for path in (self.root / 'consolidation').glob('*.json'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unacknowledged_gaps_and_oversized_snapshots_do_not_schedule(self):
        self.record['status'] = 'queued'
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'not-scheduled')
        self.record['status'] = 'acknowledged'
        self.record['capture']['transcript']['health']['recording_gap'] = True
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'not-scheduled')
        self.record['capture']['transcript']['health'].update(recording_gap=False, observed=9)
        self.assertEqual(finalized.queue(self.p, self.record)['state'], 'not-scheduled')

    def test_frozen_interval_refuses_missing_ordinals_and_interleaved_attempts(self):
        self.assertEqual(finalized.interval(list(reversed(self.rows())), 'b' * 64, 3), (10, 12))
        for rows in [self.rows()[:2], self.rows((10, 12, 13)), [self.rows()[0]] * 3]:
            with self.assertRaises(ValueError):
                finalized.interval(rows, 'b' * 64, 3)

    def test_submits_frozen_plan_once_and_restart_does_not_resend(self):
        queued = finalized.queue(self.p, self.record)
        calls = []
        pin = {'request': 'synthetic signed pin', 'reply': {}}

        def fake(args, **kwargs):
            calls.append(args)
            if 'library' in args:
                request = json.loads(Path(args[args.index('--request') + 1]).read_bytes())
                value = pin if request['action'] == 'proof-snapshot' else {'records': self.rows(), 'next': None}
            elif '--run' in args:
                frozen = json.loads(Path(args[args.index('--plan') + 1]).read_bytes())
                self.assertEqual(frozen['selection']['pin'], pin)
                value = {'id': 'e' * 64, 'state': 'succeeded'}
            else:
                self.assertIn('--finalized-attempt', args)
                self.assertEqual(json.loads(Path(args[args.index('--pin-file') + 1]).read_bytes()), pin)
                value = {'selection': {'pin': pin}, 'digest': 'synthetic', 'nonce': 'synthetic'}
            kwargs['stdout'].write(json.dumps(value).encode())
            return SimpleNamespace(returncode=0)

        with patch.object(finalized.subprocess, 'run', side_effect=fake), patch.object(finalized.Path, 'cwd', return_value=self.root):
            result = finalized.process(self.p)
            self.assertEqual(result, {'state': 'processed', 'id': queued['id'], 'jobs': 1})
            self.assertEqual(finalized.process(self.p)['state'], 'no-unstarted-events')
        self.assertEqual(sum('--run' in args for args in calls), 1)

    def test_ambiguous_submission_is_retained_and_never_retried(self):
        queued = finalized.queue(self.p, self.record)
        with patch.object(finalized.subprocess, 'run', side_effect=finalized.subprocess.TimeoutExpired('kan', 120)), patch.object(finalized.Path, 'cwd', return_value=self.root):
            self.assertEqual(finalized.process(self.p)['state'], 'not-completed')
            self.assertEqual(finalized.process(self.p)['state'], 'no-unstarted-events')
        self.assertTrue((self.root / 'consolidation' / queued['id'] / 'failure.json').exists())

    def test_overall_deadline_cannot_multiply_by_discovery_pages(self):
        finalized.queue(self.p, self.record)
        times = iter([0, 30, 121])
        calls = []
        def fake(args, **kwargs):
            calls.append(kwargs['timeout'])
            kwargs['stdout'].write(json.dumps({'request':'synthetic pin','reply':{}}).encode())
            return SimpleNamespace(returncode=0)
        with patch.object(finalized.time, 'monotonic', side_effect=lambda: next(times)), patch.object(finalized.subprocess, 'run', side_effect=fake), patch.object(finalized.Path, 'cwd', return_value=self.root):
            self.assertEqual(finalized.process(self.p)['state'], 'not-completed')
        self.assertEqual(calls, [90])
        self.assertEqual(finalized.process(self.p)['state'], 'no-unstarted-events')

    def test_changed_policy_needs_new_explicit_plan_not_silent_resend(self):
        finalized.queue(self.p, self.record)
        self.p.c['consolidation']['recipes'] = ['handoff-context']
        with patch.object(finalized.subprocess, 'run') as run:
            self.assertEqual(finalized.process(self.p)['state'], 'not-completed')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
