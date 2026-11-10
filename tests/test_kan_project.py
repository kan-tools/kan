import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('project', Path(__file__).parents[1] / 'scripts/kan-project.py')
project = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project)


class ProjectIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.other = self.root / 'second-worktree'
        self.other.mkdir()
        self.transcripts = self.root / 'actual-harness-directory-with-unexpected-encoding'
        self.transcripts.mkdir()
        self.transcript = self.transcripts / 'session.jsonl'
        self.transcript.write_text('{"type":"assistant","text":"synthetic"}\n')
        self.binary = self.root / 'kan'
        self.binary.write_text('#!/bin/sh\nexit 1\n')
        self.binary.chmod(0o700)
        self.config = self.root / 'config.json'
        self.settings = {'version': 1, 'binary': str(self.binary),
                         'project_roots': [str(self.work), str(self.other)],
                         'transcript_roots': [str(self.transcripts)],
                         'runtime': str(self.runtime), 'recipient': '01' * 32,
                         'endpoint': 'http://127.0.0.1:17381/v1/rpc', 'services': [],
                         'startup_seconds': 1, 'timeout_seconds': 1}
        for field in ['spool', 'writer_key', 'reader_config', 'reader_key']:
            f = self.root / field
            f.write_bytes(b'synthetic-private-value')
            f.chmod(0o600)
            self.settings[field] = str(f)
        self.write_config()
        self.p = project.Project(str(self.config))
        self.calls = []

    def write_config(self):
        self.config.write_text(json.dumps(self.settings))
        self.config.chmod(0o600)

    def event(self, **changes):
        v = {'cwd': str(self.work), 'session_id': 'actual-session',
             'hook_event_name': 'Stop', 'transcript_path': str(self.transcript)}
        v.update(changes)
        return json.dumps(v).encode()

    def fake(self, args, **kw):
        self.calls.append((list(map(str, args)), kw))
        if 'spool-status' in args:
            out = {'status': {'pending': 0, 'pending_bytes': 0, 'next': 10}}
        elif 'harness-capture' in args:
            out = {'health': {'recording_gap': False}, 'durability': 'local-spool'}
        else:
            out = {}
        return SimpleNamespace(returncode=0, stdout=json.dumps(out).encode(), stderr=b'')

    def test_two_explicit_worktrees_and_no_other_project(self):
        self.assertEqual(self.p.check(self.work)['status'], 'configured')
        self.assertEqual(self.p.check(self.other)['status'], 'configured')
        with self.assertRaises(project.Problem):
            self.p.check(self.root)
        self.assertIn('Day/v1', self.p.check(self.work)['project_contract'])
        self.assertNotIn('synthetic-private-value', json.dumps(self.p.check(self.work)))

    def test_finalization_wait_does_not_hold_capture_lock(self):
        running, release = threading.Event(), threading.Event()
        def drain(p):
            running.set()
            if not release.wait(4):
                raise RuntimeError('test release missing')
            return {'state': 'processed'}
        with patch.object(self.p, 'consolidator', return_value=SimpleNamespace(process=drain)), \
             patch.object(project.Path, 'cwd', return_value=self.work), \
             patch.object(project.subprocess, 'run', side_effect=self.fake), \
             ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.p.process_finalized)
            try:
                self.assertTrue(running.wait(2))
                # A real capture uses the same project runtime while the fake
                # inference remains blocked. No model/service is started.
                result = self.p.capture(self.event(cwd=str(self.other)))
                self.assertEqual(result['status'], 'acknowledged')
            finally:
                release.set()
            self.assertEqual(future.result(timeout=2)['state'], 'processed')

    def test_actual_transcript_path_and_final_snapshot_are_separate_captures(self):
        with patch.object(project.subprocess, 'run', side_effect=self.fake):
            r = self.p.capture(self.event())
        self.assertEqual(r['status'], 'acknowledged')
        captures = [a for a, kw in self.calls if 'harness-capture' in a]
        self.assertEqual(len(captures), 2)
        self.assertIn(str(self.transcript), captures[1])
        self.assertNotIn(str(self.transcript), captures[0])
        self.assertEqual(r['capture_completeness'], 'not-verified')

    def test_out_of_scope_and_symlink_paths_are_refused_before_capture(self):
        outside = self.root / 'outside.jsonl'
        outside.write_text('not selected')
        link = self.transcripts / 'link.jsonl'
        link.symlink_to(outside)
        with patch.object(project.subprocess, 'run', side_effect=self.fake):
            for path in [outside, link]:
                r = self.p.capture(self.event(transcript_path=str(path)))
                self.assertEqual(r['status'], 'capture-failed')
        self.assertEqual(self.calls, [])

    def test_backfill_never_erases_historical_gap(self):
        with patch.object(project.subprocess, 'run', side_effect=self.fake):
            gap = self.p.capture(self.event(transcript_path=str(self.root / 'missing')))
            self.assertEqual(gap['status'], 'capture-failed')
            backfill = self.p.capture(self.event(hook_event_name='KanFinalSnapshot', origin='explicit-operator-backfill'), True)
            self.assertEqual(backfill['status'], 'acknowledged')
            health = self.p.health()
        self.assertEqual(health['historical_capture_gaps'], 1)
        self.assertEqual(health['explicit_backfills'], 1)
        self.assertEqual(health['delivery']['pending'], 0)
        self.assertEqual(health['capture_completeness'], 'not-verified')

    def test_queue_is_not_acknowledged_on_failed_drain(self):
        def fail(args, **kw):
            if 'spool-drain' in args:
                return SimpleNamespace(returncode=1, stdout=b'', stderr=b'private-error')
            if 'spool-status' in args:
                return SimpleNamespace(returncode=0, stdout=b'{"status":{"pending":4,"pending_bytes":128,"next":10}}')
            return self.fake(args, **kw)
        with patch.object(project.subprocess, 'run', side_effect=fail):
            r = self.p.capture(self.event(hook_event_name='PostToolUse'))
        self.assertEqual(r['status'], 'queued')
        self.assertEqual(r['delivery']['pending'], 4)
        self.assertNotIn('private-error', json.dumps(r))

    def test_capture_gap_retains_partial_outcomes(self):
        count = 0
        def fail(args, **kw):
            nonlocal count
            if 'harness-capture' in args:
                count += 1
                if count == 2:
                    return SimpleNamespace(returncode=0, stdout=b'{"health":{"recording_gap":true}}')
            return self.fake(args, **kw)
        with patch.object(project.subprocess, 'run', side_effect=fail):
            r = self.p.capture(self.event())
        self.assertEqual(r['status'], 'capture-failed')
        self.assertIn('hook', r['capture'])
        self.assertNotIn('transcript', r['capture'])

    def test_private_permissions_and_unknown_config_fields(self):
        Path(self.settings['writer_key']).chmod(0o644)
        with self.assertRaises(project.Problem):
            self.p.check(self.work)
        self.settings['private-secret-extra'] = 'private-secret-value'
        self.write_config()
        with self.assertRaises(project.Problem) as e:
            project.Project(str(self.config))
        self.assertNotIn('private-secret', str(e.exception))

    def test_project_identity_and_real_event_cwd_required(self):
        for raw in [self.event(cwd=str(self.root)), self.event(cwd=None), self.event(session_id='')]:
            with patch.object(project.subprocess, 'run', side_effect=self.fake):
                r = self.p.capture(raw)
            self.assertEqual(r['status'], 'capture-failed')
        self.assertEqual(self.calls, [])

    def test_generated_settings_opt_in_and_reader_only(self):
        settings = self.p.settings()
        self.assertIn('SubagentStop', settings['settings']['hooks'])
        command = settings['settings']['hooks']['Stop'][0]['hooks'][0]['command']
        self.assertIn('--config', command)
        self.assertIn(str(self.config), command)
        args = settings['mcp']['mcpServers']['kan']['args']
        self.assertIn('--mcp', args)
        self.assertNotIn('--mcp-writes', args)
        self.assertNotIn('--mcp-owner', args)
        self.assertFalse((self.work / '.claude').exists())

    def test_readiness_uses_configured_budget_and_reports_exit(self):
        from unittest.mock import MagicMock
        self.p.startup = 30
        proc = SimpleNamespace(poll=lambda: None)
        connection = MagicMock()
        with patch.object(project.socket, 'create_connection', side_effect=[OSError(), OSError(), connection]), patch.object(project.time, 'monotonic', side_effect=[0, 6, 12]), patch.object(project.time, 'sleep'):
            self.p.listener_ready(proc, '127.0.0.1', 1234, 'serve-proof')
        with self.assertRaises(project.Problem) as e, patch.object(project.socket, 'create_connection', side_effect=OSError()), patch.object(project.time, 'monotonic', side_effect=[0, 31]), patch.object(project.time, 'sleep'):
            self.p.listener_ready(proc, '127.0.0.1', 1234, 'serve-proof')
        self.assertEqual(e.exception.code, 'listener-readiness-budget-exhausted')
        with self.assertRaises(project.Problem) as e:
            self.p.listener_ready(SimpleNamespace(poll=lambda: 1), '127.0.0.1', 1234, 'serve-proof')
        self.assertEqual(e.exception.code, 'service-exited-inspect-private-log')

    def test_stop_refuses_a_reused_process_identity(self):
        project.atomic_json(self.runtime / 'services.json', [{'pid': 1234, 'identity': 'owned service'}])
        result = SimpleNamespace(returncode=0, stdout='some other process')
        with patch.object(project.subprocess, 'run', return_value=result), patch.object(project.os, 'kill') as kill:
            with self.assertRaises(project.Problem):
                self.p.stop()
            kill.assert_not_called()
        self.assertTrue(json.loads((self.runtime / 'services.json').read_text()))


if __name__ == '__main__':
    unittest.main()
