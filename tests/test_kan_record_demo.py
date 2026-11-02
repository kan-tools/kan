"""Small orchestration boundaries; no Kan binary or model is executed."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('demo', Path(__file__).resolve().parents[1] / 'scripts/kan-record-demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / 'work'
        self.work.mkdir(mode=0o700)
        self.binary = self.root / 'kan'
        self.binary.write_bytes(b'synthetic binary identity, never executed')
        self.profile = self.root / 'profile.json'
        self.profile.write_text(json.dumps({'allowed_worktrees': [str(self.work)]}))
        self.profile.chmod(0o600)
        self.output = self.root / 'operator-evidence'
        self.value = demo.Demo(self.binary, self.profile, self.output, self.work)
        self.calls = []
        self.plan = {'selection': {'source': 'selected', 'from': 1, 'through': 3, 'pin': {'exact': True}}, 'model': 'synthetic-model', 'recipe': {'id': 'documentation-summary', 'revision': '1'}, 'digest': 'frozen', 'nonce': 'exact'}

    def tearDown(self):
        self.temp.cleanup()

    def response(self, value, code=0):
        def run(args, **kwargs):
            self.calls.append(args)
            self.assertEqual(kwargs['cwd'], self.work)
            return subprocess.CompletedProcess(args, code, json.dumps(value).encode(), b'synthetic diagnostics')
        return run

    def freeze(self):
        with patch.object(subprocess, 'run', self.response(self.plan)):
            self.value.freeze(1, 3)

    def test_freeze_is_not_provider_execution_and_never_replaces_prior_inputs(self):
        self.freeze()
        self.assertNotIn('--run', self.calls[0])
        self.assertEqual(demo.private_json(self.output / 'plan.json'), self.plan)
        self.assertFalse(demo.private_json(self.output / 'frozen.json')['provider_called'])
        with self.assertRaises(ValueError):
            self.value.freeze(1, 3)
        self.assertEqual(len(self.calls), 1)

    def test_changed_frozen_plan_refuses_before_any_submission(self):
        self.freeze()
        (self.output / 'plan.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.value.extract()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.output / 'extraction-start.json').exists())

    def test_failed_submission_retains_diagnostics_and_never_retries(self):
        self.freeze()
        with patch.object(subprocess, 'run', self.response({'error': 'synthetic'}, 1)):
            with self.assertRaises(RuntimeError):
                self.value.extract()
            with self.assertRaises(FileExistsError):
                self.value.extract()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(demo.private_json(self.output / 'extraction-terminal.json')['state'], 'failed-or-unknown')
        self.assertEqual(demo.private_json(self.output / 'command-0001.json')['stderr'], 'synthetic diagnostics')

    def test_readback_follows_exact_presentation_cursor_without_another_model_call(self):
        self.freeze()
        with patch.object(subprocess, 'run', self.response({'state': 'succeeded', 'id': 'report-id'})):
            self.value.extract()
        pages = iter([{'blocks': [{'text': 'é🙂'}], 'next': {'binding': 'exact', 'row': 1, 'offset': 0}}, {'blocks': [{'text': 'rest'}], 'next': None}])
        with patch.object(subprocess, 'run', lambda args, **kwargs: self.response(next(pages))(args, **kwargs)):
            result = self.value.read('derived')
        self.assertEqual(result['pages'], 2)
        self.assertNotIn('--run', self.calls[-1])
        self.assertIn('--cursor', self.calls[-1])
        self.assertEqual(json.loads(self.calls[-1][self.calls[-1].index('--cursor') + 1])['binding'], 'exact')
        self.assertIn('not-assessed', result['task_acceptance'])
        with self.assertRaises(ValueError):
            demo.Demo(self.binary, self.profile, self.work / 'evidence', self.work)
        with self.assertRaises(ValueError):
            demo.Demo(self.binary, self.profile, self.output, self.root)


if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
