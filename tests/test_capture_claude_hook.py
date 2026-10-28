import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hook', Path(__file__).parents[1] / 'scripts/capture-claude-hook.py')
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

class CaptureHook(unittest.TestCase):
    def test_exact_hook_and_separate_subagent_transcript(self):
        with tempfile.TemporaryDirectory() as root:
            transcript = Path(root) / 'subagent.jsonl'
            transcript.write_bytes(b'{"type":"assistant"}\n')
            args = SimpleNamespace(kan='kan', spool='spool', key='key', recipient='recipient', transcript_root=root, timeout=60)
            raw = json.dumps({'session_id':'id', 'hook_event_name':'SubagentStop', 'agent_transcript_path':str(transcript)}).encode() + b'\n'
            ok = SimpleNamespace(returncode=0, stdout=b'{"health":{"recording_gap":false}}')
            with patch.object(hook.subprocess, 'run', return_value=ok) as run:
                hook.run(args, raw)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args_list[0].kwargs['input'], raw)
                self.assertEqual(run.call_args_list[1].args[0][-2:], ['--input',str(transcript.resolve())])
                bad=json.loads(raw);bad['agent_transcript_path']='/etc/hosts'
                with self.assertRaises(ValueError): hook.run(args,json.dumps(bad).encode())
            gap = SimpleNamespace(returncode=0, stdout=b'{"health":{"recording_gap":true}}')
            with patch.object(hook.subprocess, 'run', return_value=gap):
                with self.assertRaises(RuntimeError): hook.run(args,raw)

if __name__ == '__main__': unittest.main()
