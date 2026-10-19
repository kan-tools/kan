#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("evidence", ROOT / "scripts/perf_failure_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTest(unittest.TestCase):
    def test_exact_bounded_log_only_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); source = root / "scratch"; log = source / ".kan/log"
            log.mkdir(parents=True)
            (log / "repo.car").write_bytes(b"synthetic canonical bytes")
            (log / "HEAD").write_bytes(b"synthetic head")
            (log / "key").write_bytes(b"DO NOT EXPORT")
            (source / ".kan-system").mkdir()
            (source / ".kan-system/private-key").write_bytes(b"DO NOT EXPORT")
            out = evidence.collect(source, root / "out", 50, 4, 7)
            self.assertEqual({p.name for p in out.iterdir()}, {"repo.car", "HEAD", "manifest.json"})
            self.assertEqual((out / "repo.car").read_bytes(), (log / "repo.car").read_bytes())
            self.assertEqual(json.loads((out / "manifest.json").read_text())["files"]["repo.car"]["state"], "retained")
            with self.assertRaises(FileExistsError): evidence.collect(source, root / "out", 50, 4, 7)
            limit = evidence.MAX_BYTES
            try:
                evidence.MAX_BYTES = 2
                bounded = evidence.collect(source, root / "bounded", 50, 4, 7)
                self.assertFalse((bounded / "repo.car").exists())
                self.assertEqual(json.loads((bounded / "manifest.json").read_text())["files"]["repo.car"]["state"], "over-budget")
            finally: evidence.MAX_BYTES = limit

    def test_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); log = root / "scratch/.kan/log"; log.mkdir(parents=True)
            (root / "private").write_bytes(b"DO NOT EXPORT")
            (log / "repo.car").symlink_to(root / "private")
            with self.assertRaises(OSError): evidence.collect(root / "scratch", root / "out", 50, 4, 7)
            self.assertFalse((root / "out/claims-50-subjects-4-failed-7/repo.car").exists())

    def test_generation_failure_stays_failed_and_retains_only_synthetic_log(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fake = root / "fake-kan"
            fake.write_text('''#!/usr/bin/env python3
from pathlib import Path
import sys
if sys.argv[1] == 'init':
    Path('.kan/log').mkdir(parents=True)
    Path('.kan/log/repo.car').write_bytes(b'synthetic failing input')
    Path('.kan/log/HEAD').write_bytes(b'synthetic head')
elif sys.argv[1] == 'observe':
    print('synthetic canonicality failure', file=sys.stderr)
    raise SystemExit(7)
''')
            fake.chmod(0o700)
            env = dict(os.environ, PERF_SMOKE="1", KAN_PERF_FAILURE_DIR=str(root / "evidence"))
            run = subprocess.run(["bash", str(ROOT / "scripts/run-perf-grid.sh"), "measure", str(fake)],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("synthetic canonicality failure", run.stderr)
            outputs = list((root / "evidence").glob("*/repo.car"))
            self.assertEqual(len(outputs), 1, run.stderr)
            self.assertEqual(outputs[0].read_bytes(), b"synthetic failing input")


if __name__ == '__main__': unittest.main()
