import importlib.util
from pathlib import Path
import unittest
import tempfile
import subprocess
import sys
import time
import os
import signal
import threading
spec = importlib.util.spec_from_file_location('revert_v2', Path(__file__).resolve().parents[1] / 'scripts/revert_v2.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class Results(unittest.TestCase):
    def test_exact_assertions(self):
        self.assertEqual(runner.parse_result('node', 'a', 'ok 1 - a\nnot ok 2 - ab', 0), ({'a'}, set()))
        self.assertEqual(runner.parse_result('node', 'a', 'not ok 1 - a', 1), ({'a'}, {'a'}))
        self.assertEqual(runner.parse_result('lib', 'a::b', 'test a::b ... FAILED', 101), ({'a::b'}, {'a::b'}))
    def test_python_assertions_are_distinct_from_errors_and_skips(self):
        for name in ('__main__.Execution', '__main__.Execution.sample'):
            self.assertEqual(runner.parse_result('python','Execution.sample',f'sample ({name}) ... ok',0),({'Execution.sample'},set()))
            self.assertEqual(runner.parse_result('python','Execution.sample',f'sample ({name}) ... FAIL',1),({'Execution.sample'},{'Execution.sample'}))
            with self.assertRaises(ValueError):
                runner.parse_result('python','Execution.sample',f'sample ({name}) ... ERROR',1)
        self.assertEqual(runner.parse_result('python','Execution.sample',"sample (__main__.Execution) ... skipped 'reason'",0),(set(),set()))
        self.assertEqual(runner.parse_result('python','Execution.sample','sample (__main__.Other) ... FAIL',1),(set(),set()))
    def test_ignored_duplicate_missing_or_crashed_are_not_passes(self):
        for output in ('ok 1 - a # SKIP', 'ok 1 - a # TODO', 'ok 1 - ab', 'ok 1 - a\nok 2 - a', 'test a ... ignored', ''):
            self.assertEqual(runner.parse_result('node', 'a', output, 0), (set(), set()))
        for output, code in [('ok 1 - a', 1), ('not ok 1 - a', 0)]:
            with self.assertRaises(ValueError):
                runner.parse_result('node', 'a', output, code)

class Execution(unittest.TestCase):
    def test_export_isolated_including_untracked_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source'; root.mkdir()
            subprocess.run(['git','init','-q',str(root)],check=True)
            (root/'tracked').write_text('original')
            subprocess.run(['git','add','tracked'],cwd=root,check=True)
            (root/'untracked').write_text('new')
            dest=Path(tmp)/'export'; dest.mkdir()
            runner.export(root,dest,None)
            self.assertEqual((dest/'untracked').read_text(),'new')
            (dest/'tracked').write_text('changed')
            self.assertEqual((root/'tracked').read_text(),'original')
            if os.name=='posix':
                (root/'link').symlink_to(root/'tracked')
                with self.assertRaises(ValueError):
                    runner.export(root,Path(tmp)/'rejected',None)
    def timeout_probe(self, detached):
        with tempfile.TemporaryDirectory() as tmp:
            ticks=Path(tmp)/'ticks'; child_pid=Path(tmp)/'child.pid'; parent_pid=Path(tmp)/'parent.pid'
            child="import os,time; from pathlib import Path; Path("+repr(str(child_pid))+").write_text(str(os.getpid())); p=Path("+repr(str(ticks))+");\nwhile True:\n p.open('a').write('x'); time.sleep(.02)"
            parent="import os,subprocess,sys,time; from pathlib import Path; Path("+repr(str(parent_pid))+").write_text(str(os.getpid())); subprocess.Popen([sys.executable,'-c',"+repr(child)+"],start_new_session="+repr(detached)+"); time.sleep(30)"
            result=[]
            def invoke():
                try: result.append(runner.run_process([sys.executable,'-c',parent],tmp,1))
                except BaseException as error: result.append(error)
            worker=threading.Thread(target=invoke,daemon=True)
            worker.start()
            try:
                # Independent watchdog: a broken production drain must fail an
                # assertion, not hang the test process or leave a probe behind.
                worker.join(8)
                self.assertFalse(worker.is_alive(),'timeout cleanup exceeded its outer watchdog')
                self.assertTrue(result)
                self.assertIsInstance(result[0],subprocess.TimeoutExpired)
                self.assertTrue(ticks.exists(),'descendant must actually run')
                size=ticks.stat().st_size; time.sleep(.15)
                if not detached:
                    self.assertEqual(ticks.stat().st_size,size,'timeout left test descendant running')
                else:
                    self.assertGreater(ticks.stat().st_size,size,'probe must own an escaped pipe holder')
            finally:
                # These PIDs came only from this test's own subprocesses.
                for path in (child_pid, parent_pid):
                    if path.exists():
                        try:
                            os.kill(int(path.read_text()),signal.SIGKILL)
                        except ProcessLookupError: pass
                worker.join(2)
    @unittest.skipUnless(os.name=='posix','requires POSIX process groups')
    def test_timeout_stops_descendant_writes(self):
        self.timeout_probe(False)
    @unittest.skipUnless(os.name=='posix','requires POSIX process groups')
    def test_detached_pipe_holder_cannot_hang_timeout_cleanup(self):
        self.timeout_probe(True)
    def test_process_exit_status_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=runner.run_process([sys.executable,'-c',"print('not ok 1 - named'); raise SystemExit(7)"],tmp,3)
            self.assertEqual(result.returncode,7)
            self.assertEqual(runner.parse_result('node','named',result.stdout,result.returncode),({'named'},{'named'}))

if __name__ == '__main__':
    unittest.main()
