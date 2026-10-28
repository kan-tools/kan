#!/usr/bin/env python3
"""Reviewer probe for F4: does run_bounded stop a whole process tree, and does a timeout
raise instead of counting as a demonstrated assertion? Uses the author's real helper."""
import importlib.util, os, subprocess, sys, tempfile, time
from pathlib import Path
E = Path(sys.argv[1]); out = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('controls', E / 'scripts/operations_review_negative_controls.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.OUT.mkdir(parents=True, exist_ok=True)
def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False
results = []
# (1) synthetic tree: python child spawns a grandchild that heartbeats forever.
with tempfile.TemporaryDirectory() as d:
    pidfile = Path(d) / 'grandchild.pid'; beat = Path(d) / 'beat'
    gscript = Path(d) / 'grandchild.py'; cscript = Path(d) / 'child.py'
    gscript.write_text(f"import os,time\nopen({str(pidfile)!r},'w').write(str(os.getpid()))\nwhile True:\n    open({str(beat)!r},'a').write('x'); time.sleep(0.1)\n")
    cscript.write_text(f"import subprocess,sys,time\nsubprocess.Popen([sys.executable,{str(gscript)!r}])\ntime.sleep(3600)\n")
    child = None
    t = time.time()
    try:
        m.run_bounded([sys.executable, str(cscript)], 'reviewer-synthetic-tree', timeout_seconds=2)
        results.append('synthetic: NO TIMEOUT RAISED (bad)')
    except RuntimeError as e:
        results.append(f'synthetic: raised {e!r} after {time.time()-t:.1f}s')
    time.sleep(0.5)
    gpid = int(pidfile.read_text()); size1 = beat.stat().st_size; time.sleep(0.5); size2 = beat.stat().st_size
    results.append(f'synthetic: grandchild {gpid} alive={alive(gpid)} heartbeat_grew={size2>size1}')
# (2) real A13 mutant (queued action never cleared) under the imported real-timer suite.
APP = E / 'web/operations/app.js'; original = APP.read_bytes(); s = original.decode()
a = "const queued=overviewQueued;overviewQueued='';if(queued)"; assert s.count(a) == 1
try:
    APP.write_text(s.replace(a, 'const queued=overviewQueued;if(queued)'))
    before = set(subprocess.run(['pgrep', '-f', 'node'], capture_output=True, text=True).stdout.split())
    t = time.time()
    try:
        r = m.run_bounded(['node', '--test', 'tests/operations_review_ui.test.cjs'], 'reviewer-a13-real-timers', timeout_seconds=20)
        results.append(f'a13: completed rc={r.returncode} in {time.time()-t:.1f}s; AssertionError={"AssertionError" in r.stdout+r.stderr}')
    except RuntimeError as e:
        results.append(f'a13: raised {e!r} after {time.time()-t:.1f}s')
    time.sleep(1)
    after = set(subprocess.run(['pgrep', '-f', 'node --test'], capture_output=True, text=True).stdout.split())
    results.append(f'a13: node --test processes remaining={sorted(after)}')
finally:
    APP.write_bytes(original)
results.append('app.js restored=' + str(APP.read_bytes() == original))
out.write_text('\n'.join(results) + '\n'); print('\n'.join(results))
