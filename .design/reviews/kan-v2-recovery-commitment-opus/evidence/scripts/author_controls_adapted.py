#!/usr/bin/env python3
"""Run the author's scripts/recovery_commitment_negative_controls.py unmodified,
with OUT redirected into review-evidence and --offline added to its cargo calls.
Usage: author_controls_adapted.py <out-dir>
"""
import importlib.util, subprocess, sys
from pathlib import Path
E = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment')
spec = importlib.util.spec_from_file_location('controls', E / 'scripts/recovery_commitment_negative_controls.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m.ROOT == E, m.ROOT
m.OUT = Path(sys.argv[1])
real = subprocess.run
def offline(cmd, **kw):
    if cmd[:2] == ['cargo', 'test']:
        cmd = cmd[:2] + ['--offline', '--locked'] + cmd[2:]
    return real(cmd, **kw)
m.subprocess.run = offline
print(len(m.CASES), 'author cases')
m.main()
