#!/usr/bin/env python3
"""Validate example supervisor argv with the built CLI; never install or serve."""
import json
import pathlib
import plistlib
import shlex
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
binary = pathlib.Path(sys.argv[1]).resolve()
unit = root / 'examples/supervision/kan-v2-drain.service'
commands = [shlex.split(line.removeprefix('ExecStart='))
            for line in unit.read_text().splitlines() if line.startswith('ExecStart=')]
with (root / 'examples/supervision/ventures.kan.drain.plist').open('rb') as f:
    commands.append(plistlib.load(f)['ProgramArguments'])
if len(commands) != 2:
    raise SystemExit('expected both supervisor command examples')
for argv in commands:
    if argv[0] != '/usr/local/bin/kan' or argv[1] != 'spool-watch':
        raise SystemExit('unexpected supervisor action')
    result = subprocess.run([str(binary), *argv[1:], '--help'], capture_output=True,
                            text=True, timeout=5, check=True)
    if 'Usage:' not in result.stdout or '--journal' not in result.stdout:
        raise SystemExit('CLI did not validate the expected command surface')
print(json.dumps({'validated_supervisor_commands': len(commands), 'installed': False}))
