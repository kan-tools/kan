#!/usr/bin/env python3
"""Linux-only negative control: the real admission test must kill cap removal."""
import os
from pathlib import Path
import subprocess
import sys

if sys.platform != 'linux':
    raise SystemExit('This negative control requires Linux distinct loopback source addresses.')
source = Path('src/evidence_gateway.rs')
original = source.read_bytes()
needle = b'pending.len()>=32 || '
if original.count(needle) != 1:
    raise SystemExit('Expected exactly one global pending cap; update the reviewed mutation.')
command = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_gateway',
           'global_pending_cap_is_32_across_distinct_peers', '--', '--exact', '--nocapture']

def run():
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    output = result.stdout + result.stderr
    print(output, flush=True)
    if 'running 1 test' not in output:
        raise RuntimeError('No exact test ran; compilation failure is not a killed mutant.')
    return result, output

baseline, _ = run()
if baseline.returncode:
    raise SystemExit('Baseline failed; mutation not attempted.')
try:
    source.write_bytes(original.replace(needle, b''))
    mutated, output = run()
    if mutated.returncode == 0 or 'global pending cap did not refuse connection 33' not in output:
        raise RuntimeError('Global-cap mutant survived or failed for an unrelated reason.')
finally:
    source.write_bytes(original)
restored, _ = run()
if restored.returncode:
    raise SystemExit('Restored test failed.')
print('DEMONSTRATED: baseline passed; cap removal failed the named assertion; restored passed.')
