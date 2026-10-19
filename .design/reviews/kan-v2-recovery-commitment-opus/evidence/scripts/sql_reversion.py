#!/usr/bin/env python3
"""Reverse the a78fa61 SQL correction inside the export (not scripts/revert_v2.py),
keep the retained test file, run the whole schema suite. Then reverse each U0 hunk
alone. Restores bytes and checks the manifest hash after every step.
Usage: sql_reversion.py <out-dir>
"""
import hashlib, json, re, subprocess, sys
from pathlib import Path
R = '/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state'
E = Path(R + '/.local-state/reviews/recovery-commitment')
REL = '.design/fixtures/recovery-bundle-v1-schema.sql'
SQL = E / REL
manifest = json.loads((E.parent / 'recovery-commitment-identity.json').read_text())['files']
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
original = SQL.read_bytes()
assert hashlib.sha256(original).hexdigest() == manifest[REL]
before = subprocess.run(['git', '-C', R, 'show', 'a78fa61^:' + REL], capture_output=True, check=True).stdout
after = subprocess.run(['git', '-C', R, 'show', 'a78fa61:' + REL], capture_output=True, check=True).stdout
assert after == original, 'export SQL differs from a78fa61 blob'
(out / 'sql-before-a78fa61.sql').write_bytes(before)

def suite(name):
    r = subprocess.run(['python3', '-I', str(E / '.design/tools/recovery_bundle_schema.py'), '-v'],
                       cwd=E, capture_output=True, text=True, timeout=120)
    (out / (name + '.txt')).write_text(r.stdout + r.stderr + f'\nexit={r.returncode}\n')
    res = re.findall(r'^(test_\S+) .*\.\.\. (ok|FAIL|ERROR)$', r.stderr, re.M)
    return r.returncode, res

def restore():
    SQL.write_bytes(original)
    assert hashlib.sha256(SQL.read_bytes()).hexdigest() == manifest[REL]

lines = []
code, res = suite('00-baseline'); lines.append(f'baseline exit={code} {res}')
try:
    SQL.write_bytes(before)
    code, res = suite('01-whole-correction-reverted'); lines.append(f'whole-reverted exit={code} {res}')
finally:
    restore()
# Per-line (U0 hunk) reversion: each changed line individually reverted.
b_lines = before.decode().splitlines(True); a_lines = after.decode().splitlines(True)
assert len(b_lines) == len(a_lines)
changed = [i for i, (x, y) in enumerate(zip(b_lines, a_lines)) if x != y]
lines.append(f'changed lines (U0 hunks): {len(changed)} at {[i+1 for i in changed]}')
for i in changed:
    label = a_lines[i].split()[0]
    mutated = a_lines[:]; mutated[i] = b_lines[i]
    try:
        SQL.write_text(''.join(mutated))
        code, res = suite(f'02-hunk-line{i+1}-{label}-reverted')
        failed = [n for n, s in res if s != 'ok']
        lines.append(f'hunk line {i+1} ({label}) reverted alone: exit={code} failed={failed}')
    finally:
        restore()
code, res = suite('03-restored'); lines.append(f'restored exit={code} {res}')
(out / 'SUMMARY.txt').write_text('\n'.join(lines) + '\n')
print('\n'.join(lines))
