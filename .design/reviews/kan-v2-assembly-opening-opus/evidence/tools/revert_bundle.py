#!/usr/bin/env python3
"""Reviewer whole-file reversion: src/evidence_store/bundle.rs := Git blob db1bb06:src/evidence_store/bundle.rs.
Only that one production file changes; tests and fixtures stay at eb4f471. Exact restore is verified."""
import hashlib, json, subprocess, sys
from pathlib import Path
EXPORT = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-session-assembly/.local-state/reviews/assembly-opening')
REPO = '/Users/m/code/kan-tools/kan/.worktrees/kan-v2-session-assembly'
OUT = EXPORT / 'review-evidence/mutations'; OUT.mkdir(exist_ok=True)
rel = 'src/evidence_store/bundle.rs'
target = EXPORT / rel
ident = json.load(open(EXPORT.parent / 'assembly-opening-identity.json'))
orig = target.read_bytes()
assert hashlib.sha256(orig).hexdigest() == ident['files'][rel]
blob = subprocess.run(['git', '-C', REPO, 'cat-file', 'blob', 'db1bb06:' + rel], capture_output=True, check=True).stdout
blob_id = hashlib.sha1(b'blob %d\0' % len(blob) + blob).hexdigest()
log = [f'pinned sha256={ident["files"][rel]} blob={ident["git_blobs"][rel]}',
       f'reverted-to db1bb06:{rel} blob={blob_id} sha256={hashlib.sha256(blob).hexdigest()}']
def run(name, args):
    r = subprocess.run(args, cwd=EXPORT, capture_output=True, text=True, timeout=600)
    text = '$ ' + ' '.join(args) + '\n' + r.stdout + r.stderr + f'\nexit={r.returncode}\n'
    (OUT / name).write_text(text)
    log.append(f'{name}: exit={r.returncode}')
    return r, text
try:
    target.write_bytes(blob)
    r, t = run('A-REV-1-empty-original-reverted.txt', ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_bundle',
              'empty_originals_remain_exact_evidence_before_and_after_restoration', '--', '--exact'])
    log.append('  compiled=' + str('could not compile' not in t) + ' FAILED=' + str('... FAILED' in t))
    r, t = run('A-REV-2-full-bundle-suite-reverted.txt', ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_bundle'])
    log += ['  ' + l for l in t.splitlines() if l.startswith('test ') or 'panicked' in l or l.startswith('E')]
finally:
    target.write_bytes(orig)
restored = hashlib.sha256(target.read_bytes()).hexdigest()
log.append(f'restored sha256={restored} equal_pinned={restored == ident["files"][rel]}')
r, t = run('A-REV-3-restored.txt', ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_bundle'])
log += ['  ' + l for l in t.splitlines() if l.startswith('test result')]
(OUT / 'A-REV-driver.txt').write_text('\n'.join(log) + '\n')
print('\n'.join(log))
