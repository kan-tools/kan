#!/usr/bin/env python3
"""Scope B: reproduce the three focused member follow-through controls and the
whole-runtime reversion of src/evidence_recovery_member.rs to cd0a9ff, using an
explicit-repo `git show` for both reversion and restoration. Logs go to
review-evidence/mutations/scopeB-*. Frozen bytes are SHA256-checked after each step.
"""
import hashlib, json, subprocess
from pathlib import Path

REPO = '/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-replay'
EXPORT = Path(REPO + '/.local-state/reviews/recovery-replay')
REL = 'src/evidence_recovery_member.rs'
FILE = EXPORT / REL
OUT = EXPORT / 'review-evidence/mutations'
WANT = json.loads((EXPORT.parent / 'recovery-replay-identity.json').read_text())['files'][REL]
T = 'evidence_recovery_member_review_regressions'
# Exactly the author's control text (scripts/recovery_member_followup_controls.py).
CONTROLS = [
 ('empty-request-cid', 'cid != &crate::evidence_store::ciphertext_cid(b""),', 'true || cid != &crate::evidence_store::ciphertext_cid(b""),', 'empty_service_request_cid_refuses_without_an_original'),
 ('retain-issuer-length', 'if !c.referenced {', 'if true {', 'cp11_basis_deterministic'),
 ('request-bound-edge', 'n <= service::MAX_REQUEST as u64', 'n < service::MAX_REQUEST as u64', 'cp01_request_length_edges_without_bytes'),
]


def sha():
    return hashlib.sha256(FILE.read_bytes()).hexdigest()


def git_show(rev):
    return subprocess.run(['git', '-C', REPO, 'show', f'{rev}:{REL}'], capture_output=True, check=True).stdout


def cargo(args):
    r = subprocess.run(['cargo', 'test', '--features', 'v2-crypto'] + args, cwd=EXPORT, capture_output=True, text=True, timeout=1200)
    return r.returncode, r.stdout + r.stderr


def note(name, text):
    (OUT / name).write_text(text)
    print(text.splitlines()[0] if text else name, flush=True)


def kind(code, log, test):
    if 'could not compile' in log or 'error[E' in log:
        return 'COMPILE-FAILURE'
    if code == 0:
        return 'SURVIVED'
    if f'test {test} ... FAILED' in log:
        if 'left: None' in log or 'called `Result::unwrap()` on an `Err`' in log or 'left: [' in log or 'left: Some' in log:
            return 'KILLED-SEMANTIC'
        return 'KILLED(inspect)'
    return 'FAILED-OTHER(inspect)'


def main():
    original = FILE.read_bytes()
    assert hashlib.sha256(original).hexdigest() == WANT
    assert git_show('b52aa48') == original, 'export member differs from pinned blob'
    text = original.decode()
    try:
        for name, old, new, test in CONTROLS:
            assert text.count(old) == 1, (name, text.count(old))
            FILE.write_text(text.replace(old, new))
            code, log = cargo(['--test', T, test, '--', '--exact', '--nocapture'])
            FILE.write_bytes(original); assert sha() == WANT
            note(f'scopeB-control-{name}.txt', f'scopeB control {name}: {kind(code, log, test)} exit={code} test={test}\n--- {old}\n+++ {new}\n\n{log}')
        # Whole production-file reversion to cd0a9ff via explicit repo git show.
        old_src = git_show('cd0a9ff')
        FILE.write_bytes(old_src)
        diff = subprocess.run(['git', '-C', REPO, 'diff', 'cd0a9ff', 'b52aa48', '--', REL], capture_output=True, text=True).stdout
        named = 'empty_service_request_cid_refuses_without_an_original'
        code, log = cargo(['--test', T, named, '--', '--exact', '--nocapture'])
        note('scopeB-whole-reversion-named.txt', f'scopeB whole reversion (cd0a9ff runtime) named regression: {kind(code, log, named)} exit={code}\nreverted sha256={hashlib.sha256(old_src).hexdigest()}\n{diff}\n\n{log}')
        code, log = cargo(['--no-fail-fast', '--test', 'evidence_recovery_member', '--test', T, '--test', 'evidence_recovery_member_corrections', '--test', 'evidence_recovery_replay'])
        failed = [l for l in log.splitlines() if l.startswith('test ') and 'FAILED' in l]
        note('scopeB-whole-reversion-suites.txt', f'scopeB whole reversion affected suites: exit={code} failed={failed}\n\n{log}')
    finally:
        FILE.write_bytes(git_show('b52aa48'))
        print('restored via git show b52aa48:', 'sha256 ok' if sha() == WANT else 'MISMATCH', flush=True)
    code, log = cargo(['--test', T, 'empty_service_request_cid_refuses_without_an_original', '--', '--exact'])
    note('scopeB-restored-named.txt', f'scopeB restored named regression exit={code}\n\n{log}')


if __name__ == '__main__':
    main()
