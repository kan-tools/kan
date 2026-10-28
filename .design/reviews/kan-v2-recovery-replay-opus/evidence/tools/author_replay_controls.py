#!/usr/bin/env python3
"""Reproduce the author's 11 focused replay controls with their exact CASES table
(imported, not retyped) and their own semantic kill criteria, but write logs to
review-evidence/mutations/author-* instead of the export's .local-state/.
Frozen bytes are SHA256-checked after every control.
"""
import hashlib, importlib.util, json
from pathlib import Path

EXPORT = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-replay/.local-state/reviews/recovery-replay')
spec = importlib.util.spec_from_file_location('author_controls', EXPORT / 'scripts/recovery_replay_negative_controls.py')
ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
OUT = EXPORT / 'review-evidence/mutations'
MAN = json.loads((EXPORT.parent / 'recovery-replay-identity.json').read_text())['files']
FILES = {ac.FILE: MAN['src/evidence_recovery_replay.rs'], ac.MEMBER: MAN['src/evidence_recovery_member.rs']}


def frozen():
    return all(hashlib.sha256(p.read_bytes()).hexdigest() == h for p, h in FILES.items())


def judge(name, test, code, log):
    if 'could not compile' in log:
        return 'COMPILE-FAILURE'
    if code == 0:
        return 'SURVIVED'
    if f'test {test} ... FAILED' not in log:
        return 'FAILED-OTHER'
    if test == ac.VECTOR:
        return 'KILLED-ACCEPTANCE' if 'hostile history must refuse' in log else 'DIAGNOSTIC-ONLY'
    if test == 'rollback_before_external_checkpoint_and_foreign_checkpoint_refuse':
        return 'KILLED-ACCEPTANCE' if 'left: None' in log else 'DIAGNOSTIC-ONLY'
    return 'KILLED-SEMANTIC' if ('candidate expected length' in log or 'assertion failed:' in log) else 'KILLED(inspect)'


def main():
    assert frozen()
    original = ac.FILE.read_text(); original_member = ac.MEMBER.read_text()
    try:
        for name, old, new, test in ac.CASES:
            assert original.count(old) == 1, name
            ac.FILE.write_text(original.replace(old, new))
            r = ac.run(test); log = r.stdout + r.stderr
            ac.FILE.write_text(original); assert frozen()
            v = judge(name, test, r.returncode, log)
            (OUT / f'author-{name}.txt').write_text(f'author control {name}: {v} exit={r.returncode}\n--- {old}\n+++ {new}\n\n{log}')
            print(f'author-{name}: {v}', flush=True)
        old = '.map_err(|_| Error::Invalid("retained writer request"))?;'
        assert original_member.count(old) == 1
        ac.MEMBER.write_text(original_member.replace(old, '.ok();'))
        r = ac.run(ac.VECTOR); log = r.stdout + r.stderr
        ac.MEMBER.write_text(original_member); assert frozen()
        v = judge('virtual-output-writer', ac.VECTOR, r.returncode, log)
        (OUT / 'author-virtual-output-writer.txt').write_text(f'author control virtual-output-writer: {v} exit={r.returncode}\n--- {old}\n+++ .ok();\n\n{log}')
        print(f'author-virtual-output-writer: {v}', flush=True)
    finally:
        ac.FILE.write_text(original); ac.MEMBER.write_text(original_member)
        print('frozen bytes restored' if frozen() else 'RESTORE MISMATCH', flush=True)


if __name__ == '__main__':
    main()
