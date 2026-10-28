#!/usr/bin/env python3
"""Reviewer mutation/reversion runner. One case per invocation; restores bytes.

usage: mutate.py CASES.json NAME
Case: {"edits": [[file, old, new], ...] | "patch": path-to-diff (reverse-applied with patch -p1 -R),
       "runs": [[label, [cargo args...]], ...]}
Writes review-evidence/raw/mutations/NAME/*.txt and prints a one-line summary.
"""
import hashlib, json, subprocess, sys, time
from pathlib import Path

EXP = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-reconstruction/.local-state/reviews/reconstruction')
OUT_ROOT = EXP / 'review-evidence/raw/mutations'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    cases = json.loads(Path(sys.argv[1]).read_text())
    name = sys.argv[2]
    case = cases[name]
    out = OUT_ROOT / name
    out.mkdir(parents=True, exist_ok=True)
    files = sorted({e[0] for e in case.get('edits', [])} | set(case.get('files', [])))
    saved = {f: (EXP / f).read_bytes() for f in files}
    hashes = {f: sha(EXP / f) for f in files}
    summary = []
    added = [EXP / dst for _, dst in case.get('add', [])]
    try:
        for src, dst in case.get('add', []):
            assert not (EXP / dst).exists(), dst
            (EXP / dst).write_bytes(Path(src).read_bytes())
        if 'patch' in case:
            r = subprocess.run(['patch', '-p1', '-R', '--no-backup-if-mismatch', '-d', str(EXP), '-i', case['patch']],
                               capture_output=True, text=True)
            (out / 'apply.txt').write_text(r.stdout + r.stderr + f'\nexit={r.returncode}\n')
            assert r.returncode == 0, 'patch failed'
        for f, old, new in case.get('edits', []):
            text = (EXP / f).read_text()
            assert text.count(old) == 1, (name, f, text.count(old))
            (EXP / f).write_text(text.replace(old, new, 1))
        changed = [f for f in files if (EXP / f).read_bytes() != saved[f]]
        assert changed, 'mutation changed nothing'
        diff = subprocess.run(['diff', '-u', '/dev/null', '/dev/null'], capture_output=True, text=True)
        for f in changed:
            tmp = out / ('orig-' + f.replace('/', '__'))
            tmp.write_bytes(saved[f])
            d = subprocess.run(['diff', '-u', str(tmp), str(EXP / f)], capture_output=True, text=True)
            (out / ('mutation-' + f.replace('/', '__') + '.diff')).write_text(d.stdout)
            tmp.unlink()
        for label, args in case['runs']:
            t = time.time()
            r = subprocess.run(['cargo'] + args, cwd=EXP, capture_output=True, text=True, timeout=900)
            log = r.stdout + r.stderr
            (out / (label + '.txt')).write_text(' '.join(['cargo'] + args) + '\n' + log + f'\nexit={r.returncode}\n')
            compile_error = 'could not compile' in log
            failed = [l.split()[1] for l in log.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
            results = [l for l in log.splitlines() if l.startswith('test result:')]
            summary.append(f'{label}: exit={r.returncode} compile_error={compile_error} failed={failed} {results} {time.time()-t:.0f}s')
    finally:
        for a in added:
            a.unlink(missing_ok=True)
        summary.append('added_removed=' + str(not any(a.exists() for a in added)))
        for f in files:
            (EXP / f).write_bytes(saved[f])
        restored = all(sha(EXP / f) == hashes[f] for f in files)
        summary.append(f'restored_bytes={restored}')
        (out / 'SUMMARY.txt').write_text('\n'.join(summary) + '\n')
        print(name + ' | ' + ' | '.join(summary), flush=True)


if __name__ == '__main__':
    main()
