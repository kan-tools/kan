#!/usr/bin/env python3
"""Reviewer mutation harness: one exact substitution, named tests, byte restore.

Usage: mutate.py LABEL FILE OLD NEW KIND NAME [NAME...]
KIND is 'lib', a Rust integration target (e.g. evidence_reader), or 'node'
(NAME is then the exact Node test title). OLD must occur exactly once.
Result line: KILLED (compiled, named assertion failed) / SURVIVED / COMPILE-ERROR.
"""
import pathlib, re, subprocess, sys, os

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'review-evidence' / 'mutants'


def main():
    label, file, old, new, kind, *names = sys.argv[1:]
    path = ROOT / file
    original = path.read_bytes()
    text = original.decode()
    if text.count(old) != 1:
        print(f'{label}: BAD-MUTANT occurrences={text.count(old)}')
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    log = OUT / f'{label}.txt'
    verdicts = []
    try:
        path.write_text(text.replace(old, new))
        with log.open('w') as f:
            f.write(f'file={file}\n--- old\n{old}\n+++ new\n{new}\n\n')
        for name in names:
            if kind == 'node':
                cmd = ['node', '--test', '--test-reporter=tap',
                       '--test-name-pattern=^' + re.escape(name) + '$', 'tests/library_ui.test.cjs']
            else:
                cmd = ['cargo', 'test', '-j4', '--features', 'v2-crypto']
                cmd += ['--lib'] if kind == 'lib' else ['--test', kind]
                cmd += [name, '--', '--exact']
            run = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
            out = run.stdout + run.stderr
            with log.open('a') as f:
                f.write(f'$ {" ".join(cmd)}\nexit={run.returncode}\n{out}\n')
            if 'could not compile' in out or '\nerror[' in out:
                verdicts.append((name, 'COMPILE-ERROR'))
                continue
            if kind == 'node':
                passed = re.search(r'^ok \d+ - ' + re.escape(name) + '$', out, re.M)
                failed = re.search(r'^not ok \d+ - ' + re.escape(name) + '$', out, re.M)
            else:
                passed = re.search(r'^test ' + re.escape(name) + r' \.\.\. ok$', out, re.M)
                failed = re.search(r'^test ' + re.escape(name) + r' \.\.\. FAILED$', out, re.M)
            verdicts.append((name, 'KILLED' if failed else 'SURVIVED' if passed else 'NOT-RUN'))
    finally:
        path.write_bytes(original)
    assert path.read_bytes() == original
    overall = 'KILLED' if any(v == 'KILLED' for _, v in verdicts) else (
        'COMPILE-ERROR' if all(v == 'COMPILE-ERROR' for _, v in verdicts) else 'SURVIVED')
    detail = ', '.join(f'{n}={v}' for n, v in verdicts)
    line = f'{label}: {overall} [{detail}]'
    with (OUT / 'SUMMARY.txt').open('a') as f:
        f.write(line + '\n')
    print(line)
    return 0


if __name__ == '__main__':
    sys.exit(main())
