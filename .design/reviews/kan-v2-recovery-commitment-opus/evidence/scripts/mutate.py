#!/usr/bin/env python3
"""Reviewer compiled-mutation runner (one cargo job at a time).

Usage: mutate.py <cases.json> <out-dir>
cases.json: [{"name","file","old","new","count","cargo_tests":[...],"env":{...}}]
Each case: assert exact occurrence count, write mutated source, run cargo test with
--no-fail-fast over the listed test targets, record per-test ok/FAILED, restore the
original bytes and verify sha256 against the frozen manifest. Never leaves a mutation
in place (try/finally). Classification is computed later by the reviewer, not here.
"""
import hashlib, json, os, re, subprocess, sys, time
from pathlib import Path

E = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment')
MANIFEST = json.loads((E.parent / 'recovery-commitment-identity.json').read_text())['files']

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    cases = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
    summary = []
    for case in cases:
        path = E / case['file']
        original = path.read_bytes()
        assert sha(path) == MANIFEST[case['file']], 'pre-mutation hash mismatch ' + case['file']
        text = original.decode()
        n = text.count(case['old'])
        assert n == case['count'], (case['name'], n)
        cmd = ['cargo', 'test', '--offline', '--locked', '--no-fail-fast', '--features', 'v2-crypto']
        for t in case['cargo_tests']:
            cmd += ['--test', t]
        cmd += ['--', '--test-threads=1']
        env = dict(os.environ); env.update(case.get('env', {}))
        try:
            path.write_text(text.replace(case['old'], case['new']))
            t0 = time.time()
            run = subprocess.run(cmd, cwd=E, env=env, capture_output=True, text=True, timeout=900)
            log = run.stdout + run.stderr
        finally:
            path.write_bytes(original)
        restored = sha(path) == MANIFEST[case['file']]
        compiled = 'could not compile' not in log and 'error[E' not in log
        results = re.findall(r'^test (\S+) \.\.\. (ok|FAILED)$', log, re.M)
        failed = [n for n, r in results if r == 'FAILED']
        (out / (case['name'] + '.txt')).write_text(
            'CASE ' + json.dumps({k: case[k] for k in ('name', 'file', 'old', 'new')}) + '\n'
            + 'CMD ' + ' '.join(cmd) + '\n' + log + f'\nexit={run.returncode} elapsed={time.time()-t0:.1f}s restored_hash_ok={restored}\n')
        line = f"{case['name']}\tcompiled={compiled}\texit={run.returncode}\ttests={len(results)}\tfailed={','.join(failed) or '-'}\trestored={restored}"
        print(line, flush=True)
        summary.append(line)
        assert restored, 'RESTORE FAILED ' + case['name']
    (out / 'SUMMARY.txt').write_text('\n'.join(summary) + '\n')

if __name__ == '__main__':
    main()
