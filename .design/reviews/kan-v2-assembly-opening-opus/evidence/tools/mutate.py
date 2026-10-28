#!/usr/bin/env python3
"""Reviewer mutation driver. One mutant at a time; exact pinned SHA-256 restore after each.
Usage: mutate.py SPEC_JSON   where SPEC is a list of
  {"id","file","old","new","runs":[[test_target, filter_or_null, extra_env_or_null]], "expect"}
A mutant is KILLED only if it compiles and some named test FAILS. Compile failure is reported
as COMPILE-FAIL (not a kill). Raw output per mutant goes to review-evidence/mutations/<id>.txt.
"""
import hashlib, json, os, subprocess, sys
from pathlib import Path
EXPORT = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-session-assembly/.local-state/reviews/assembly-opening')
ident = json.load(open(EXPORT.parent / 'assembly-opening-identity.json'))
OUT = EXPORT / 'review-evidence/mutations'; OUT.mkdir(exist_ok=True)
spec = json.load(open(sys.argv[1]))
summary = []
for m in spec:
    path = EXPORT / m['file']
    orig = path.read_bytes()
    assert hashlib.sha256(orig).hexdigest() == ident['files'][m['file']], 'pre-state not pinned: ' + m['file']
    text = orig.decode()
    count = text.count(m['old'])
    log = [f"# {m['id']}: {m['file']}\n# expect: {m['expect']}\n# old occurrences={count}\n--- old\n{m['old']}\n+++ new\n{m['new']}\n"]
    verdict = None
    if count != 1:
        verdict = 'NOT-APPLIED(count=%d)' % count
    else:
        try:
            path.write_text(text.replace(m['old'], m['new']))
            failed, compiled = [], True
            for target, filt, env in m['runs']:
                args = ['cargo', 'test', '--features', 'v2-crypto', '--test', target]
                if filt: args += [filt]
                args += ['--', '--nocapture']
                e = dict(os.environ); e.update(env or {})
                r = subprocess.run(args, cwd=EXPORT, capture_output=True, text=True, timeout=900, env=e)
                out = r.stdout + r.stderr
                log.append('$ ' + ' '.join(args) + f"  env={env}\n" + out + f'\nexit={r.returncode}\n')
                if 'could not compile' in out or 'error[E' in out:
                    compiled = False
                failed += [l for l in out.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
            verdict = 'COMPILE-FAIL' if not compiled else ('KILLED by ' + '; '.join(failed) if failed else 'SURVIVED')
        finally:
            path.write_bytes(orig)
    ok = hashlib.sha256(path.read_bytes()).hexdigest() == ident['files'][m['file']]
    log.append(f'\nVERDICT {verdict}\nrestored_exact={ok}\n')
    (OUT / (m['id'] + '.txt')).write_text('\n'.join(log))
    summary.append(f"{m['id']}: {verdict} | restored_exact={ok} | expect: {m['expect']}")
    print(summary[-1], flush=True)
    assert ok
(OUT / ('driver-' + Path(sys.argv[1]).stem + '.txt')).write_text('\n'.join(summary) + '\n')
