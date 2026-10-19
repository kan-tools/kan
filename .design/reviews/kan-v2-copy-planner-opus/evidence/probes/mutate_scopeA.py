#!/usr/bin/env python3
"""Reviewer mutants for Scope A. Each mutant runs the author's copy suites and the
reviewer probe suite separately so attribution is per suite. Restores exact bytes."""
import hashlib, os, subprocess, sys
from pathlib import Path
E = Path(sys.argv[1]); OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
SRC = E / 'src/evidence_store/copy_upgrade.rs'; PLAN = E / 'src/evidence_copy_plan.rs'
orig = {p: p.read_bytes() for p in (SRC, PLAN)}
def sub(p, a, b):
    s = orig[p].decode(); assert s.count(a) == 1, a; return s.replace(a, b)
M = [
  ('drop-exact-source-schema', SRC, 'reader.ledger.check_write_profile(false)?;', '/* mutant */'),
  ('confirm-skips-owner-pin', SRC, 'plan.check_archive(expected_archive)?;', 'let _ = expected_archive;'),
  ('drop-one-entry-check', SRC, 'if es.len() != 1 {', 'if false {'),
  ('drop-did-canonical-check', PLAN, '        != did\n', '        != did && false\n'),
  ('objects-desc-order', SRC, 'FROM objects ORDER BY cid")', 'FROM objects ORDER BY cid DESC")'),
  ('omit-object-length', SRC, '''                hash.update(
                    u64::try_from(length)''', '''                let _ = hash.clone(); (
                    u64::try_from(length)'''),
]
env = dict(os.environ, REVIEW_PLANS=str(E/'review-evidence/probes/noncanonical_plans.json'),
           REVIEW_ORACLE=str(E/'review-evidence/probes/reviewer_source_digest.py'))
def run(suite):
    r = subprocess.run(['cargo','test','--features','v2-crypto','--test',suite,'--','--test-threads=1'],
                       cwd=E, env=env, capture_output=True, text=True)
    log = r.stdout + r.stderr
    if 'could not compile' in log: return 'COMPILE-ERROR', log
    failed = [l.split()[1] for l in log.splitlines() if l.startswith('test ') and l.rstrip().endswith('FAILED')]
    return ('KILLED ' + ','.join(failed)) if r.returncode else 'survived', log
try:
    for name, p, a, b in M:
        p.write_text(sub(p, a, b))
        row = [name]
        for suite in ('evidence_copy_plan', 'evidence_copy_source', 'zz_review_copy_planner'):
            verdict, log = run(suite); (OUT / f'{name}.{suite}.txt').write_text(log); row.append(f'{suite}={verdict}')
        print(' | '.join(row), flush=True)
        p.write_bytes(orig[p])
finally:
    for p, b in orig.items(): p.write_bytes(b)
for p, b in orig.items():
    assert hashlib.sha256(p.read_bytes()).digest() == hashlib.sha256(b).digest()
print('restored', [str(p.relative_to(E)) for p in orig])
