#!/usr/bin/env python3
"""Reviewer mutants for Scope B corrections; per-suite attribution; exact restore."""
import hashlib, subprocess, sys
from pathlib import Path
E=Path(sys.argv[1]); OUT=Path(sys.argv[2]); OUT.mkdir(parents=True,exist_ok=True)
BIN=E/'src/bin/kan-v2.rs'; o=BIN.read_bytes(); s=o.decode()
ctx='format!("cannot read recovery source {}: {e}", database.display())'
assert s.count(ctx)==2
i=s.index(ctx); j=s.index(ctx,i+1)
M=[('context-profile2-only-dropped', s[:i]+'format!("{e}")'+s[i+len(ctx):]),
   ('context-legacy-only-dropped', s[:j]+'format!("{e}")'+s[j+len(ctx):]),
   ('backup-claims-independent', s.replace('"independent_backup":false,"issuer_proofs"','"independent_backup":true,"issuer_proofs"',1)),
   ('legacy-verify-claims-proofs', s.replace('} else {"structural-closure"}','} else {"payloads-writer-requests-and-issuer-proofs"}',1)),
   ('verify-claims-writable-checked', s.replace('"writable_admission":"not-checked","cryptographic_admission"','"writable_admission":"checked","cryptographic_admission"',1))]
try:
    for name,m in M:
        assert m!=s,name
        BIN.write_text(m); row=[name]
        for suite in ('evidence_attested_lifecycle','recovery_cli'):
            r=subprocess.run(['cargo','test','--features','v2-crypto','--test',suite],cwd=E,capture_output=True,text=True)
            log=r.stdout+r.stderr; (OUT/f'{name}.{suite}.txt').write_text(log)
            if 'could not compile' in log: v='COMPILE-ERROR'
            else:
                f=[l.split()[1] for l in log.splitlines() if l.startswith('test ') and l.rstrip().endswith('FAILED')]
                v=('KILLED '+','.join(f)) if r.returncode else 'survived'
            row.append(f'{suite}={v}')
        print(' | '.join(row),flush=True)
        BIN.write_bytes(o)
finally:
    BIN.write_bytes(o)
assert hashlib.sha256(BIN.read_bytes()).digest()==hashlib.sha256(o).digest(); print('restored kan-v2.rs')
