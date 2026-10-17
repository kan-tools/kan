#!/usr/bin/env python3
"""Run only in an idle author worktree; compile and kill three service regressions."""
import os
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parents[1]
source=root/'src/evidence_service.rs'
original=source.read_bytes()
env=dict(os.environ,CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0')
mutations=[
 ('signature verification', 'if !sign::verify(\n            &value.request.principal,', 'if false && !sign::verify(\n            &value.request.principal,', 'signatures_canonical_bounds_expiry_and_reply_binding'),
 ('capability separation', 'if (append && !grant.append) || (!append && !grant.inventory)', 'if false && ((append && !grant.append) || (!append && !grant.inventory))', 'independent_capabilities_deny_other_scopes_and_unadmitted_writers'),
 ('retained issuer binding', 'if record.receipt.body()["issuer"]', 'if false && record.receipt.body()["issuer"]', 'retained_signature_and_receipt_issuer_are_verified_independently_of_structure'),
 ('audience binding', 'request.scope != self.scope || request.audience != self.issuer()', 'request.scope != self.scope', 'signatures_canonical_bounds_expiry_and_reply_binding'),
]
for name,old,new,test in mutations:
    text=original.decode()
    if text.count(old)!=1: raise SystemExit(f'{name}: mutation is not unique')
    try:
        source.write_text(text.replace(old,new,1))
        output=subprocess.run(['cargo','test','--features','v2-service','--test','evidence_service',test],cwd=root,env=env,capture_output=True,text=True)
        if output.returncode==0 or 'test result: FAILED' not in output.stdout:
            raise SystemExit(f'{name}: expected runtime failure was not observed\n{output.stdout}\n{output.stderr}')
        print(name+': detected runtime failure',flush=True)
    finally:
        source.write_bytes(original)
subprocess.run(['cargo','test','--features','v2-service','--test','evidence_service'],cwd=root,env=env,check=True)
