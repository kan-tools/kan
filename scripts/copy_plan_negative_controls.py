#!/usr/bin/env python3
"""Compiled plan/source regressions. Run only while the shared build cache is idle."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
PLAN=ROOT/'src/evidence_copy_plan.rs'
SOURCE=ROOT/'src/evidence_store/copy_upgrade.rs'
STORE=ROOT/'src/evidence_store.rs'
OUT=ROOT/'.local-state/reviews/copy-plan-controls'
def main():
    if not __debug__:raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True)
    originals={p:p.read_text() for p in (PLAN,SOURCE,STORE)}
    for p,s in originals.items():(OUT/(p.name+'.original')).write_text(s)
    cases=[
        ('allow-current-k256',PLAN,originals[PLAN].replace('if require_p256 && algorithm != atrium_crypto::Algorithm::P256 {','if false && require_p256 && algorithm != atrium_crypto::Algorithm::P256 {'),'evidence_copy_plan','malformed_or_unsupported_plans_refuse'),
        ('omit-staged-object-inventory',SOURCE,originals[SOURCE][:originals[SOURCE].index('        // Bind staged-but-uncommitted objects')]+originals[SOURCE][originals[SOURCE].index('        let plan = Plan::new('):],'evidence_copy_source','staged_but_uncommitted_objects_are_part_of_the_source_commitment'),
        ('ignore-owner-archive',PLAN,originals[PLAN].replace('if &self.archive != expected {','if false && &self.archive != expected {'),'evidence_copy_plan','changing_each_owner_pin_or_source_coordinate_changes_archive_identity'),
        ('ignore-receipts-in-source-digest',SOURCE,originals[SOURCE].replace('frame(&mut hash, record.receipt.bytes());','let _ = record.receipt.bytes();'),'evidence_copy_source','same_frontier_with_a_changed_unsigned_receipt_fails_exact_plan_confirmation'),
        ('confirm-frontier-only',SOURCE,originals[SOURCE].replace('if checked.plan.bytes() != plan.bytes() {','if checked.plan.source().through != plan.source().through || checked.plan.source().tip != plan.source().tip {'),'evidence_copy_source','same_frontier_with_a_changed_unsigned_receipt_fails_exact_plan_confirmation'),
        ('ignore-historical-issuer',SOURCE,originals[SOURCE].replace('|| signed.request.audience != historical_issuer','|| false'),'evidence_copy_source','plans_require_explicit_scope_historical_issuer_and_all_source_payloads'),
        ('ignore-target-scope',SOURCE,originals[SOURCE].replace('signed.request.scope != service::hex(&target.scope)','false'),'evidence_copy_source','plans_require_explicit_scope_historical_issuer_and_all_source_payloads'),
        ('unpin-source-transaction',STORE,originals[STORE].replace('PRAGMA query_only=ON; BEGIN;','PRAGMA query_only=ON;'),'evidence_copy_source','source_plan_is_pinned_and_reconfirmation_detects_later_admission'),
    ]
    try:
        for name,p,s,suite,test in cases:
            assert s!=originals[p],name+' inactive';p.write_text(s)
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test',suite,test,'--','--exact'],cwd=ROOT,capture_output=True,text=True)
            log=run.stdout+run.stderr;(OUT/(name+'.txt')).write_text(log)
            assert run.returncode!=0,name+' SURVIVED';assert 'could not compile' not in log,name+' compile failure';assert 'test '+test+' ... FAILED' in log,name+' no named assertion'
            print('DEMONSTRATED:',name,flush=True);p.write_text(originals[p])
    finally:
        for p,s in originals.items():p.write_text(s)
    run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_copy_plan','--test','evidence_copy_source'],cwd=ROOT,capture_output=True,text=True)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr);assert run.returncode==0,'restored baseline failed'
    print('Eight compiled mutants fail; restored plan/source tests pass.',flush=True)
if __name__=='__main__':main()
