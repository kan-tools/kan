#!/usr/bin/env python3
"""Synthetic compiled controls; run alone against the shared Cargo cache."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.local-state/reviews/copy-destination-followup-controls'
def main():
    if not __debug__: raise RuntimeError('assertions required')
    cases=[
        ('remove-plan-custody-guards','src/evidence_store/copy_upgrade.rs',
         '    if same_existing_file(database, plan) {',
         '    return Ok(());\n    #[allow(unreachable_code)]\n    if same_existing_file(database, plan) {',
         'evidence_copy_destination','plan_custody_refuses_sqlite_families_before_opening_or_writing'),
        ('skip-cli-copy-path-checks','src/bin/kan-v2.rs',
         'kan::evidence_store::copy_upgrade::read_plan_for_copy(\n                &plan,\n                &database,\n                &archive,\n                &binding.archive,\n            )?',
         'kan::evidence_store::copy_upgrade::read_plan(&plan, &binding.archive)?',
         'evidence_copy_destination','owner_cli_plan_paths_cannot_be_sqlite_files_or_sidecars'),
        ('omit-profile3-full-audit-schema','src/evidence_store/copied.rs',
         '    ledger.check_profile(3)?;\n    ledger.check_copy_schema()?;', '    ledger.check_profile(3)?;',
         'evidence_copy_destination','profile3_schema_drift_refuses_open_verify_resume_and_stale_handle_backup'),
        ('skip-object-prefix-comparison','src/evidence_store/copied.rs',
         'if id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)? {',
         'if false && (id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)?) {',
         'evidence_copy_destination','resume_refuses_self_consistent_foreign_object_prefix_before_advancing'),
        ('skip-record-prefix-comparison','src/evidence_store/copied.rs',
         'if old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes()\n            {',
         'if false && (old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes())\n            {',
         'evidence_copy_destination','resume_refuses_valid_foreign_receipt_prefix_before_signing_more_proofs'),
        ('omit-cli-explicit-profile','src/bin/kan-v2.rs',
         'if !proof.copy_profile {', 'if false && !proof.copy_profile {',
         'evidence_copy_destination','owner_cli_copy_preconditions_refuse_without_creating_output'),
    ]
    OUT.mkdir(parents=True,exist_ok=True)
    originals={ROOT/c[1]:(ROOT/c[1]).read_text() for c in cases}
    try:
        for name,filename,old,new,suite,test in cases:
            p=ROOT/filename;before=originals[p];assert before.count(old)==1,(name,'pattern count',before.count(old))
            p.write_text(before.replace(old,new,1))
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test',suite,test,'--','--exact'],cwd=ROOT,capture_output=True,text=True,timeout=120)
            log=run.stdout+run.stderr;(OUT/(name+'.txt')).write_text(log)
            assert run.returncode!=0,name+' SURVIVED'
            assert 'could not compile' not in log,name+' compile error'
            assert 'test '+test+' ... FAILED' in log,name+' missing named failure'
            print('DEMONSTRATED:',name,flush=True);p.write_text(before)
    finally:
        for p,before in originals.items():p.write_text(before)
    run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_copy_destination','--test','evidence_copy_source','--test','surface_conformance'],cwd=ROOT,capture_output=True,text=True,timeout=180)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr);assert run.returncode==0,'restored baseline failed'
    print(f'{len(cases)} compiled controls; restored suites passed.',flush=True)
if __name__=='__main__':main()
