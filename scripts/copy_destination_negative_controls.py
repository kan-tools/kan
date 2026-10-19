#!/usr/bin/env python3
"""Synthetic compiled controls; run alone against the shared Cargo cache."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.local-state/reviews/copy-destination-controls'
def main():
    if not __debug__: raise RuntimeError('assertions required')
    cases=[
        ('complete-without-source-digest','src/evidence_store/copied.rs','digest == plan.source().digest','{ let _ = digest; true }','evidence_copy_destination','empty_record_history_is_incomplete_until_all_staged_objects_are_copied'),
        ('skip-preflight-completeness','src/evidence_store/attested.rs','if target.is_some() && !status.source_copy_complete {','if false && target.is_some() && !status.source_copy_complete {','evidence_copy_destination','bounded_copy_preserves_original_bytes_and_acknowledged_proofs_before_new_admission'),
        ('skip-writer-membership-check','src/evidence_store/attested.rs','copied::admission_ready(tx, binding, plan, previous.through)?;','copied::check_plan(tx, binding, plan)?;','evidence_copy_destination','admission_rechecks_original_membership_after_staging_under_writer_transaction'),
        ('ignore-external-archive','src/evidence_store/copied.rs','plan.check_archive(&binding.archive)?;','','evidence_copy_destination','owner_recipe_signer_and_profile_are_required_before_mutation'),
        ('ignore-historical-issuer','src/evidence_store/attested.rs','if signed.request.audience != plan.source().historical_issuer {','if false && signed.request.audience != plan.source().historical_issuer {','evidence_copy_destination','profile3_rejects_mixed_historical_issuers_with_a_specific_reason'),
        ('ignore-retained-position','src/evidence_store/attested.rs','if record.sequence > plan.source().through {','if false && record.sequence > plan.source().through {','evidence_copy_destination','profile3_rejects_retained_after_admission_and_admission_inside_original_prefix'),
        ('oracle-omits-independent-sort','.design/tools/copy_source_digest.py',"sorted(conn.execute('SELECT cid,bytes FROM objects ORDER BY length(bytes) DESC,cid DESC').fetchall(),key=lambda row:row[0])","conn.execute('SELECT cid,bytes FROM objects ORDER BY length(bytes) DESC,cid DESC').fetchall()",'evidence_copy_source','source_fingerprint_matches_an_independent_python_byte_oracle'),
        ('wrong-inventory-capability','src/evidence_store/copied.rs','crate::persistence::SurfaceWrite::EvidenceCopy,','crate::persistence::SurfaceWrite::EvidenceAttestation,','surface_conformance','every_persistence_facade_call_is_independently_inventoried'),
        ('unregistered-plan-file-write','src/evidence_store/copy_upgrade.rs','crate::persistence::SurfaceWrite::EvidenceCopyPlan,','crate::persistence::SurfaceWrite::EvidenceArchive,','surface_conformance','every_persistence_facade_call_is_independently_inventoried'),
    ]
    OUT.mkdir(parents=True,exist_ok=True)
    originals={ROOT/c[1]:(ROOT/c[1]).read_text() for c in cases}
    try:
        for name,filename,old,new,suite,test in cases:
            p=ROOT/filename;before=originals[p];assert old in before,name+' inactive'
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
