#!/usr/bin/env python3
"""Compiled proof lifecycle negative controls; restores sources even on failure."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
STORE=ROOT/'src/evidence_store.rs'
PROOF=ROOT/'src/evidence_store/attested.rs'
BIN=ROOT/'src/bin/kan-v2.rs'
OUT=ROOT/'.local-state/reviews/lifecycle-controls'

def main():
    if not __debug__: raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True)
    originals={p:p.read_text() for p in (STORE,PROOF,BIN)}
    for p,s in originals.items(): (OUT/(p.name+'.original')).write_text(s)
    store=originals[STORE]; proof=originals[PROOF]; binary=originals[BIN]
    cases=[
        ('inflate-verify-admission-label',BIN,binary.replace('"cryptographic_admission":if attested {"proof-purpose-dependent"} else {"not-verified"}', '"cryptographic_admission":if attested {"admitted-verified"} else {"not-verified"}',1),'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle'),
        ('inflate-recover-history-label',BIN,binary.replace('"historical_completeness":"not-verified",\n                    "independent_backup"', '"historical_completeness":"complete",\n                    "independent_backup"'),'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle'),
        ('drop-source-error-context',BIN,binary.replace('format!("cannot read recovery source {}: {e}", database.display())','format!("{e}")'),'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle'),
        ('drop-exact-standalone-schema',PROOF,proof.replace('reader.reader.ledger.check_write_profile(true)?;', 'let _ = &reader.reader.ledger;'),'standalone_proof_verification_and_backup_refuse_undeclared_schema'),
        ('drop-precommit-proof-audit',STORE,store.replace('attested::verify_contents(&target, binding, &expected)?;', 'let _ = binding;'),'corrupt_source_proofs_are_rejected_before_output_profile_is_committed'),
        ('drop-proof-copy',STORE,store.replace('attested::copy_proof(&self.ledger.conn, &tx, raw.sequence)?;','let _ = &tx;'),'proof_bytes_survive_backup_rebuild_and_derived_repair'),
        ('drop-extra-proof-check',PROOF,proof.replace('if u64::try_from(count).ok() != Some(through) {','if false && u64::try_from(count).ok() != Some(through) {'),'recovery_refuses_missing_or_corrupt_proofs_and_payloads'),
        ('resume-as-legacy',PROOF,proof.replace('Ledger::initialize_empty(root, &path, &mut |_| {}, Some(&binding))?','Ledger::initialize_empty(root, &path, &mut |_| {}, None)?'),'interrupted_initialization_resumes_only_by_explicit_owner_action'),
        ('drop-backup-proof-audit',PROOF,proof.replace('verify_contents(&reader.reader.ledger, &reader.binding, &base)?;', 'let _ = &reader.binding;'),'backup_success_requires_verifying_the_copied_proof_chain'),
        ('drop-pinned-read',STORE,store.replace('PRAGMA query_only=ON; BEGIN;','PRAGMA query_only=ON;'),'recovery_pins_source_before_later_admission'),
    ]
    try:
        for name,p,s,test in cases:
            assert s!=originals[p],name+' inactive'
            p.write_text(s)
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_attested_lifecycle',test,'--','--exact'],cwd=ROOT,capture_output=True,text=True)
            text=run.stdout+run.stderr;(OUT/(name+'.txt')).write_text(text)
            assert run.returncode!=0,name+' SURVIVED'
            assert 'could not compile' not in text,name+' compile failure'
            assert 'test '+test+' ... FAILED' in text,name+' no named failure'
            print('DEMONSTRATED:',name,flush=True)
            p.write_text(originals[p])
    finally:
        for p,s in originals.items():p.write_text(s)
    args=['cargo','test','--features','v2-crypto','--test','evidence_attested_lifecycle','--test','evidence_store','--test','surface_conformance']
    run=subprocess.run(args,cwd=ROOT,capture_output=True,text=True)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr)
    assert run.returncode==0,'restored baseline failed'
    print(f'{len(cases)} compiled mutants fail; restored lifecycle/store/surface pass.',flush=True)
if __name__=='__main__':main()
