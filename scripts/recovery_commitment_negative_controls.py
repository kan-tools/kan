#!/usr/bin/env python3
"""Compile targeted streaming commitment guards; preserve failures and restore."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/'src/evidence_recovery_commitment.rs'
OUT=ROOT/'.local-state/commitment-author/controls'
CASES=[
 ('binary-cid-order','Ok((cid.to_string(), raw))','Ok((format!("{:02x?}", raw), raw))','independent_python_member_output_and_restoration_framing_matches',1),
 ('poisoned-builder','if self.core.failed {','if false && self.core.failed {','skipped_extra_and_reordered_sections_never_finish',4),
 ('record-order',' && sequence == s.seen + 1','', 'skipped_extra_and_reordered_sections_never_finish',1),
 ('output-domain','tools.kan.recovery.output.v1','tools.kan.recovery.member.v1','independent_python_member_output_and_restoration_framing_matches',1),
 ('original-key','s.core.frame(&key)?;\n            s.core.n(bytes.len() as u64)?;','s.core.n(bytes.len() as u64)?;','independent_python_member_output_and_restoration_framing_matches',1),
 ('candidate-hash','shape(actual == key[4..], "candidate hash")?;','shape(true, "candidate hash")?;','sorted_unique_cids_are_required_and_candidate_hashes_are_checked',1),
 ('duplicate-cid','old < &next','old <= &next','sorted_unique_cids_are_required_and_candidate_hashes_are_checked',1),
 ('byte-budget','if self.bytes > self.limits.bytes','if false && self.bytes > self.limits.bytes','failure_mid_payload_and_candidate_verification_consumes_budget_and_poisons',1),
 ('cancellation','if self.limits.cancelled.load(Ordering::Relaxed)','if false && self.limits.cancelled.load(Ordering::Relaxed)','local_limits_cancellation_and_failed_work_are_explicit',1),
]
def main():
    if not __debug__:raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True);original=FILE.read_text()
    try:
        for name,old,new,test,count in CASES:
            assert original.count(old)==count,(name,original.count(old))
            FILE.write_text(original.replace(old,new))
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_commitment',test,'--','--exact'],cwd=ROOT,capture_output=True,text=True,timeout=180)
            log=run.stdout+run.stderr;(OUT/(name+'.txt')).write_text(log+'\nexit='+str(run.returncode)+'\n')
            assert run.returncode!=0,name+' SURVIVED'
            assert 'could not compile' not in log,name+' did not compile'
            assert 'test '+test+' ... FAILED' in log,name+' lacks named assertion failure'
            print('DEMONSTRATED: '+name,flush=True);FILE.write_text(original)
    finally:FILE.write_text(original)
    run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_commitment'],cwd=ROOT,capture_output=True,text=True,timeout=180)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr+'\nexit='+str(run.returncode)+'\n');assert run.returncode==0,'restoration failed'
    print(f'{len(CASES)} compiled controls; restored suite passed.',flush=True)
if __name__=='__main__':main()
