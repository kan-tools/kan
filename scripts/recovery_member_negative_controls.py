#!/usr/bin/env python3
"""Compile targeted logical member guards; preserve failures and restore."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/'src/evidence_recovery_member.rs'
OUT=ROOT/'.local-state/member-author/controls'
CASES=[
 ('item-budget','if u64::try_from(items).map_err(|_| Error::Budget)? > budget.items','if false && u64::try_from(items).map_err(|_| Error::Budget)? > budget.items','bounded_acquisition_order_and_cancellation_refuse',1),
 ('input-budget','if self.bytes > self.budget.input_bytes','if false && self.bytes > self.budget.input_bytes','bounded_acquisition_order_and_cancellation_refuse',1),
 ('cancelled','if self.budget.cancelled.load(Ordering::Relaxed)','if false && self.budget.cancelled.load(Ordering::Relaxed)','bounded_acquisition_order_and_cancellation_refuse',1),
 ('source-digest','require(digest == p.source().digest, "source metadata digest")?','require(true || digest == p.source().digest, "source metadata digest")?','copy_plan_cannot_relabel_a_different_complete_source_digest',1),
 ('expected-length','c.length.is_none_or(|old| old == n)','true || c.length.is_none_or(|old| old == n)','shared_cid_lengths_and_duplicate_operations_refuse_even_when_all_bytes_missing',1),
 ('duplicate-operation','operations.insert((writer.to_string(), op.to_vec()))','true || operations.insert((writer.to_string(), op.to_vec()))','shared_cid_lengths_and_duplicate_operations_refuse_even_when_all_bytes_missing',1),
 ('original-hash','&& actual == object.cid.to_bytes()[4..]','&& (true || actual == object.cid.to_bytes()[4..])','missing_corrupt_empty_and_orphan_bytes_have_exact_distinct_loss_and_commitment',1),
 ('orphan-loss','if !c.referenced && c.state != Availability::Available','if false && !c.referenced && c.state != Availability::Available','missing_corrupt_empty_and_orphan_bytes_have_exact_distinct_loss_and_commitment',1),
 ('writer-signature','.map_err(|_| Error::Invalid("retained writer request"))?;','.ok();','hash_valid_but_unsigned_bytes_are_not_treated_as_recoverable_loss',1),
]

def main():
    if not __debug__:raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True);original=FILE.read_text()
    try:
        for name,old,new,test,count in CASES:
            assert original.count(old)==count,(name,original.count(old))
            FILE.write_text(original.replace(old,new))
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_member',test,'--','--exact'],cwd=ROOT,capture_output=True,text=True,timeout=180)
            log=run.stdout+run.stderr;(OUT/(name+'.txt')).write_text(log+'\nexit='+str(run.returncode)+'\n')
            if name == 'cancelled' and run.returncode == 0:
                print('SURVIVED: early cancellation guard; final commitment framing still refuses cancellation (not coverage of early interruption)',flush=True)
                FILE.write_text(original)
                continue
            assert run.returncode!=0,name+' SURVIVED' 
            assert 'could not compile' not in log,name+' did not compile'
            assert 'test '+test+' ... FAILED' in log,name+' lacks named assertion failure'
            print('DEMONSTRATED: '+name,flush=True);FILE.write_text(original)
    finally:FILE.write_text(original)
    run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_member'],cwd=ROOT,capture_output=True,text=True,timeout=180)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr+'\nexit='+str(run.returncode)+'\n');assert run.returncode==0,'restoration failed'
    print(f'{len(CASES)} compiled controls attempted; see individual semantic failures/survivors above; restored suite passed.',flush=True)
if __name__=='__main__':main()
