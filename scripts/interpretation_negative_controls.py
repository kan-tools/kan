#!/usr/bin/env python3
"""Selected semantic controls. Preserve every run and restore exact source."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/evidence_interpretation.rs'
BASE=ROOT/'.local-state/provider-author'
CASES=[
 ('coarse-citation','coarse: true,','coarse: false,','request_history_and_unknown_fields_remain_source_linked'),
 ('protocol-validity','state.stopped && !state.invalid','state.stopped','block_sequence_conflicts_and_sparse_indices_never_complete'),
 ('source-bytes','if raw != piece {','if false && raw != piece {','mapping_refuses_gaps_overlaps_forged_source_bytes_and_ranges'),
 ('duplicate-lineage','for source in &s.sources {','for source in &s.sources[..1] {','every_capture_split_preserves_sse_text_and_exact_duplicate_source_spans'),
 ('output-budget','if self.output > self.limits.output_bytes {','if false && self.output > self.limits.output_bytes {','exact_budgets_and_cancellation_return_no_partial_document'),
 ('cancel','if self.limits.cancelled.load(Ordering::Relaxed) {','if false && self.limits.cancelled.load(Ordering::Relaxed) {','exact_budgets_and_cancellation_return_no_partial_document'),
 ('input-budget','if bytes.len() > w.limits.input_bytes {','if false && bytes.len() > w.limits.input_bytes {','exact_budgets_and_cancellation_return_no_partial_document'),
]
def main():
 BASE.mkdir(exist_ok=True)
 out=BASE/('controls-'+str(len(list(BASE.glob('controls-*')))+1));out.mkdir()
 original=SOURCE.read_text()
 try:
  for name,old,new,test in CASES:
   # Both public entry points intentionally share the input-bound control.
   assert original.count(old)==(2 if name=='input-budget' else 1),(name,original.count(old))
   SOURCE.write_text(original.replace(old,new))
   r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_interpretation',test,'--','--exact','--nocapture'],cwd=ROOT,capture_output=True,text=True,timeout=240)
   log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
   assert r.returncode and 'could not compile' not in log and ('test '+test+' ... FAILED') in log,name+' survived or did not compile'
   assert 'assertion' in log or 'called `Result::unwrap_err()` on an `Ok` value' in log,name+' lacks behavioral failure'
   print('DEMONSTRATED '+name,flush=True);SOURCE.write_text(original)
 finally:SOURCE.write_text(original)
 r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_interpretation'],cwd=ROOT,capture_output=True,text=True,timeout=240)
 (out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
 print('Selected controls demonstrated; restored tests pass.',flush=True)
if __name__=='__main__':main()
