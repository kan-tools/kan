#!/usr/bin/env python3
"""Selected compiled assembly controls; each restores exact source bytes."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/evidence_assembly.rs'
OUT=ROOT/'.local-state/assembly-author/controls'
ISOLATION='scope_writer_observer_attempt_isolation_ignores_transport_link_claims'
CASES=[
 ('scope-key','inputs[i].scope,','[0;32],',ISOLATION),
 ('writer-key','inputs[i].writer,','"ignored-writer",',ISOLATION),
 ('observer-key','                    observer,','                    0,',ISOLATION),
 ('attempt-key','&f.header.attempt,','"ignored-attempt",',ISOLATION),
 ('duplicate-conflict','                    conflict = true;','                    conflict = false;','ordinal_conflicts_keep_both_bytes_and_prevent_synthetic_rendering'),
 ('gap-rendering','if out.issues.is_empty()','if true || out.issues.is_empty()','holes_overlaps_and_contradictory_extents_are_not_repaired'),
 ('assembled-budget','self.assembled > self.limits.assembled_bytes','false && self.assembled > self.limits.assembled_bytes','exact_budget_edges_cancellation_and_repeat_are_deterministic'),
 ('source-lineage','sources: sources\n','sources: sources[..1]\n','shuffled_selection_preserves_exact_binary_spans_and_duplicate_lineage'),
]
def main():
 if not __debug__:raise RuntimeError('assertions required')
 original=SOURCE.read_text();OUT.mkdir(parents=True,exist_ok=True)
 try:
  for name,old,new,test in CASES:
   assert original.count(old)==1,(name,original.count(old))
   SOURCE.write_text(original.replace(old,new))
   r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_assembly',test,'--','--exact','--nocapture'],cwd=ROOT,capture_output=True,text=True,timeout=240)
   log=r.stdout+r.stderr; (OUT/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
   assert r.returncode and 'could not compile' not in log,name+' survived or did not compile'
   assert 'test '+test+' ... FAILED' in log,name+' lacks named assertion failure'
   assert 'assertion' in log,name+' lacks semantic assertion'
   print('DEMONSTRATED: '+name,flush=True)
 finally:SOURCE.write_text(original)
 r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_assembly'],cwd=ROOT,capture_output=True,text=True,timeout=240)
 (OUT/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
 print('Eight selected controls demonstrated; restored assembly tests pass.',flush=True)
if __name__=='__main__':main()
