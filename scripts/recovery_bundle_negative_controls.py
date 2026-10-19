#!/usr/bin/env python3
"""Selected compiled physical-reader controls. Always restore source bytes.
No exhaustive mutation score; compile/diagnostic-only failures are not kills.
"""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/evidence_store/bundle.rs'
OUT=ROOT/'.local-state/bundle-author/controls'
PHYSICAL='schema_marker_history_identity_and_physical_cell_damage_refuse'
BUDGET='acquisition_budgets_have_exact_edges_and_replay_has_separate_limits'
CASES=[
 ('schema','schema(&conn, &mut work)?;','// omitted schema gate',PHYSICAL,False),
 ('identity','cell(row, 1, 32, 32, false, work)? == context.bundle','true || cell(row, 1, 32, 32, false, work)? == context.bundle',PHYSICAL,False),
 ('canonical-key','value.to_string() == text','true || value.to_string() == text',PHYSICAL,False),
 ('observation-coordinate','integer(row, 0, 1, MAX_SAFE)? == observations.len() as u64 + 1','true || integer(row, 0, 1, MAX_SAFE)? == observations.len() as u64 + 1',PHYSICAL,False),
 ('acquisition-bytes','self.bytes > self.budget.acquired_bytes','false && self.bytes > self.budget.acquired_bytes',BUDGET,False),
 ('acquisition-items','self.items > self.budget.items','false && self.items > self.budget.items',BUDGET,False),
 ('external-checkpoint','replay::verify(input, &candidates, &observations, checkpoint, limits)?','replay::verify(input, &candidates, &observations, None, limits)?','foreign_external_pins_and_checkpoint_refuse',False),
 ('pinned-snapshot','PRAGMA mmap_size=0; BEGIN;','PRAGMA mmap_size=0;','evidence_store::bundle::snapshot_tests::later_wal_changes_cannot_mix_into_the_pinned_snapshot',True),
]
def run(test,unit):
 args=['cargo','test','--features','v2-crypto']+(['--lib'] if unit else ['--test','evidence_recovery_bundle'])+[test,'--','--exact','--nocapture']
 return subprocess.run(args,cwd=ROOT,text=True,capture_output=True,timeout=240)
def main():
 if not __debug__:raise RuntimeError('assertions required')
 OUT.mkdir(parents=True,exist_ok=True);original=SOURCE.read_text()
 try:
  for name,old,new,test,unit in CASES:
   assert original.count(old)==1,(name,original.count(old))
   SOURCE.write_text(original.replace(old,new));r=run(test,unit);log=r.stdout+r.stderr
   (OUT/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
   assert r.returncode and 'could not compile' not in log,name+' survived or failed compilation'
   assert 'test '+test+' ... FAILED' in log,name+' lacks named assertion failure'
   if test==PHYSICAL:assert 'accepted mutation:' in log,name+' diagnostic-only failure'
   elif name=='pinned-snapshot':assert 'called `Result::unwrap()` on an `Err` value' in log,name+' missing snapshot failure'
   else:assert 'assertion failed:' in log,name+' missing semantic failure'
   print('DEMONSTRATED: '+name,flush=True);SOURCE.write_text(original)
 finally:SOURCE.write_text(original)
 for test,unit in [('',False),('evidence_store::bundle::snapshot_tests',True)]:
  args=['cargo','test','--features','v2-crypto']+(['--lib',test] if unit else ['--test','evidence_recovery_bundle'])
  r=subprocess.run(args,cwd=ROOT,text=True,capture_output=True,timeout=240)
  (OUT/('restored-units.txt' if unit else 'restored-integration.txt')).write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
 print(str(len(CASES))+' selected semantic controls demonstrated; restored tests pass.',flush=True)
if __name__=='__main__':main()
