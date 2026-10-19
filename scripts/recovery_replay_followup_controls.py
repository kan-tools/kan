#!/usr/bin/env python3
"""A-F1/A-F2 controls; classify redundant writer/length defenses explicitly."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/evidence_recovery_replay.rs'
MEMBER=ROOT/'src/evidence_recovery_member.rs'
OUT=ROOT/'.local-state/replay-correction/controls'
CORPUS='reviewer_probe_corpus'
WRITER='.map_err(|_| Error::Invalid("candidate writer request"))?;'
CASES=[
 ('candidate-hash','work.hash(c.bytes)? == raw[4..]','true || work.hash(c.bytes)? == raw[4..]',CORPUS,'P22-original-only-candidate-hash-single-fault class=ACCEPTED_HOSTILE'),
 ('candidate-length','target.length.is_none_or(|n| n == c.bytes.len() as u64)','true || target.length.is_none_or(|n| n == c.bytes.len() as u64)',CORPUS,'P23-complete-recipe-staged-length-single-fault class=ACCEPTED_HOSTILE'),
 ('output-losses','output.losses().is_empty()','true || output.losses().is_empty()',CORPUS,'P04-corrupt-orphan-with-self-consistent-o1 class=ACCEPTED_HOSTILE'),
 ('checkpoint-context','p.context == *input.context','(true || p.context == *input.context)','reviewer_checkpoint_context_and_range_probes','CHECKPOINT observer-differs: ACCEPT'),
 ('candidate-writer',WRITER,'.ok();',CORPUS,'P01-writer-invalid-restoration-without-intent class=ACCEPTED_HOSTILE'),
]
def run(name,source,test):
 SOURCE.write_text(source)
 r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_replay_review_regressions',test,'--','--exact','--nocapture'],cwd=ROOT,capture_output=True,text=True,timeout=240)
 log=r.stdout+r.stderr;(OUT/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
 assert 'could not compile' not in log,name+' compile failure'
 return r,log
def main():
 if not __debug__:raise RuntimeError('assertions required')
 OUT.mkdir(parents=True,exist_ok=True);original=SOURCE.read_text();original_member=MEMBER.read_text()
 try:
  for name,old,new,test,signal in CASES:
   assert original.count(old)==1,(name,original.count(old))
   r,log=run(name,original.replace(old,new),test)
   assert r.returncode and signal in log,name+' did not demonstrate hostile acceptance'
   print('DEMONSTRATED: '+name,flush=True)
  old='key.length = Some(length);';assert original.count(old)==1
  changed=original.replace(old,'key.length = None;')
  r,log=run('record-length-alone',changed,CORPUS)
  assert 'P20-partial-copy-issuer-length-constrains-candidate class=DIAG detail=got candidate writer request' in log
  assert 'P20-partial-copy-issuer-length-constrains-candidate class=ACCEPTED_HOSTILE' not in log
  print('REDUNDANT DEFENSE: record-length-alone still refuses P20 via exact writer binding; diagnostic-only failure.',flush=True)
  r,log=run('record-length-and-writer',changed.replace(WRITER,'.ok();'),CORPUS)
  assert r.returncode and 'P20-partial-copy-issuer-length-constrains-candidate class=ACCEPTED_HOSTILE' in log
  print('DEMONSTRATED: record-length-and-writer (combined removal; not a single-guard kill)',flush=True)
  old='.map_err(|_| Error::Invalid("retained writer request"))?;';assert original_member.count(old)==1
  MEMBER.write_text(original_member.replace(old,'.ok();'))
  r,log=run('original-writer',original,CORPUS)
  assert r.returncode and 'P02-writer-invalid-bytes-as-original-refuse-member class=ACCEPTED_HOSTILE' in log
  print('DEMONSTRATED: original-writer (member validation, not a virtual-output-only control)',flush=True)
 finally:
  SOURCE.write_text(original);MEMBER.write_text(original_member)
 r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_replay','--test','evidence_recovery_replay_review_regressions'],cwd=ROOT,capture_output=True,text=True,timeout=240)
 (OUT/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
 print('Six single-guard semantic controls, one diagnostic-only redundant defense and one combined semantic control; restored suites pass.',flush=True)
if __name__=='__main__':main()
