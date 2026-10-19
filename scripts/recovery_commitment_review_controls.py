#!/usr/bin/env python3
"""Qualify promoted independent boundary probes and deterministic cancellation."""
from pathlib import Path
import json,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.local-state/commitment-followups/controls'
FILE=ROOT/'src/evidence_recovery_commitment.rs'
def main():
 OUT.mkdir(parents=True,exist_ok=True)
 subprocess.run([sys.executable,str(ROOT/'.design/reviews/kan-v2-recovery-commitment-opus/evidence/scripts/gen_cases_a.py'),str(OUT.parent/'reviewer-cases.json')],check=True)
 cases=json.loads((ROOT/'.local-state/commitment-followups/reviewer-cases.json').read_text())
 selected=[c for c in cases if c['name'][:4] in ['AC01','AC02','AC03','AC04','AC05','AC06','AC07','AC08','AC09','AC10','AC16','AC17','AC25']]
 original=FILE.read_text()
 try:
  for c in selected:
   assert original.count(c['old'])==c['count'],c['name']
   FILE.write_text(original.replace(c['old'],c['new']))
   args=['cargo','test','--features','v2-crypto']
   if c['name'][:4] in ['AC01','AC02','AC25']:args+=['--lib','evidence_recovery_commitment::polling_tests']
   else:args+=['--test','evidence_recovery_commitment_review_regressions']
   run=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=180)
   log=run.stdout+run.stderr;(OUT/(c['name']+'.txt')).write_text(log+'\nexit='+str(run.returncode)+'\n')
   assert run.returncode!=0 and 'could not compile' not in log and ' ... FAILED' in log,c['name']+' not demonstrated'
   print('DEMONSTRATED: '+c['name'],flush=True);FILE.write_text(original)
 finally:FILE.write_text(original)
 for name,args in [('integration',['--test','evidence_recovery_commitment','--test','evidence_recovery_commitment_review_regressions']),('polling',['--lib','evidence_recovery_commitment::polling_tests'])]:
  run=subprocess.run(['cargo','test','--features','v2-crypto']+args,cwd=ROOT,capture_output=True,text=True,timeout=180)
  (OUT/('restored-'+name+'.txt')).write_text(run.stdout+run.stderr+'\nexit='+str(run.returncode)+'\n');assert run.returncode==0,name+' restoration failed'
 print(str(len(selected))+' compiled controls fail assertions; restored tests pass.',flush=True)
if __name__=='__main__':main()
