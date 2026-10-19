from pathlib import Path
import subprocess,json,hashlib
base=Path('.local-state/provider-followup');out=base/('controls-'+str(len(list(base.glob('controls-*')))+1));out.mkdir()
p=Path('src/evidence_interpretation.rs');original=p.read_text();before=hashlib.sha256(p.read_bytes()).hexdigest()
args=['sh','.local-state/cargo.sh','test','--features','v2-crypto','--test','evidence_interpretation','--test','evidence_interpretation_review_regressions','--test','evidence_interpretation_followups']
try:
 for c in json.loads((base/'controls.json').read_text()):
  old,new=c['old'],c['new'];occ=c['occurrence']
  if occ is None:assert original.count(old)==1,c['id'];mutated=original.replace(old,new)
  else:
   index=-1
   for _ in range(occ+1):index=original.index(old,index+1)
   mutated=original[:index]+new+original[index+len(old):]
  p.write_text(mutated);r=subprocess.run(args,capture_output=True,text=True,timeout=240);log=r.stdout+r.stderr
  (out/(c['id']+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and 'could not compile' not in log and ' ... FAILED' in log and ('assertion' in log or 'called `Result::unwrap_err()` on an `Ok` value' in log or ' cohered' in log),c['id']+' not semantically demonstrated'
  print('DEMONSTRATED '+c['id'],flush=True);p.write_text(original);assert hashlib.sha256(p.read_bytes()).hexdigest()==before
finally:p.write_text(original)
r=subprocess.run(args,capture_output=True,text=True,timeout=240);(out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
print('All twelve selected controls demonstrated; source restored and tests pass.',flush=True)
