from pathlib import Path
import os,subprocess,json
root=Path(__file__).resolve().parents[2];base=root/'.local-state/assembly-followup';out=base/('controls-'+str(len(list(base.glob('controls-*')))+1));out.mkdir()
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4')
p=root/'src/evidence_assembly.rs';original=p.read_text()
try:
 for c in json.loads((base/'controls.json').read_text()):
  assert original.count(c['old'])==1,c['id'];p.write_text(original.replace(c['old'],c['new']))
  r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_assembly_review_regressions','--','--nocapture'],cwd=root,text=True,capture_output=True,timeout=240)
  log=r.stdout+r.stderr;(out/(c['id']+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and 'could not compile' not in log and ' ... FAILED' in log and 'assertion' in log,c['id']+' not demonstrated'
  print('DEMONSTRATED '+c['id'],flush=True);p.write_text(original)
finally:p.write_text(original)
r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_assembly','--test','evidence_assembly_review_regressions'],cwd=root,text=True,capture_output=True,timeout=240)
(out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
print('Five follow-up semantic controls demonstrated; restored tests pass.',flush=True)
