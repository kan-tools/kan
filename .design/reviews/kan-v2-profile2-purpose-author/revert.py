from pathlib import Path
import subprocess
root=Path.cwd(); path=root/'src/evidence_store/attested.rs'; out=root/'.local-state/reviews/profile2-purpose-author'
fixed=path.read_bytes()
assert fixed==subprocess.check_output(['git','show','648c8d7:src/evidence_store/attested.rs'])
prior=subprocess.check_output(['git','show','77eaac7:src/evidence_store/attested.rs'])
assert prior!=fixed
cases=[('evidence_attested_store','purpose_order_is_a_store_invariant_not_just_a_signature_check'),('evidence_attested_followups','p5a_single_historical_issuer_prefix_requires_copy_profile'),('evidence_attested_followups','p5c_planless_historical_proofs_refuse_verification_and_rebuild_without_rewriting')]
try:
 path.write_bytes(prior)
 for suite,test in cases:
  r=subprocess.run(['cargo','test','--features','v2-crypto','--test',suite,test,'--','--exact'],capture_output=True,text=True)
  text=r.stdout+r.stderr;(out/(test+'-reverted.txt')).write_text(text)
  assert r.returncode!=0 and 'could not compile' not in text and 'test '+test+' ... FAILED' in text,test
  print('whole production fix reversion fails:',test,flush=True)
finally:path.write_bytes(fixed)
r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_attested_store','--test','evidence_attested_followups','--test','evidence_attested_lifecycle'],capture_output=True,text=True)
(out/'restored.txt').write_text(r.stdout+r.stderr)
assert r.returncode==0,'restored failed'
print('restored proof-store/followup/lifecycle tests pass',flush=True)
