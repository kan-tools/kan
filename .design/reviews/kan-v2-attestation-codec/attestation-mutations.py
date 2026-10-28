from pathlib import Path
import subprocess
p=Path('src/evidence_attestation.rs');original=p.read_text()
root=Path('.local-state/attestation-mutations');root.mkdir(exist_ok=True)
labels=['pinned-issuer','configured-archive','configured-scope','sequence','profile','genesis','chain-position','chain-commitments','record-binding','receipt-binding','admitted-issuer','signature-range','signature-invalid','pinned-frontier']
try:
 for label in labels:
  anchor='return Err(invalid("'+label+'"));'
  assert original.count(anchor)==1,(label,original.count(anchor))
  p.write_text(original.replace(anchor,'let _removed_check = ();'))
  test='descending_pages_link_to_the_exact_pin_and_terminate_at_genesis' if label=='pinned-frontier' else 'independent_resigned_negative_vectors_fail_at_named_check'
  r=subprocess.run(['sh','.local-state/cargo.sh','test','--features','v2-crypto','--test','evidence_attestation',test,'--','--exact'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  (root/(label+'.txt')).write_bytes(r.stdout)
  assert r.returncode!=0 and b'could not compile' not in r.stdout and ('test '+test+' ... FAILED').encode() in r.stdout,(label,r.stdout[-2500:])
  print(label+': compiled named assertion failed',flush=True)
finally:p.write_text(original)
r=subprocess.run(['sh','.local-state/cargo.sh','test','--features','v2-crypto','--test','evidence_attestation','--test','evidence_contract'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(root/'restored.txt').write_bytes(r.stdout);assert r.returncode==0,r.stdout[-2500:]
print('Exact source restored; 5 attestation and 7 canonical codec tests pass.')
