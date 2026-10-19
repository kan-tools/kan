#!/usr/bin/env python3
"""Selected compiled controls for review corrections, with restored source/logs."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.local-state/member-followup/controls'
MEMBER=ROOT/'src/evidence_recovery_member.rs'
FRAME=ROOT/'src/evidence_recovery_commitment.rs'
TARGET='evidence_recovery_member_review_regressions'
CASES=[
 ('authenticated-length',MEMBER,'!hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64)','true || !hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64)',TARGET,'completed_copy_cannot_mislabel_hash_valid_orphan_with_false_length'),
 ('partial-length',MEMBER,'if !c.referenced {','if false && !c.referenced {',TARGET,'rp02_partial_profile3_membership_is_labeled_unverified'),
 ('partial-basis',MEMBER,'Basis::UnverifiedMembership','Basis::VerifiedCopyRecipe',TARGET,'rp02_partial_profile3_membership_is_labeled_unverified'),
 ('shared-request',MEMBER,'require(!c.referenced, "reused service request CID")?;','require(true || !c.referenced, "reused service request CID")?;',TARGET,'rp03_shared_request_cid_refuses_with_or_without_bytes'),
 ('request-bound',MEMBER,'n <= service::MAX_REQUEST as u64','true || n <= service::MAX_REQUEST as u64','evidence_recovery_member_corrections','authentic_bytes_with_false_metadata_are_not_repairable_loss'),
 ('membership-charge',MEMBER,'work.input(44)?;','',TARGET,'membership_bytes_are_charged_at_the_exact_input_boundary'),
 ('orphan-hash',MEMBER,'let hash_valid = actual == object.cid.to_bytes()[4..];','let hash_valid = true || actual == object.cid.to_bytes()[4..];',TARGET,'orphan_hash_mismatch_is_reported_without_rewriting_its_bytes'),
 ('issuer-utf8',FRAME,'!header.issuer.is_empty() && header.issuer.len() <= 80','!header.issuer.is_empty() && header.issuer.chars().count() <= 80','evidence_recovery_commitment_review_regressions','rv_a4_local_bounds_exact_edges'),
]
def main():
 if not __debug__:raise RuntimeError('assertions required')
 OUT.mkdir(parents=True,exist_ok=True);original={p:p.read_text() for p in [MEMBER,FRAME]}
 try:
  for name,path,old,new,target,test in CASES:
   assert original[path].count(old)==1,(name,original[path].count(old))
   path.write_text(original[path].replace(old,new))
   r=subprocess.run(['cargo','test','--features','v2-crypto','--test',target,test,'--','--exact','--nocapture'],cwd=ROOT,capture_output=True,text=True,timeout=240)
   log=r.stdout+r.stderr;(OUT/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
   assert r.returncode!=0,name+' SURVIVED'
   assert 'could not compile' not in log,name+' compile failure'
   assert 'test '+test+' ... FAILED' in log,name+' no named assertion failure'
   print('DEMONSTRATED: '+name,flush=True);path.write_text(original[path])
 finally:
  for path,s in original.items():path.write_text(s)
 r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_member','--test',TARGET,'--test','evidence_recovery_member_corrections','--test','evidence_recovery_commitment_review_regressions'],cwd=ROOT,capture_output=True,text=True,timeout=240)
 (OUT/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
 print('8 compiled controls failed named assertions; restored suites passed. See raw failures for semantics.',flush=True)
if __name__=='__main__':main()
