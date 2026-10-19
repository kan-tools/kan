from pathlib import Path
import subprocess,os,hashlib,json
root=Path.cwd();out=root/'.local-state/creation-controls';out.mkdir(exist_ok=False)
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='commit.gpgsign',GIT_CONFIG_VALUE_0='false')
cases=[
('wrong-write-capability','crate::persistence::SurfaceWrite::EvidenceBundle,','crate::persistence::SurfaceWrite::EvidenceArchive,','every_persistence_facade_call_is_independently_inventoried'),
('wrong-source-capability','crate::persistence::SurfaceWrite::EvidenceBundleSource,','crate::persistence::SurfaceWrite::EvidenceRecoverySource,','every_persistence_facade_call_is_independently_inventoried'),
('stale-selection','require(member.frontier() == selected, "selected source frontier")?;','let selected = member.frontier();','creation_refuses_stale_pins_invalid_physical_types_extra_proofs_and_existing_outputs'),
('extra-proofs','(None, None) => break,','(None, _) => break,','creation_refuses_stale_pins_invalid_physical_types_extra_proofs_and_existing_outputs'),
('output-cap','let pages = request.output_bytes / 4096;','let pages = (request.output_bytes / 4096).max(1024);','output_page_limit_retains_failure_without_truncating_source'),
('commit-outcome','if commit_attempted {','if false && commit_attempted {','precommit_cancellation_retains_unrecognized_artifact_and_postcommit_cancellation_is_uncertain'),
('premature-publication','observe(CreationBoundary::MemberInserted);','tx.execute_batch("PRAGMA application_id=1263419953; PRAGMA user_version=1; COMMIT; BEGIN IMMEDIATE;")?;\n        observe(CreationBoundary::MemberInserted);','abrupt_death_never_publishes_a_partial_created_bundle'),
]
p=Path('src/evidence_store/bundle/create.rs');original=p.read_text();before=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'identity.json').write_text(json.dumps({'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'path':str(p),'sha256':before,'status':subprocess.check_output(['git','status','--porcelain'],text=True)},indent=2))
try:
 for name,old,new,test in cases:
  assert original.count(old)==1,(name,original.count(old));p.write_text(original.replace(old,new))
  r=subprocess.run(['cargo','test','--features','v2-crypto','--test',('surface_conformance' if test.startswith('every_') else 'evidence_bundle_creation'),test,'--','--exact'],capture_output=True,text=True,timeout=240)
  log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and 'could not compile' not in log and ' ... FAILED' in log and 'panicked at' in log,name
  print('DEMONSTRATED '+name,flush=True);p.write_text(original)
finally:p.write_text(original)
assert hashlib.sha256(p.read_bytes()).hexdigest()==before
r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_bundle_creation'],capture_output=True,text=True,timeout=240);(out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
print('Restored creation tests pass.',flush=True)
