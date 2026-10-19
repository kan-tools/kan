from pathlib import Path
import subprocess,hashlib,json,os
root=Path.cwd();out=root/'.local-state/content-controls';out.mkdir(exist_ok=False)
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='commit.gpgsign',GIT_CONFIG_VALUE_0='false')
cases=[
('final-current-grant','            self.page(pin, sequences[0] - 1, 1).await?;','', 'evidence_reader','content_rechecks_current_grant_after_successful_acquisition'),
('duplicate-selection','|| sequences.iter().collect::<BTreeSet<_>>().len() != sequences.len()','|| false && sequences.iter().collect::<BTreeSet<_>>().len() != sequences.len()', 'evidence_reader','content_refuses_invalid_selections_tampering_and_revocation_without_partial_success'),
('exact-u64','"sequence":row.sequence.to_string()','"sequence":row.sequence', 'lib','evidence_content::tests::canonical_decimal_and_new_source_coordinates_preserve_full_width'),
('serialized-cap','if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {','if false && bytes.len() > self.limit.saturating_sub(self.bytes.len()) {','lib','evidence_content::tests::serialized_byte_limit_and_cancellation_refuse_without_partial_output'),
('independent-items','const ITEMS: usize = 1024;','const ITEMS: usize = 1025;','evidence_reader','content_has_an_independent_item_limit_with_no_partial_success'),
('mapping-work','budget.charge_scan(charge)?;','let _ = charge;','lib','evidence_content::tests::aggregate_work_is_charged_across_interpretation_and_all_item_mappings'),
]
p=root/'src/evidence_content.rs';original=p.read_text();before=hashlib.sha256(p.read_bytes()).hexdigest()
try:
 for name,old,new,target,test in cases:
  assert original.count(old)==1,(name,original.count(old))
  p.write_text(original.replace(old,new));cmd=['cargo','test','--features','v2-crypto']+(['--lib'] if target=='lib' else ['--test',target])+[test,'--','--exact']
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=240);log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and 'could not compile' not in log and ' ... FAILED' in log and 'panicked at' in log,name
  print('DEMONSTRATED '+name,flush=True);p.write_text(original)
finally:p.write_text(original)
assert hashlib.sha256(p.read_bytes()).hexdigest()==before
r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_reader','content_'],capture_output=True,text=True);(out/'restored-reader.txt').write_text(r.stdout+r.stderr);assert r.returncode==0
r=subprocess.run(['cargo','test','--features','v2-crypto','--lib','evidence_content::tests'],capture_output=True,text=True);(out/'restored-units.txt').write_text(r.stdout+r.stderr);assert r.returncode==0
print('Restored Content tests pass.',flush=True)
