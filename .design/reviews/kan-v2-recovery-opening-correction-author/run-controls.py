from pathlib import Path
import os,subprocess,sys
root=Path(__file__).resolve().parents[2];base=root/'.local-state/opening-correction';out=base/('controls-'+str(len(list(base.glob('controls-*')))+1));out.mkdir()
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3')
bundle=root/'src/evidence_store/bundle.rs';replay=root/'src/evidence_recovery_replay.rs';original={p:p.read_text() for p in [bundle,replay]}
progress="""    conn.progress_handler(
        1000,
        Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),
    )?;"""
cases=[('canonical-spelling',bundle,'value.to_string() == text','true || value.to_string() == text','evidence_recovery_bundle','parser_accepted_noncanonical_spellings_refuse_in_every_key_table','accepted mutation:'),('vm-progress',bundle,progress,'// intentionally removed progress handler','evidence_recovery_bundle','sqlite_schema_loading_obeys_deadline_and_in_flight_cancellation','deadline did not interrupt SQLite schema loading'),('writer-pass-accounting',replay,'(row.manifest.len() + row.receipt.len() + c.bytes.len()) as u64','0','evidence_recovery_replay_review_regressions','reviewer_budget_monotonicity_and_bounds','scan-charge accounting:')]
try:
 for name,path,old,new,target,test,needle in cases:
  assert original[path].count(old)==1,(name,original[path].count(old))
  path.write_text(original[path].replace(old,new))
  r=subprocess.run(['cargo','test','--features','v2-crypto','--test',target,test,'--','--exact','--nocapture'],cwd=root,text=True,capture_output=True,timeout=240)
  log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and 'could not compile' not in log and 'test '+test+' ... FAILED' in log and needle in log,name+' not demonstrated'
  print('DEMONSTRATED '+name,flush=True);path.write_text(original[path])
finally:
 for path,data in original.items():path.write_text(data)
r=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_bundle','--test','evidence_recovery_replay_review_regressions'],cwd=root,text=True,capture_output=True,timeout=240)
(out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
print('All three selected controls demonstrated; restored tests pass.',flush=True)
