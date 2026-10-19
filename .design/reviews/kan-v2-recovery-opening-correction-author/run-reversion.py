from pathlib import Path
import os,subprocess,sys
root=Path(__file__).resolve().parents[2];out=root/'.local-state/opening-correction/reversion';out.mkdir()
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='commit.gpgsign',GIT_CONFIG_VALUE_0='false')
commands=[('01-clean',['cargo','clean','-p','kan']),('02-reversion',['/opt/homebrew/bin/python3','scripts/revert_v2.py','--helper','/Users/m/.codex/plugins/cache/kan-tools/day/0.12.0-beta.3/scripts/revert-demo.py','--production','src/evidence_store/bundle.rs','--tests','evidence_recovery_bundle::empty_originals_remain_exact_evidence_before_and_after_restoration']),('03-clean-return',['cargo','clean','-p','kan'])]
for name,cmd in commands:
 r=subprocess.run(cmd,cwd=root,capture_output=True,text=True)
 (out/(name+'.txt')).write_text('$ '+' '.join(cmd)+'\n'+r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n')
 print(name,r.returncode,flush=True)
 if name=='02-reversion':print(r.stdout+r.stderr,flush=True)
 if r.returncode:sys.exit(r.returncode)
