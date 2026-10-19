from pathlib import Path
import os, subprocess, sys
root=Path(__file__).resolve().parents[1]; base=root/'.local-state/provider-author';base.mkdir(exist_ok=True);out=base/('attempt-'+str(len(list(base.glob('attempt-*')))+1));out.mkdir()
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='commit.gpgsign',GIT_CONFIG_VALUE_0='false')
commands=[('02-clean',['cargo','clean','-p','kan']),('03-tests',['cargo','test','--features','v2-crypto','--test','evidence_interpretation','--test','evidence_assembly','--test','evidence_reconstruction','--test','evidence_reconstruction_review_regressions']),('03b-cancellation',['cargo','test','--features','v2-crypto','--lib','evidence_interpretation::tests']),('04-clippy',['cargo','clippy','--features','v2-crypto','--all-targets','--','-D','warnings']),('05-format',['cargo','fmt','--all','--','--check'])]
for name,cmd in commands:
 r=subprocess.run(cmd,cwd=root,capture_output=True,text=True)
 (out/(name+'.txt')).write_text('$ '+' '.join(cmd)+'\n'+r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n')
 print(name,r.returncode,flush=True)
 if r.returncode:print((r.stdout+r.stderr)[-6000:]);sys.exit(r.returncode)
