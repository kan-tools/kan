import importlib.util, os, pathlib, shutil, subprocess, sys, tempfile
root=pathlib.Path.cwd()
if shutil.disk_usage(root).free<15*1024**3: raise SystemExit('need 15GiB free')
scratch=pathlib.Path(tempfile.mkdtemp(prefix='kan-gateway-review-fix-revert-'))
print('scratch',scratch,flush=True)
paths=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=root).split(b'\0')
for raw in paths:
 if not raw:continue
 rel=pathlib.Path(os.fsdecode(raw))
 if rel.parts[0] in ('.local-state','.kan','.day','target'):continue
 source=root/rel
 if source.is_file() and not source.is_symlink():
  (scratch/rel).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,scratch/rel)
patch=subprocess.check_output(['git','diff','--unified=0','HEAD','--','src/evidence_operations.rs','src/evidence_capture.rs','web/operations/app.js'],cwd=root,text=True)
(scratch/'production-fix.patch').write_text(patch)
os.environ['KAN_CRYPTO_ORACLE_PYTHON']='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python'
os.environ.update(CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',CARGO_TARGET_DIR=str(scratch/'target'))
helper='/Users/m/.codex/plugins/cache/kan-tools/day/0.12.0-beta.3/scripts/revert-demo.py'
spec=importlib.util.spec_from_file_location('revert_demo',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
original_git=module.git
original_args=module.cargo_args
def git(*args,**kwargs):
 if args==('rev-parse','--show-toplevel'):return str(scratch)
 if args==('diff','--unified=0','HEAD'):return patch
 if args and args[0]=='ls-files':return ''
 return original_git(*args,**kwargs)
def cargo_args(name):
 args,filt=original_args(name);return args[:2]+['--features','v2-crypto']+args[2:]+['--','--exact'],filt
module.git=git;module.cargo_args=cargo_args
# Adapt only test execution for the Node client; patch selection, reversion,
# restoration, outcome classification and trailer remain the bundled tool's.
original_run_tests=module.run_tests
node_spec='node::future_clock_badge'
node_name='future clock samples produce consistent badges and retain uncertain reporter history'
node_phase=0
def run_tests(specs,cwd,target_dir):
 global node_phase
 rust=[name for name in specs if name!=node_spec]
 results,compiled=original_run_tests(rust,cwd,target_dir)
 if not compiled or node_spec not in specs:return results,compiled
 import re
 node_phase+=1
 r=subprocess.run(['node','--test','--test-reporter=tap','--test-name-pattern=^'+re.escape(node_name)+'$','tests/operations_ui.test.cjs'],cwd=cwd,capture_output=True,text=True,timeout=30)
 output=r.stdout+r.stderr
 (scratch/f'node-reversion-{node_phase}.txt').write_text(output)
 ran=set();failed=set()
 for line in output.splitlines():
  match=re.fullmatch(r'(not ok|ok) \d+ - (.+)',line)
  if match and match.group(2)==node_name:
   ran.add(node_name)
   if match.group(1)=='not ok':failed.add(node_name)
 # A selected assertion must actually run; syntax errors and empty selection
 # produce no matching named result, and the helper reports NO-SUCH-TEST.
 results[node_spec]=(ran,failed)
 return results,compiled
module.run_tests=run_tests
try:
 subprocess.run(['cp','-cR','/Users/m/code/kan-tools/kan/.worktrees/kan-v2-gateway/target',str(scratch/'target')],check=True,timeout=60)
 subprocess.run(['cargo','clean','-p','kan'],cwd=scratch,check=True,timeout=60)
 os.chdir(scratch)
 sys.argv=[helper,'--tests','lib::evidence_operations::tests::burst_keeps_final_cumulative_summary_and_terminal_gap,evidence_operations::persisted_terminal_observation_rejects_regression_and_contradiction,node::future_clock_badge']
 module.main()
finally:
 shutil.rmtree(scratch/'target',ignore_errors=True)
 print('removed scratch target; source and patch retained',flush=True)
