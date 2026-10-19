# ADAPTED copy of .design/reviews/kan-v2-decoder-regressions-author/raw/controls.py:
# only the output directory and --offline/--locked changed. Run with cwd=export.
from pathlib import Path
import subprocess,difflib
root=Path.cwd();path=root/'src/evidence_reconstruction.rs';out=Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment/review-evidence/C/author-controls');original=path.read_text()
def run(name,test=None):
 cmd=['cargo','test','--offline','--locked','--features','v2-crypto','--test','evidence_reconstruction_review_regressions']
 if test:cmd += [test,'--','--exact']
 r=subprocess.run(cmd,cwd=root,capture_output=True,text=True,timeout=180);log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n');return r.returncode,log
code,log=run('02-baseline');assert code==0
clock='    if !object.contains_key("observed_at_unix_micros") {\n        return Err(Error::Header);\n    }\n';assert original.count(clock)==1
moved=original.replace(clock,'').replace('    if version != 2 {',clock+'    if version != 2 {')
cases=[('03-clock-before-unsupported',moved,'review_pa2_timestamp_distinction_and_unsupported_precedence'),('04-unit-fields-ignored',original.replace('if kind == "forwarding-intent" && event.len() != 1','if false && kind == "forwarding-intent" && event.len() != 1'),'review_pa1_capture_projection_is_lossless_over_mutation_corpus')]
try:
 for name,source,test in cases:
  path.write_text(source);(out/(name+'.diff')).write_text(''.join(difflib.unified_diff(original.splitlines(True),source.splitlines(True),fromfile='original',tofile='mutated')))
  code,log=run(name,test);assert code!=0 and 'could not compile' not in log and 'test '+test+' ... FAILED' in log,name
  print('DEMONSTRATED: '+name,flush=True)
finally:path.write_text(original)
code,log=run('05-restored');assert code==0
print('2 controls; restored review regressions pass.')
