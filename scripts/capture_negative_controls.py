#!/usr/bin/env python3
"""Mutate a committed source export, never the invoking checkout.
Mac/APFS dependency clone; bounded runtime witnesses and restoration; retain logs.
"""
import io
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
if shutil.disk_usage(root).free < 15 * 1024**3:
    raise SystemExit('need at least 15 GiB free for scratch build')
head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
scratch = Path(tempfile.mkdtemp(prefix='kan-capture-controls-'))
print(f'committed source: {head}; scratch: {scratch}', flush=True)
archive = subprocess.check_output(['git','archive',head],cwd=root)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(scratch, filter='data')
env = dict(os.environ, CARGO_BUILD_JOBS='4', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(scratch/'target'))
def run(args, name, timeout=180):
    log = scratch/(name+'.log')
    with log.open('w') as out:
        child = subprocess.Popen(args,cwd=scratch,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            code=child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL); child.wait()
            raise SystemExit(f'{name}: timeout, not a runtime kill')
    return code,log.read_text()
def passed(output,n):
    return re.search(rf'^test result: ok\. {n} passed; 0 failed;',output,re.M) is not None
try:
    subprocess.run(['cp','-cR',str(root/'target'),str(scratch/'target')],check=True,timeout=60)
    code,output=run(['cargo','clean','-p','kan'],'clean',60)
    if code: raise SystemExit(output)
    source=scratch/'src/evidence_capture.rs'; original=source.read_text()
    controls=[
        ('gap-health','if self.sink.admit(&operation, &frame).is_ok() {','if { let _ = self.sink.admit(&operation, &frame); true } {','full_and_unavailable_capture_continue_with_visible_gap'),
        ('response-evidence','recorder.record(Event::ResponseChunk { offset }, chunk)?;','let _ = offset;','disconnect_is_unknown_and_retains_observed_prefix'),
        ('unknown-outcome','let success = matches!(result, Ok(Ok(())));','let success = true;','disconnect_is_unknown_and_retains_observed_prefix'),
        ('redirect','reqwest::redirect::Policy::none()','reqwest::redirect::Policy::limited(1)','redirect_is_observed_but_never_followed'),
        ('observer-id','Observer::Gateway => 1,','Observer::Gateway => 0,','binary_stream_above_ten_mib_has_exact_bodies_and_independent_frames'),
        ('flush','output.flush().await.map_err(|_| Error::OutcomeUnknown)?;','// omit output flush','empty_body_still_requires_successful_output_flush'),
    ]
    command=['cargo','test','--features','v2-crypto','--test','evidence_capture']
    code,output=run(command,'baseline')
    if code or not passed(output,14): raise SystemExit('baseline failed\n'+output)
    for name,old,new,test in controls:
        if original.count(old)!=1: raise SystemExit(f'{name}: edit not unique')
        selected=command+[test,'--','--exact']
        try:
            source.write_text(original.replace(old,new,1))
            code,output=run(selected,name)
            if code==0 or not re.search(r'^test result: FAILED\. 0 passed; 1 failed;',output,re.M) or f'test {test} ... FAILED' not in output:
                raise SystemExit(f'{name}: no named runtime failure\n{output}')
            print(f'{name}: named runtime failure',flush=True)
        finally:
            source.write_text(original)
        code,output=run(selected,name+'-restored')
        if code or not passed(output,1): raise SystemExit(f'{name}: restoration failed\n{output}')
    print(f'{len(controls)} controls killed and restored',flush=True)
finally:
    if (scratch/'target').exists():
        shutil.rmtree(scratch/'target')
        print('removed scratch target; source/logs retained',flush=True)
