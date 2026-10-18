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
scratch = Path(tempfile.mkdtemp(prefix='kan-gateway-controls-'))
print(f'committed source: {head}; scratch: {scratch}', flush=True)
archive = subprocess.check_output(['git','archive',head],cwd=root)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    for member in tar.getmembers():
        name = Path(member.name)
        if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe source-export archive entry')
    tar.extractall(scratch)  # members checked above; supports system Python 3.9
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
    controls=[
        ('client-auth','src/evidence_gateway.rs','.with_client_cert_verifier(verifier)','.with_no_client_auth()','tls_and_local_auth_fail_before_provider'),
        ('local-auth','src/evidence_gateway.rs','if let Some(token) = token {','if let Some(token) = token.filter(|_|false) {','tls_and_local_auth_fail_before_provider'),
        ('completion','src/evidence_gateway.rs','if self.complete.load(Ordering::Acquire) {','if true {','truncated_upstream_remains_incomplete_with_visible_gaps'),
        ('cancel','src/evidence_gateway.rs','self.0.abort();','let _ = &self.0;','downstream_disconnect_aborts_owned_forwarder'),
        ('provider-key','src/evidence_gateway.rs','outgoing.insert("x-api-key", key.clone());','let _ = key;','anthropic_profile_preserves_sse_open_headers_and_separates_credentials'),
        ('protocol-headers','src/evidence_gateway.rs','name.as_str().starts_with("anthropic-")','false','anthropic_profile_preserves_sse_open_headers_and_separates_credentials'),
        ('secret-omission','src/evidence_capture.rs','"authorization" | "x-api-key" | "proxy-authorization" | "cookie" | "set-cookie"','"cookie" | "set-cookie"','anthropic_profile_preserves_sse_open_headers_and_separates_credentials'),
    ]
    command=['cargo','test','--features','v2-crypto','--test','evidence_gateway']
    code,output=run(command,'baseline')
    if code or not passed(output,15):raise SystemExit('baseline failed\n'+output)
    for name,file,old,new,test in controls:
        source = scratch / file
        original = source.read_text()
        if original.count(old)!=1: raise SystemExit(f'{name}: edit not unique')
        target='evidence_gateway'
        selected=['cargo','test','--features','v2-crypto','--test',target,test,'--','--exact']
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
