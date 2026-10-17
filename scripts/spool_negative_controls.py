#!/usr/bin/env python3
"""Idle author worktree only. SIGKILL can leave a mutation: restore from Git then."""
import os
from pathlib import Path
import subprocess
source=Path('src/evidence_spool.rs')
original=source.read_bytes()
env=dict(os.environ,CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0')
for name,old,new,test in [
 ('ack proof','service::admitted_manifest(&request, &signed, &st.audience)?;', 'let _ = &signed;', 'exact_bytes_restart_capacity_and_proven_remote_acknowledgment'),
 ('capacity','if used.checked_add(bytes.len() as u64).ok_or(Error::Full)? > st.budget', 'if false && used.checked_add(bytes.len() as u64).ok_or(Error::Full)? > st.budget', 'exact_bytes_restart_capacity_and_proven_remote_acknowledgment'),
 ('chain frontier','if position != st.next || previous != st.previous', 'if false && (position != st.next || previous != st.previous)', 'wrong_binding_fork_and_reordered_ack_never_advance'),
]:
    text=original.decode()
    if text.count(old)!=1: raise SystemExit(name+': mutation not unique')
    try:
        source.write_text(text.replace(old,new,1))
        run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_spool',test],env=env,capture_output=True,text=True)
        if run.returncode==0 or 'test result: FAILED' not in run.stdout:
            raise SystemExit(name+': expected runtime failure absent\n'+run.stdout+run.stderr)
        print(name+': runtime regression detected',flush=True)
    finally:
        source.write_bytes(original)
subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_spool'],env=env,check=True)
