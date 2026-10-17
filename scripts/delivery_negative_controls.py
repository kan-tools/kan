#!/usr/bin/env python3
"""Run only in an idle author worktree; finally restores source except on SIGKILL."""
import os
from pathlib import Path
import subprocess
source = Path('src/evidence_delivery.rs')
original = source.read_bytes()
env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
for name, old, new, test in [
    ('durable admission', 'if spool.enqueue(&request)? != Enqueue::Queued {', 'if false && spool.enqueue(&request)? != Enqueue::Queued {', 'maximum_and_empty_inputs_and_exact_request_provenance'),
    ('acknowledgment publication', 'spool.acknowledge(&reply.bytes()?)?;', 'let _ = &reply;', 'remote_rejections_preserve_head_and_stale_ack_cannot_remove_next'),
    ('offline scope and writer pin', 'signed.request.scope != service::hex(scope) || signed.request.principal != writer', 'false && (signed.request.scope != service::hex(scope) || signed.request.principal != writer)', 'offline_decryption_requires_all_pins_and_private_key_permissions'),
]:
    text = original.decode()
    if text.count(old) != 1:
        raise SystemExit(name + ': mutation not unique')
    try:
        source.write_text(text.replace(old, new, 1))
        run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_delivery', test], env=env, capture_output=True, text=True)
        if run.returncode == 0 or 'test result: FAILED' not in run.stdout:
            raise SystemExit(name + ': expected runtime regression absent\n' + run.stdout + run.stderr)
        print(name + ': runtime regression detected', flush=True)
    finally:
        source.write_bytes(original)
subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_delivery'], env=env, check=True)
