#!/usr/bin/env python3
"""Idle author checkout only: runtime regressions, restoring bytes in finally."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
env = dict(os.environ, CARGO_BUILD_JOBS='4', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
controls = [
    ('scope scan', 'src/evidence_store.rs',
     'SELECT EXISTS(SELECT 1 FROM commits WHERE scope < ?1) OR EXISTS(SELECT 1 FROM commits WHERE scope > ?1)',
     'SELECT EXISTS(SELECT 1 FROM commits WHERE scope != ?1)',
     ['--lib', 'evidence_store::admission_tests::scope_guard_uses_bounded_index_probes']),
    ('admission fence', 'src/evidence_store.rs',
     'if !matches {', 'if false && !matches {',
     ['--test', 'evidence_store', 'audited_partition_frontier_fences_new_writes_and_exact_retries']),
    ('missing object state', 'src/evidence_service.rs',
     'evidence_store::Error::Missing(_) => Failure::Corrupt,',
     'evidence_store::Error::Missing(_) => Failure::Missing,',
     ['--test', 'evidence_service', 'missing_committed_object_is_corrupt_on_read_and_startup']),
]
for name, relative, old, new, target in controls:
    source = root / relative
    original = source.read_bytes()
    text = original.decode()
    if text.count(old) != 1:
        raise SystemExit(f'{name}: mutation is not unique')
    command = ['cargo', 'test', '--features', 'v2-crypto', *target]
    subprocess.run(command, cwd=root, env=env, check=True)
    try:
        source.write_text(text.replace(old, new, 1))
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
        if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
            raise SystemExit(f'{name}: expected runtime failure absent\n{result.stdout}\n{result.stderr}')
        print(f'{name}: detected runtime failure', flush=True)
    finally:
        source.write_bytes(original)
    subprocess.run(command, cwd=root, env=env, check=True)
