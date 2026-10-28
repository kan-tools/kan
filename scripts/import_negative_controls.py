#!/usr/bin/env python3
"""Idle author worktree only; restore source in finally (SIGKILL excepted)."""
import os
from pathlib import Path
import subprocess
source = Path('src/evidence_import.rs')
original = source.read_bytes()
env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
for name, old, new, test in [
    ('expected plan', 'if expected != self.id || route(spool)? != self.route {', 'if false && (expected != self.id || route(spool)? != self.route) {', 'pinned_inventory_detects_changes_and_route_identity_changes_before_admission'),
    ('chunk read commitment', 'if digest(&bytes) != expected.sha256 {', 'if false && digest(&bytes) != expected.sha256 {', 'changed_chunk_after_plan_validation_cannot_be_sealed'),
]:
    text = original.decode()
    if text.count(old) != 1:
        raise SystemExit(name + ': mutation not unique')
    try:
        source.write_text(text.replace(old, new, 1))
        result = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_import', test], env=env, capture_output=True, text=True)
        if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
            raise SystemExit(name + ': expected runtime regression absent\n' + result.stdout + result.stderr)
        print(name + ': runtime regression detected', flush=True)
    finally:
        source.write_bytes(original)
subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_import'], env=env, check=True)
