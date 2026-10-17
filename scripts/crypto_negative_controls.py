#!/usr/bin/env python3
"""Idle author worktree only; restore source even after expected test failures."""
import os
from pathlib import Path
import subprocess
source = Path("src/evidence_crypto.rs")
original = source.read_bytes()
env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0")
for name, changes, test in [
    ("scope binding", [("info.extend_from_slice(scope);", "let _ = scope; info.extend_from_slice(&[0;32]);")], "authenticated_boundaries_and_fresh_encapsulation"),
    ("header authentication", [("context.seal(plaintext, &frame)", "context.seal(plaintext, &[])"), (".open(&frame[HEADER..], &frame[..HEADER])", ".open(&frame[HEADER..], &[])")], "independent_receiver_accepts_and_rejects_authenticated_data"),
]:
    text = original.decode()
    for old, new in changes:
        if text.count(old) != 1: raise SystemExit(name + ": mutation not unique")
        text = text.replace(old, new, 1)
    try:
        source.write_text(text)
        result = subprocess.run(["cargo", "test", "--features", "v2-crypto", "--test", "evidence_crypto", test], env=env, capture_output=True, text=True)
        if result.returncode == 0 or "test result: FAILED" not in result.stdout:
            raise SystemExit(name + ": expected runtime failure absent\n" + result.stdout + result.stderr)
        print(name + ": runtime regression detected", flush=True)
    finally:
        source.write_bytes(original)
subprocess.run(["cargo", "test", "--features", "v2-crypto", "--test", "evidence_crypto"], env=env, check=True)
