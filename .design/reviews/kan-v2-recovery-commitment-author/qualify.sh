#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
out=$PWD/.local-state/commitment-author
cargo clean -p kan > "$out/03-clean.txt" 2>&1
cargo test --features v2-crypto --test evidence_recovery_commitment > "$out/04-tests.txt" 2>&1
python3 scripts/recovery_commitment_negative_controls.py > "$out/05-controls.txt" 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > "$out/06-clippy.txt" 2>&1
cargo fmt --all -- --check > "$out/07-fmt.txt" 2>&1
