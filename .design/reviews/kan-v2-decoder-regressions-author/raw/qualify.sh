#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-reconstruction
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
out=$PWD/.local-state/decoder-regressions-author
cargo clean -p kan > "$out/01-clean.txt" 2>&1
python3 "$out/controls.py" > "$out/06-controls.txt" 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > "$out/07-clippy.txt" 2>&1
cargo fmt --all -- --check > "$out/08-fmt.txt" 2>&1
