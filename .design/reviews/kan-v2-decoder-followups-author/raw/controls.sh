#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-reconstruction
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
cargo clean -p kan > .local-state/decoder-followup-author/07-controls-clean.txt 2>&1
python3 scripts/reconstruction_negative_controls.py total-family-bound unit-extra-fields required-clock-field > .local-state/decoder-followup-author/08-controls.txt 2>&1
cargo fmt --all -- --check > .local-state/decoder-followup-author/09-final-fmt.txt 2>&1
