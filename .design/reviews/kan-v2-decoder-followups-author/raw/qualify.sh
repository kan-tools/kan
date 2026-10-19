#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-reconstruction
out=$PWD/.local-state/decoder-followup-author
sh .local-state/cargo.sh clean -p kan > "$out/01-clean.txt" 2>&1
sh .local-state/cargo.sh test --features v2-crypto --test evidence_reconstruction > "$out/02-tests.txt" 2>&1
sh .local-state/cargo.sh clippy --features v2-crypto --all-targets -- -D warnings > "$out/03-clippy.txt" 2>&1
sh .local-state/cargo.sh fmt --all -- --check > "$out/04-fmt.txt" 2>&1
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
cargo clean -p kan > "$out/05-reversion-clean.txt" 2>&1
python3 scripts/revert_v2.py --helper /Users/m/.codex/plugins/cache/kan-tools/day/0.12.0-beta.3/scripts/revert-demo.py --tests evidence_reconstruction::every_recognized_event_rejects_extra_fields_including_unit_variants,evidence_reconstruction::recognized_header_requires_explicit_timestamp_even_when_unknown --production src/evidence_reconstruction.rs > "$out/06-reversion.txt" 2>&1
