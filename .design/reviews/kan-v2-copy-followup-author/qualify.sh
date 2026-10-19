#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-copy-upgrade
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
mkdir -p .local-state/reviews/copy-followup-author
cargo clean -p kan > .local-state/reviews/copy-followup-author/clean.txt 2>&1
cargo test --features v2-crypto --test evidence_copy_plan --test evidence_copy_source --test evidence_attested_lifecycle --test recovery_cli --test surface_conformance > .local-state/reviews/copy-followup-author/tests.txt 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > .local-state/reviews/copy-followup-author/clippy.txt 2>&1
python3 -B scripts/copy_plan_negative_controls.py > .local-state/reviews/copy-followup-author/controls.txt 2>&1
python3 -B scripts/attested_lifecycle_negative_controls.py > .local-state/reviews/copy-followup-author/lifecycle-controls.txt 2>&1
cargo fmt --all -- --check > .local-state/reviews/copy-followup-author/fmt.txt 2>&1
