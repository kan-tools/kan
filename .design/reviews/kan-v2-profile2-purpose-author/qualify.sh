#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-copy-destination
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
cargo clean -p kan > .local-state/reviews/profile2-purpose-author/clean.txt 2>&1
cargo test --features v2-crypto --test evidence_attested_store --test evidence_attested_followups --test evidence_attested_lifecycle --test evidence_copy_plan --test evidence_copy_source --test surface_conformance > .local-state/reviews/profile2-purpose-author/tests.txt 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > .local-state/reviews/profile2-purpose-author/clippy.txt 2>&1
python3 -B .local-state/reviews/profile2-purpose-author/revert.py > .local-state/reviews/profile2-purpose-author/reversion.txt 2>&1
cargo fmt --all -- --check > .local-state/reviews/profile2-purpose-author/fmt.txt 2>&1
