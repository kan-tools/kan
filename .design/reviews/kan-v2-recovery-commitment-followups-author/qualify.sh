#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
cargo clean -p kan > .local-state/commitment-followups/01-clean.txt 2>&1
cargo test --features v2-crypto --test evidence_recovery_commitment --test evidence_recovery_commitment_review_regressions > .local-state/commitment-followups/02-tests.txt 2>&1
cargo test --features v2-crypto --lib evidence_recovery_commitment::polling_tests > .local-state/commitment-followups/03-polling.txt 2>&1
python3 scripts/recovery_commitment_review_controls.py > .local-state/commitment-followups/04-controls.txt 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > .local-state/commitment-followups/05-clippy.txt 2>&1
cargo fmt --all -- --check > .local-state/commitment-followups/06-fmt.txt 2>&1
python3 .design/tools/recovery_commitments.py --check > .local-state/commitment-followups/07-oracle.txt 2>&1
