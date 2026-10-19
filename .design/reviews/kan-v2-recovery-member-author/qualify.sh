#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
cargo clean -p kan > .local-state/member-author/01-clean.txt 2>&1
cargo test --features v2-crypto --test evidence_recovery_member > .local-state/member-author/02-tests.txt 2>&1
python3 scripts/recovery_member_negative_controls.py > .local-state/member-author/03-controls.txt 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > .local-state/member-author/04-clippy.txt 2>&1
cargo fmt --all -- --check > .local-state/member-author/05-fmt.txt 2>&1
"$KAN_CRYPTO_ORACLE_PYTHON" .design/tools/recovery_member_vectors.py --check > .local-state/member-author/06-oracle.txt 2>&1
