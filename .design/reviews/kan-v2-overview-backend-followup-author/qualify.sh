#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-collection-build
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export KAN_CRYPTO_ORACLE_PYTHON=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python
export KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
mkdir -p .local-state/reviews/overview-backend-author
cargo clean -p kan > .local-state/reviews/overview-backend-author/clean.txt 2>&1
cargo test --features v2-crypto --lib evidence_operations::projection::tests > .local-state/reviews/overview-backend-author/projection.txt 2>&1
cargo test --features v2-crypto --lib evidence_operations_collection::overview::tests > .local-state/reviews/overview-backend-author/window.txt 2>&1
cargo test --features v2-crypto --test evidence_overview_review_regressions --test surface_conformance > .local-state/reviews/overview-backend-author/integration.txt 2>&1
cargo test --features v2-crypto --test evidence_capture_contention coordinated_sink_returns_inner_wait_to_its_caller > .local-state/reviews/overview-backend-author/wrapper.txt 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > .local-state/reviews/overview-backend-author/clippy.txt 2>&1
python3 -B scripts/overview_review_negative_controls.py > .local-state/reviews/overview-backend-author/controls.txt 2>&1
cargo fmt --all -- --check > .local-state/reviews/overview-backend-author/fmt.txt 2>&1
