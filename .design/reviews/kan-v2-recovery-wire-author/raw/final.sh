#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-bundle-codec
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
out=$PWD/.local-state/bundle-codec-author
python3 scripts/recovery_observation_negative_controls.py > "$out/13-controls.txt" 2>&1
cargo test --features v2-crypto --test evidence_recovery_observation --test evidence_reconstruction --test evidence_attestation --test evidence_copy_plan > "$out/14-final-tests.txt" 2>&1
cargo clippy --features v2-crypto --all-targets -- -D warnings > "$out/15-final-clippy.txt" 2>&1
cargo fmt --all -- --check > "$out/16-final-fmt.txt" 2>&1
/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python .design/tools/recovery_observation_vectors.py --check > "$out/17-wire-oracle-check.txt" 2>&1
python3 .design/tools/recovery_commitments.py --check > "$out/18-commitments-check.txt" 2>&1
python3 .design/tools/recovery_bundle_schema.py > "$out/19-schema-check.txt" 2>&1
