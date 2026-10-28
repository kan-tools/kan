#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
out=$PWD/.local-state/commitment-author
cargo clean -p kan > "$out/08-parent-update-clean.txt" 2>&1
cargo test --features v2-crypto --test evidence_recovery_commitment --test evidence_recovery_observation --test evidence_reconstruction --test evidence_reconstruction_review_regressions > "$out/09-final-tests.txt" 2>&1
python3 - <<'PY' > "$out/10-order-control.txt" 2>&1
import importlib.util
spec=importlib.util.spec_from_file_location('controls','scripts/recovery_commitment_negative_controls.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.CASES=[c for c in m.CASES if c[0]=='binary-cid-order'];assert len(m.CASES)==1;m.main()
PY
cargo clippy --features v2-crypto --all-targets -- -D warnings > "$out/11-final-clippy.txt" 2>&1
cargo fmt --all -- --check > "$out/12-final-fmt.txt" 2>&1
python3 .design/tools/recovery_commitments.py --check > "$out/13-final-oracle.txt" 2>&1
