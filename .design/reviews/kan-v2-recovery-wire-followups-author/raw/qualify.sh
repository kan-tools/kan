#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-bundle-codec
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
out=$PWD/.local-state/wire-followups-author
cargo clean -p kan > "$out/05-clean.txt" 2>&1
cargo test --features v2-crypto --test evidence_recovery_observation --test evidence_reconstruction --test evidence_reconstruction_review_regressions > "$out/06-tests.txt" 2>&1
python3 - <<'PY' > "$out/07-order-control.txt" 2>&1
import importlib.util
spec=importlib.util.spec_from_file_location('controls','scripts/recovery_observation_negative_controls.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.CASES=[c for c in m.CASES if c[0]=='binary-cid-order'];assert len(m.CASES)==1;m.main()
PY
cargo clippy --features v2-crypto --all-targets -- -D warnings > "$out/08-clippy.txt" 2>&1
cargo fmt --all -- --check > "$out/09-fmt.txt" 2>&1
/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python .design/tools/recovery_observation_vectors.py --check > "$out/10-wire-check.txt" 2>&1
python3 .design/tools/recovery_commitments.py --check > "$out/11-framing-check.txt" 2>&1
python3 .design/tools/recovery_bundle_schema.py > "$out/12-schema-check.txt" 2>&1
