#!/bin/sh
# Reviewer baseline: run from export root. Env inherited from runner (shared CARGO_TARGET_DIR, 4 jobs).
set -u
E=review-evidence/raw
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR JOBS=$CARGO_BUILD_JOBS pwd=$(pwd)" > $E/01-env.txt
cargo clean -p kan > $E/01-clean.txt 2>&1; echo "exit=$?" >> $E/01-clean.txt
cargo test --features v2-crypto --test evidence_attested_store --test evidence_attested_followups --test evidence_attested_lifecycle --test evidence_copy_plan --test evidence_copy_source --test recovery_cli --test surface_conformance --test evidence_overview_review_regressions > $E/02-targeted-AB.txt 2>&1; echo "exit=$?" >> $E/02-targeted-AB.txt
cargo test --features v2-crypto --lib evidence_operations::projection::tests > $E/03-projection.txt 2>&1; echo "exit=$?" >> $E/03-projection.txt
cargo test --features v2-crypto --lib evidence_operations_collection::overview::tests > $E/03-window.txt 2>&1; echo "exit=$?" >> $E/03-window.txt
cargo test --features v2-crypto --test evidence_capture_contention > $E/03-contention-all.txt 2>&1; echo "exit=$?" >> $E/03-contention-all.txt
cargo clippy --features v2-crypto --all-targets -- -D warnings > $E/04-clippy.txt 2>&1; echo "exit=$?" >> $E/04-clippy.txt
cargo fmt --all -- --check > $E/05-fmt.txt 2>&1; echo "exit=$?" >> $E/05-fmt.txt
