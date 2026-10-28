#!/bin/sh
# Bounded baseline; one heavy job at a time.
EXP=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-reconstruction/.local-state/reviews/reconstruction
OUT=$EXP/review-evidence/raw/final-restored
mkdir -p $OUT
cd $EXP || exit 1
run() { name=$1; shift; "$@" > $OUT/$name.txt 2>&1; echo "exit=$?" >> $OUT/$name.txt; }
run inventory cargo test --features v2-crypto --test evidence_inventory
run inventory-vm cargo test --features v2-crypto --lib evidence_store::inventory::tests
run copy_destination cargo test --features v2-crypto --test evidence_copy_destination
run reconstruction cargo test --features v2-crypto --test evidence_reconstruction
run capture cargo test --features v2-crypto --test evidence_capture
run clippy cargo clippy --features v2-crypto --all-targets -- -D warnings
run fmt cargo fmt --all -- --check
touch $OUT/DONE
