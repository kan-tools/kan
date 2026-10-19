#!/bin/sh
set -eu
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member
export CARGO_TARGET_DIR=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
python3 scripts/recovery_member_negative_controls.py > .local-state/member-author/03-controls.txt 2>&1
sh .local-state/cargo.sh clippy --features v2-crypto --all-targets -- -D warnings > .local-state/member-author/04-clippy.txt 2>&1
sh .local-state/cargo.sh fmt --all -- --check > .local-state/member-author/05-fmt.txt 2>&1
/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python .design/tools/recovery_member_vectors.py --check > .local-state/member-author/06-oracle.txt 2>&1
