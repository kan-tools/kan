#!/bin/sh
set -eu
root=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/reviews/opus-fixture-final
cd "$root"
export CARGO_TARGET_DIR="$root/target"
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
exec cargo "$@"
