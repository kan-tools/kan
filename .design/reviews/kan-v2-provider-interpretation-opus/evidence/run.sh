#!/bin/sh
# usage: run.sh LOGNAME cmd...  -- records cwd, env subset, command, output, exit code
log="$(dirname "$0")/logs/$1.txt"; shift
{ echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) cwd=$(pwd)"; echo "# CARGO_TARGET_DIR=$CARGO_TARGET_DIR CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"; echo "\$ $*"; } > "$log"
"$@" >> "$log" 2>&1; rc=$?
echo "# exit=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$log"
echo "$log exit=$rc"; exit $rc
