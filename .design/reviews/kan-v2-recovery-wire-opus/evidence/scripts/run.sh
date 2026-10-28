#!/bin/sh
# usage: run.sh <logname> <cmd...> ; logs command, output, exit code under review-evidence/logs
set -u
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-bundle-codec/.local-state/reviews/recovery-wire || exit 99
log="review-evidence/logs/$1"; shift
{ echo "\$ $*"; echo "# start $(date -u +%FT%TZ) CARGO_TARGET_DIR=$CARGO_TARGET_DIR JOBS=$CARGO_BUILD_JOBS"; } > "$log"
"$@" >> "$log" 2>&1
rc=$?
echo "# end $(date -u +%FT%TZ) exit=$rc" >> "$log"
echo "$(date -u +%FT%TZ) $log exit=$rc :: $*" >> review-evidence/COMMANDS.txt
echo "$rc" > "$log.exit"
exit $rc
