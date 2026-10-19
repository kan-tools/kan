#!/bin/sh
# run.sh LOGNAME CMD... : run in the export, record command, output, exit code and wall time.
set -u
log="$1"; shift
cd /Users/m/code/kan-tools/kan/.worktrees/kan-v2-session-assembly/.local-state/reviews/assembly-opening || exit 99
out="review-evidence/raw/$log.txt"
{
  printf '$ %s\n' "$*"
  printf '# cwd=%s CARGO_TARGET_DIR=%s CARGO_BUILD_JOBS=%s date=%s\n' "$PWD" "${CARGO_TARGET_DIR:-}" "${CARGO_BUILD_JOBS:-}" "$(date -u +%FT%TZ)"
} > "$out"
start=$(date +%s)
"$@" >> "$out" 2>&1
rc=$?
end=$(date +%s)
printf '\nexit=%s wall_s=%s\n' "$rc" "$((end-start))" >> "$out"
tail -n 25 "$out"
exit "$rc"
