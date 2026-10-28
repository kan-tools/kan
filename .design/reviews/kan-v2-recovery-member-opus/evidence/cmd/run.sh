#!/bin/sh
# Usage: run.sh <logname> <command...>; runs in export root, logs cmd/exit/time/output.
EXPORT=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member/.local-state/reviews/recovery-member
cd "$EXPORT" || exit 99
name=$1; shift
log="$EXPORT/review-evidence/logs/$name.txt"
start=$(date +%s)
{ echo "# cwd: $EXPORT"; echo "# cmd: $*"; echo "# started: $(date -u +%FT%TZ)"; } > "$log"
"$@" >> "$log" 2>&1
rc=$?
end=$(date +%s)
{ echo; echo "# exit=$rc elapsed_s=$((end-start))"; } >> "$log"
echo "$(date -u +%FT%TZ) $name exit=$rc elapsed=$((end-start))s :: $*" >> "$EXPORT/review-evidence/COMMANDS.txt"
echo "$name exit=$rc elapsed=$((end-start))s"
exit $rc
