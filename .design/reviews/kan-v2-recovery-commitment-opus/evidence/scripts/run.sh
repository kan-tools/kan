#!/bin/sh
# Usage: run.sh <log-name> <command...>
# Runs one command from the export root, appends it to COMMANDS.txt, captures
# stdout+stderr to logs/<log-name>.txt and the exit code to logs/<log-name>.exit.
set -u
E=/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment
cd "$E" || exit 99
name=$1; shift
printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$*" >> review-evidence/COMMANDS.txt
"$@" > "review-evidence/logs/$name.txt" 2>&1
code=$?
printf '%s\n' "$code" > "review-evidence/logs/$name.exit"
printf 'exit=%s\n' "$code"
exit 0
