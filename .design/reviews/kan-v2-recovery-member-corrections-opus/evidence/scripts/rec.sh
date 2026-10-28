#!/bin/sh
# usage: rec.sh <logname> <command...>; records command, env, exit, raw output
log="$(dirname "$0")/../logs/$1.txt"; shift
{
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# cwd: $(pwd)"
  echo "# cmd: $*"
  echo "# ---"
} > "$log"
"$@" >> "$log" 2>&1
rc=$?
echo "# --- exit=$rc" >> "$log"
echo "exit=$rc log=$log"
exit $rc
