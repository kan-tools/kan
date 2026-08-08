#!/usr/bin/env bash
# Print the status line for a design doc's Status block. Measured, not typed.
#
# WHY THIS EXISTS. `.design/v0.12-milestone.md` carried "347 tests" for main
# across three sessions while CI reported 350 — a number taken once, pasted
# forward, and never re-measured. It had settled into the milestone doc, which
# is exactly where a later reader trusts it most. That is the same failure as a
# `PREDICTED` row that never converts: a figure nobody re-checks is
# indistinguishable from one that is right.
#
# So the fix is a construction rather than a discipline. Run this, paste the
# output. If the number is wrong, it is wrong about the tree in front of you
# rather than about a tree from last week.
#
# THE TEST COUNT IS SUMMED FROM `test result:` LINES, and the parser is worth a
# note because its predecessor was wrong: `grep -o` returns only the matched
# substring, which shifts awk's fields, so `$5`/`$7` are the WORDS "passed;"
# and "failed" rather than the numbers, and a string in arithmetic context is
# zero. It reported "failed: 0" against a control containing two failures. The
# fields here are `$4`/`$6`, and `--verify` proves that against a known control
# before you trust a run.
#
# Usage:  scripts/status-line.sh [--verify]
set -uo pipefail

parse() {
  grep -oE "^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed" \
    | awk '{p+=$4; f+=$6} END {printf "%d %d %d\n", p, f, NR}'
}

# A VERDICT MUST BE COMPUTED, NOT PRINTED. This branch exists so the healthy
# answer is unreachable unless a control with known failures reproduces
# exactly -- the probe that shipped before this printed "safe to trust"
# unconditionally, on the line after the check.
if [ "${1:-}" = --verify ]; then
  control=$(printf 'test result: ok. 10 passed; 0 failed; 0 ignored\ntest result: FAILED. 3 passed; 2 failed; 0 ignored\n' | parse)
  if [ "$control" = "13 2 2" ]; then
    echo "parser verified against a 13-passed/2-failed control: discriminates"
    exit 0
  fi
  echo "PARSER BROKEN: control returned '$control', expected '13 2 2'"
  exit 1
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT

cargo test --workspace >"$log" 2>&1
test_rc=$?
read -r passed failed lines < <(parse <"$log")

fmt_out=$(cargo fmt --all -- --check 2>&1); fmt_rc=$?
clippy_out=$(cargo clippy --workspace --all-targets -- -D warnings 2>&1); clippy_rc=$?

# Every field derived from an exit code or a count, never asserted.
[ "$fmt_rc" -eq 0 ]    && fmt="clean"    || fmt="DIRTY"
[ "$clippy_rc" -eq 0 ] && clippy="clean" || clippy="WARNINGS"

echo "\`$(git rev-parse --abbrev-ref HEAD)\` at \`$(git rev-parse --short HEAD)\`. \
${passed} tests, clippy ${clippy}, fmt ${fmt}."

if [ "$failed" -ne 0 ] || [ "$test_rc" -ne 0 ]; then
  echo
  echo "NOT A CLEAN TREE: ${failed} failing across ${lines} result lines (cargo exit ${test_rc})."
  echo "Do not paste the line above into a status block as though it were green."
  exit 1
fi
