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
#
# Any argument other than a recognised one is an error rather than a silent
# fall-through to the slow path: `-verify` used to run the whole suite while
# the caller waited for a one-line answer.
case "${1:-}" in
  "") ;;
  --verify)
    control=$(printf 'test result: ok. 10 passed; 0 failed; 0 ignored\ntest result: FAILED. 3 passed; 2 failed; 0 ignored\n' | parse)
    if [ "$control" = "13 2 2" ]; then
      echo "parser verified against a 13-passed/2-failed control: discriminates"
      exit 0
    fi
    echo "PARSER BROKEN: control returned '$control', expected '13 2 2'"
    exit 1 ;;
  *)
    echo "unknown argument: $1 (expected --verify or nothing)" >&2
    exit 2 ;;
esac

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

# A ZERO DENOMINATOR IS NOT A PASS. If nothing produced a `test result:` line
# -- a build failure, a filter that matched nothing, a harness change -- then
# "0 tests" is the absence of a measurement, not a measurement of zero.
if [ "$lines" -eq 0 ]; then
  echo "no test result lines parsed (cargo exit ${test_rc}) -- refusing to report a count" >&2
  tail -20 "$log" >&2
  exit 1
fi

# THE TESTS FIELD MUST DISCLOSE ITS OWN FAILURE, in the line itself. It was the
# only field that did not: two failures rendered as a bare "105 tests" while
# clippy and fmt correctly rendered WARNINGS and DIRTY, and the warning sat
# BELOW the line most likely to be copied. A footnote saying "do not paste the
# line above" is a discipline; putting the failure inside the line is a
# construction.
if [ "$failed" -ne 0 ]; then tests="${passed} tests (${failed} FAILING)"; else tests="${passed} tests"; fi

# A dirty tree attributes its numbers to a commit that did not produce them.
dirty=""
[ -n "$(git status --porcelain 2>/dev/null)" ] && dirty=" +uncommitted changes"

echo "\`$(git rev-parse --abbrev-ref HEAD)\` at \`$(git rev-parse --short HEAD)\`${dirty}. \
${tests}, clippy ${clippy}, fmt ${fmt}."

if [ "$failed" -ne 0 ] || [ "$test_rc" -ne 0 ] || [ "$fmt_rc" -ne 0 ] || [ "$clippy_rc" -eq 1 ]; then
  echo
  echo "NOT A CLEAN TREE. Diagnostics:" >&2
  [ "$fmt_rc" -ne 0 ] && printf '%s\n' "$fmt_out" | head -20 >&2
  [ "$clippy_rc" -ne 0 ] && printf '%s\n' "$clippy_out" | grep -E "^(error|warning)" | head -20 >&2
  [ "$failed" -ne 0 ] && grep -E "^(test .* FAILED|---- .* stdout)" "$log" | head -20 >&2
  exit 1
fi
