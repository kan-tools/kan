#!/usr/bin/env bash
# Turn one PREDICTED row of the migration-expectations table into a MEASURED
# one, in place, preserving everything a human wrote.
#
# WHY THIS IS A SCRIPT AND NOT A RED BUILD. The gate this replaces failed the
# run that took the measurement -- so the FIRST CORRECT MEASUREMENT was the
# failing case, and every release inherited one scheduled red at the next
# release's PR. That is the shape ADR-78 already condemned once ("a permanently
# red gate is one nobody reads"), reintroduced as a recurring one. A gate should
# fire when something is WRONG. Here nothing was: the outcome matched its
# prediction exactly, and all that remained was bookkeeping.
#
# So the bookkeeping is done by the machine that has the answer. The expectation
# stays the pass criterion -- a row whose outcome does NOT match still fails,
# loudly, and this script is never reached.
#
# WHAT IT PRESERVES. The `why` column carries reasoning nobody wants regenerated:
# which model predicted the outcome, what the row is a control for, what a
# future disagreement would mean. Only the leading token is rewritten, so
#
#     PREDICTED at cut time. The identity-at-rest plane is ...
#
# becomes
#
#     MEASURED in run 123, confirming what was PREDICTED at cut time. The
#     identity-at-rest plane is ...
#
# and every clause after the first word survives verbatim.
#
# IDEMPOTENT: a row that already says MEASURED is left alone and exits 0, so a
# re-run, a retry, or two cells racing cannot double-convert or corrupt a row.
#
# Usage: convert-prediction.sh <tag> <mode> <run-id> [tsv-path]

set -euo pipefail

tag="${1:?tag required}"
mode="${2:?mode required}"
run_id="${3:?run id required}"
tsv="${4:-tests/fixtures/migration-expectations.tsv}"

if [ ! -f "$tsv" ]; then
  echo "convert-prediction: no such table: $tsv" >&2
  exit 1
fi

python3 - "$tag" "$mode" "$run_id" "$tsv" <<'PY'
import sys

tag, mode, run_id, path = sys.argv[1:5]
lines = open(path).read().split("\n")
out, found, converted = [], False, False

for line in lines:
    fields = line.split("\t")
    if len(fields) >= 4 and fields[0] == tag and fields[1] == mode:
        found = True
        why = fields[3]
        if why.startswith("PREDICTED"):
            # Replace the leading token only. Everything the author wrote after
            # it is reasoning that outlives the prediction.
            rest = why[len("PREDICTED"):].lstrip()
            fields[3] = f"MEASURED in run {run_id}, confirming what was PREDICTED {rest}"
            line = "\t".join(fields)
            converted = True
    out.append(line)

if not found:
    sys.stderr.write(f"convert-prediction: no row for ({tag}, {mode}) in {path}\n")
    sys.exit(1)

if converted:
    open(path, "w").write("\n".join(out))
    print(f"converted ({tag}, {mode}) -> MEASURED in run {run_id}")
else:
    # Already measured. Not an error: a re-run must be safe.
    print(f"({tag}, {mode}) is already a measurement -- nothing to do")
PY
