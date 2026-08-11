#!/usr/bin/env bash
# Key-op latency across a claims x subjects grid, and the scaling gate over it.
#
# Design: .design/perf-instrument.md. Serves telos/performance-at-scale.
#
# Two invocations, one file, so the measurement and the judgment cannot drift
# apart:
#
#   run-perf-grid.sh measure <kan-binary>          > results.tsv
#   run-perf-grid.sh gate    results.tsv tests/fixtures/perf-bounds.tsv
#
# `measure` prints ONE TSV to stdout (op, claims, subjects, ms); everything
# else goes to stderr. `gate` computes the growth ratio per (op, axis) from a
# results file and errors when a committed bound is exceeded. Absolute times
# are never judged -- the gate is about SHAPE (kan#181 was 141s of O(n^2)
# subprocesses next to a 72ms `--json` read of the same subject; the decade between linear and
# quadratic is wider than any runner's noise, which is what makes the ratio
# gateable where wall-clock is not).
set -euo pipefail

say() { echo "$@" >&2; }

# THE GRID IS THE CONTRACT. Expanded here, on purpose: changing coverage is a
# reviewed edit to this list, not a workflow input somebody quietly lowers to
# make a slow run finish. Ratios below are computed from named entries in
# this list; the gate resolves them by (claims, subjects) pair, so editing
# the list without editing the axes in `gate_axes` is an error, not a skew.
GRID=(
  "50 4"
  "200 4"
  "800 4"
  "800 40"
  "800 400"
)

# Claims axis: 16x claims, subjects fixed. Subjects axis: 100x subjects,
# claims fixed. Small end first, large end second. Absolute sizes are the
# SMALLEST at which the shapes are already visible (the first smoke run saw
# status-all's superlinearity by 200 claims) -- the RATIOS are what the gate
# consumes, and 16x/100x hold regardless of the absolutes. Going higher
# costs minutes of generation per point and buys no discrimination; it also
# starts to MEASURE the append defect instead of bounding it (the first full
# run averaged ~750ms/append by claim 1400).
CLAIMS_AXIS_SMALL="50 4"
CLAIMS_AXIS_LARGE="800 4"
SUBJECTS_AXIS_SMALL="800 4"
SUBJECTS_AXIS_LARGE="800 400"

# A new empty commit every this-many claims, so commit anchors are
# heterogeneous. A single-commit log makes every ancestry question trivially
# cheap, which hides exactly the plane #181 lived on. Small enough that the
# SMALLEST grid point gets several anchors: at 100 the (50,4) point got
# zero, so the claims axis compared a trivial-ancestry log against a real
# one and conflated 16x claims with 8x commits (cold review of PR #201,
# finding 9). At 10, commit count grows in proportion to claims across the
# axis, so a commit-pair-quadratic cost reads as the claims-quadratic ratio
# it is.
COMMIT_EVERY=10

# Appends timed in passing: the mean of the final n/8 appends (floor 10) at
# each grid size. Final, not first -- the write path at size N, not at size
# 0 -- and PROPORTIONAL, not fixed: a fixed 50 at the (50,4) point averaged
# the entire 0->49 ramp, which calibrates a linear-in-size append to ~32 on
# a 16x axis instead of ~16 (cold review of PR #201, finding 10). With n/8,
# both ends sample near their own size and linear lands near 16 again.
APPEND_SAMPLE_FLOOR=10

# Read ops: min of this many runs. Min is the noise-robust latency statistic
# on a shared runner; a mean smears one scheduler hiccup across the result.
# ADAPTIVE: an op whose first run exceeds SLOW_MS is measured once -- at that
# duration scheduler noise is a rounding error, and repeating a two-minute op
# to shave jitter off it is how a job eats its own timeout. An op that hits
# CAP_S is recorded AT the cap, as a floor: the ratio computed from a floor
# is a lower bound, so the gate trips on it rather than the job dying with
# no table at all.
READ_REPS=3
SLOW_MS=5000
CAP_S=240

# PERF_SMOKE=1 shrinks the grid ~20x for a local plumbing check. The smoke
# grid exists so the script can be verified end-to-end without ten minutes of
# generation; its numbers are NOT comparable to CI's and the gate refuses to
# run on them (the results carry a smoke marker).
if [ -n "${PERF_SMOKE:-}" ]; then
  GRID=("10 2" "40 2" "160 2" "160 8" "160 40")
  CLAIMS_AXIS_SMALL="10 2";  CLAIMS_AXIS_LARGE="160 2"
  SUBJECTS_AXIS_SMALL="160 2"; SUBJECTS_AXIS_LARGE="160 40"
  COMMIT_EVERY=5; APPEND_SAMPLE_FLOOR=5
fi

cmd="${1:?usage: run-perf-grid.sh measure <kan-binary> | gate <results.tsv> <bounds.tsv>}"

# ---------------------------------------------------------------- measure --
measure() {
  KAN_BIN="${1:?usage: run-perf-grid.sh measure <kan-binary>}"
  [ -e "$KAN_BIN" ] && KAN_BIN="$(cd "$(dirname "$KAN_BIN")" && pwd)/$(basename "$KAN_BIN")"
  [ -x "$KAN_BIN" ] || { say "not executable: $KAN_BIN"; exit 1; }

  # Scratch workspaces only, keychain off: the sanctioned combination.
  # KAN_NO_KEYCHAIN outside a temp dir is a data-affecting hazard (kan#146),
  # which is why it is set here, next to the mktemp, and nowhere else.
  export KAN_NO_KEYCHAIN=1
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

  echo -e "op\tclaims\tsubjects\tms"
  [ -n "${PERF_SMOKE:-}" ] && echo -e "#smoke\t0\t0\t0"

  # The trap cleans the CURRENT point's workspace on any failure path; the
  # in-loop rm handles the completed ones. Without it, every failed run
  # leaked a mktemp dir (harmless in CI, litter locally).
  trap '[ -n "${work:-}" ] && rm -rf "$work"' EXIT
  for point in "${GRID[@]}"; do
    read -r n_claims n_subjects <<<"$point"
    work="$(mktemp -d)"
    (
      cd "$work"
      git init -q .
      git -c user.email=perf@example.com -c user.name=perf \
        commit -q --allow-empty -m init

      say "== grid point: $n_claims claims x $n_subjects subjects ($work)"

      # Generation IS the append meter. python drives the subprocesses so the
      # per-call timing does not pay bash's fork overhead as measurement.
      # The writer's stderr is CAPTURED and reported on failure. The first
      # full run died at claim 1431 with the cause thrown away by a DEVNULL
      # -- the exact unactionable "unwritable with no captured reason" the
      # migration cell's writer.log exists to prevent.
      "$PYTHON" - "$KAN_BIN" "$n_claims" "$n_subjects" "$COMMIT_EVERY" "$APPEND_SAMPLE_FLOOR" <<'PYGEN'
import subprocess, sys, time
kan, n, s, every, floor = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
sample = max(floor, n // 8)
times = []
for i in range(n):
    if i and i % every == 0:
        subprocess.run(["git", "-c", "user.email=perf@example.com", "-c", "user.name=perf",
                        "commit", "-q", "--allow-empty", "-m", f"anchor {i}"], check=True)
    t0 = time.perf_counter()
    r = subprocess.run([kan, "observe", f"synthetic claim {i} for the perf grid",
                        "--subject", f"s{i % s}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        print(f"generation failed: observe exited {r.returncode} at claim {i}. "
              f"Its stderr:\n{r.stderr.strip()[-2000:]}", file=sys.stderr)
        sys.exit(1)
    times.append(time.perf_counter() - t0)
mean_ms = sum(times[-sample:]) / len(times[-sample:]) * 1000.0
print(f"append\t{mean_ms:.1f}")
PYGEN

      # Read ops, min of READ_REPS (adaptive; see the knobs above). s0 exists
      # at every grid size (round-robin from 0) and holds ~claims/subjects of
      # the log.
      "$PYTHON" - "$KAN_BIN" "$READ_REPS" "$SLOW_MS" "$CAP_S" <<'PYREAD'
import subprocess, sys, time
kan, reps, slow_ms, cap_s = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
OPS = [
    ("show-subject", [kan, "show", "s0"]),
    ("show-all",     [kan, "show", "--all", "--json"]),
    ("status-all",   [kan, "status"]),
    ("issues",       [kan, "issues"]),
    ("context",      [kan, "context", "--budget", "4000"]),
]
# AN OP THAT FAILS IS A FAILED MEASURE, NOT A MISSING ROW. The first
# version printed the op's name to stderr, emitted no row, and exited 0 --
# and the gate, deriving its op list from the results, then passed green
# with that op's committed bounds unenforced. Silent absence is how this
# instrument gets fooled (cold review of PR #201, blocking finding; same
# class as the tee-swallowed gate exit).
failed = []
for name, argv in OPS:
    best = None
    for i in range(reps):
        t0 = time.perf_counter()
        try:
            r = subprocess.run(argv, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, timeout=cap_s)
        except subprocess.TimeoutExpired:
            # A cap hit is a FLOOR -- but it must not overwrite a real
            # measurement from an earlier rep. Min is the statistic; a
            # completed 100ms run outranks a later hang (finding 5).
            if best is None:
                print(f"{name}: hit the {cap_s:.0f}s cap with no completed rep "
                      f"-- recording the cap as a FLOOR; the true time is larger",
                      file=sys.stderr)
                best = cap_s
            else:
                print(f"{name}: rep {i+1} hit the {cap_s:.0f}s cap; keeping the "
                      f"completed min of {best*1000.0:.1f}ms", file=sys.stderr)
            break
        dt = time.perf_counter() - t0
        if r.returncode != 0:
            print(f"{name}: exited {r.returncode} on rep {i+1}. Its stderr:\n"
                  f"{r.stderr.decode(errors='replace').strip()[-2000:]}",
                  file=sys.stderr)
            best = None
            failed.append(name)
            break
        best = dt if best is None or dt < best else best
        if dt * 1000.0 > slow_ms:
            print(f"{name}: {dt*1000.0:.0f}ms on the first run -- single "
                  f"measurement; jitter is a rounding error at this size",
                  file=sys.stderr)
            break
    if best is not None:
        print(f"{name}\t{best * 1000.0:.1f}")
if failed:
    print(f"measure FAILED: {', '.join(failed)} did not produce a measurement; "
          f"a table with holes must not reach the gate looking complete",
          file=sys.stderr)
    sys.exit(1)
PYREAD
    ) | while IFS=$'\t' read -r op ms; do
      # Subshell stdout carries only the two meters' `op<TAB>ms` lines; stamp
      # the grid point on here, once, instead of threading it through python.
      echo -e "${op}\t${n_claims}\t${n_subjects}\t${ms}"
    done
    rm -rf "$work"
  done
}

# ------------------------------------------------------------------- gate --
gate() {
  results="${1:?usage: run-perf-grid.sh gate <results.tsv> <bounds.tsv>}"
  bounds="${2:?usage: run-perf-grid.sh gate <results.tsv> <bounds.tsv>}"
  "$PYTHON" - "$results" "$bounds" \
    "$CLAIMS_AXIS_SMALL" "$CLAIMS_AXIS_LARGE" \
    "$SUBJECTS_AXIS_SMALL" "$SUBJECTS_AXIS_LARGE" <<'PYGATE'
import sys

results_path, bounds_path = sys.argv[1], sys.argv[2]
axes = {
    "claims":   (tuple(sys.argv[3].split()), tuple(sys.argv[4].split())),
    "subjects": (tuple(sys.argv[5].split()), tuple(sys.argv[6].split())),
}
FLOOR_MS = 100.0  # below this at the large end, a ratio is noise in a costume

t = {}
smoke = False
for line in open(results_path):
    line = line.rstrip("\n")
    if not line or line.startswith("op\t"):
        continue
    if line.startswith("#smoke"):
        smoke = True
        continue
    op, claims, subjects, ms = line.split("\t")
    t[(op, claims, subjects)] = float(ms)
if smoke:
    sys.exit("gate: refusing a smoke-grid results file -- its numbers exist "
             "to check plumbing, not shape, and a bound converted against "
             "them would be a measurement that never happened.")
if not t:
    sys.exit("gate: no measurements in " + results_path)

bound = {}
for lineno, line in enumerate(open(bounds_path), 1):
    if not line.strip() or line.startswith("#"):
        continue
    parts = line.rstrip("\n").split("\t", 3)
    if len(parts) != 4:
        sys.exit(f"gate: bounds line {lineno} has {len(parts)} tab-separated "
                 f"fields, not 4 -- refusing a table it cannot read.")
    op, axis, maxratio, why = parts
    if not (why.startswith("MEASURED") or why.startswith("PREDICTED")):
        sys.exit(f"gate: bound ({op}, {axis}) has a why that opens with "
                 f"neither MEASURED nor PREDICTED -- the confidence token "
                 f"is the contract, not decoration.")
    if (op, axis) in bound:
        sys.exit(f"gate: duplicate bound for ({op}, {axis}) -- last-wins "
                 f"would silently drop one of two committed decisions.")
    bound[(op, axis)] = (float(maxratio), why)

# THE BOUNDS FILE DRIVES THE LOOP, the results only answer it. Deriving the
# op list from the results let a crashed op vanish: no rows, no lookup, no
# enforcement, green (cold review of PR #201, blocking finding). Every
# committed bound must find its measurements or the gate fails; an op in
# the results with no bound still fails from the per-axis check below.
ops = sorted({op for (op, _) in bound} | {op for (op, _, _) in t})
failures, rows, unjudged = [], [], 0
for op in ops:
    for axis, (small, large) in axes.items():
        ts, tl = t.get((op, *small)), t.get((op, *large))
        if ts is None or tl is None:
            failures.append(f"({op}, {axis}): no measurement at the axis "
                            f"endpoints. Either the GRID/axis lists drifted, "
                            f"or the op failed to produce a row -- the measure "
                            f"log says which.")
            continue
        ratio = tl / ts if ts > 0 else float("inf")
        b = bound.get((op, axis))
        if b is None:
            failures.append(f"({op}, {axis}): measured (ratio {ratio:.1f}) but no "
                            f"committed bound. Scaling shape is a decision, "
                            f"never a default -- add the row.")
            continue
        maxratio, why = b
        if tl < FLOOR_MS:
            # Not judged -- but not silently blessed either (finding 3): a
            # sub-floor ratio over its bound is recorded as exactly that.
            verdict = "below-floor" if ratio <= maxratio else "below-floor!"
            if ratio > maxratio:
                unjudged += 1
        elif ratio <= maxratio:
            verdict = "ok"
        else:
            verdict = "EXCEEDED"
            failures.append(f"({op}, {axis}): ratio {ratio:.1f} exceeds bound "
                            f"{maxratio:.0f}. Committed reason: {why}")
        rows.append((op, axis, f"{ts:.1f}", f"{tl:.1f}", f"{ratio:.1f}",
                     f"{maxratio:.0f}", verdict))

hdr = ("op", "axis", "small ms", "large ms", "ratio", "bound", "verdict")
w = [max(len(r[i]) for r in rows + [hdr]) for i in range(len(hdr))]
for r in [hdr] + [tuple(x) for x in rows]:
    print("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))

if failures:
    print()
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
if unjudged:
    print(f"\nscaling gate: no gated ratio exceeded its bound; {unjudged} "
          f"below-floor row(s) exceed theirs at sub-{FLOOR_MS:.0f}ms times "
          f"(marked '!', recorded, not judged)")
else:
    print("\nscaling gate: no gated ratio exceeded its bound")
PYGATE
}

PYTHON="${PYTHON:-python3}"

case "$cmd" in
  measure) shift; measure "$@" ;;
  gate)    shift; gate "$@" ;;
  *) say "unknown command: $cmd"; exit 1 ;;
esac
