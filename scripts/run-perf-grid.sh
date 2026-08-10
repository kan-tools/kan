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
# subprocesses next to a 72ms bulk read; the decade between linear and
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
# cheap, which hides exactly the plane #181 lived on.
COMMIT_EVERY=100

# Appends timed in passing: the mean of the final this-many appends at each
# grid size. Final, not first -- the write path at size N, not at size 0.
APPEND_SAMPLE=50

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
  COMMIT_EVERY=20; APPEND_SAMPLE=10
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
      "$PYTHON" - "$KAN_BIN" "$n_claims" "$n_subjects" "$COMMIT_EVERY" "$APPEND_SAMPLE" <<'PYGEN'
import subprocess, sys, time
kan, n, s, every, sample = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
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
for name, argv in OPS:
    best = None
    for i in range(reps):
        t0 = time.perf_counter()
        try:
            r = subprocess.run(argv, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=cap_s)
        except subprocess.TimeoutExpired:
            print(f"{name}: hit the {cap_s:.0f}s cap -- recording the cap as a "
                  f"FLOOR; the true time is larger", file=sys.stderr)
            best = cap_s
            break
        dt = time.perf_counter() - t0
        if r.returncode != 0:
            print(f"{name}\tFAILED", file=sys.stderr); best = None; break
        best = dt if best is None or dt < best else best
        if dt * 1000.0 > slow_ms:
            print(f"{name}: {dt*1000.0:.0f}ms on the first run -- single "
                  f"measurement; jitter is a rounding error at this size",
                  file=sys.stderr)
            break
    if best is not None:
        print(f"{name}\t{best * 1000.0:.1f}")
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
for line in open(bounds_path):
    if not line.strip() or line.startswith("#"):
        continue
    op, axis, maxratio, why = line.rstrip("\n").split("\t", 3)
    if not (why.startswith("MEASURED") or why.startswith("PREDICTED")):
        sys.exit(f"gate: bound ({op}, {axis}) has a why that opens with "
                 f"neither MEASURED nor PREDICTED -- the confidence token "
                 f"is the contract, not decoration.")
    bound[(op, axis)] = (float(maxratio), why)

ops = sorted({op for (op, _, _) in t})
failures, rows = [], []
for op in ops:
    for axis, (small, large) in axes.items():
        ts, tl = t.get((op, *small)), t.get((op, *large))
        if ts is None or tl is None:
            failures.append(f"({op}, {axis}): grid points missing from results "
                            f"-- the axis list and the GRID list have drifted.")
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
            verdict = "below-floor"
        elif ratio <= maxratio:
            verdict = "ok"
        else:
            verdict = "EXCEEDED"
            failures.append(f"({op}, {axis}): ratio {ratio:.1f} exceeds bound "
                            f"{maxratio:.0f}. {why.split('.')[0]}.")
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
print("\nscaling gate: all bounded ratios within bounds")
PYGATE
}

PYTHON="${PYTHON:-python3}"

case "$cmd" in
  measure) shift; measure "$@" ;;
  gate)    shift; gate "$@" ;;
  *) say "unknown command: $cmd"; exit 1 ;;
esac
