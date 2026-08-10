# perf-instrument — key-op latency and its scaling, measured in CI

**Status:** designed 2026-08-10, serving `telos/performance-at-scale`
(witnesses: `perf-grid-report`, `scaling-gate-run`). Tension with
`telos/raw-data-and-projections` is recorded
(`tension/performance-at-scale--raw-data-and-projections`): performance work
must speed up recomputation or cache outside the store, never persist a
projection as data.

## Why

Performance defects here have been *scaling* defects, not constant-factor
ones. kan#181: `kan show <subject>` spent 141 s spawning 8,540 git
subprocesses — O(n²) in commit-anchored claim pairs — on a log where
`show --all --json` took 72 ms. Nothing in CI could have seen it: the suite's
logs are tiny, and a green suite says nothing about shape. The instrument
this doc designs makes the *shape* a measured, gated fact and the raw
timings a retained record.

## What is measured

One grid of synthetic workspaces, **expanded in the script** (the list is
the contract; changing it is a reviewed edit, not a knob):

| claims | subjects | axis role |
|-------:|---------:|-----------|
|    125 |       10 | claims axis, small |
|    500 |       10 | claims axis, mid |
|  2,000 |       10 | claims axis, large / subjects axis, small |
|  2,000 |      100 | subjects axis, mid |
|  2,000 |    1,000 | subjects axis, large |

Absolute sizes are chosen so the whole grid generates in ~10 CI minutes;
the gate consumes only the 16×/100× *ratios*, which hold regardless of the
absolutes. (The first smoke run measured `status-all` superlinear enough
that a 4,000-claim large end risked eating the job's own timeout — the
instrument found its first finding while being built.)

Claims axis: 16× claims at fixed subjects. Subjects axis: 100× subjects at
fixed claims. Each workspace is generated fresh by driving the release
binary (`observe`, subjects cycled round-robin), with a new empty git commit
every 100 claims so commit anchors are heterogeneous — a single-commit log
would make ancestry trivially cheap and hide exactly the #181 plane.

Key ops metered per grid point, wall-clock ms:

- `append` — mean per-`observe` latency over the final 50 appends of
  generation (the write path at that log size; no separate pass)
- `show-subject` — `kan show s0` (the #181 op; s0 holds ~claims/subjects
  of the log)
- `show-all` — `kan show --all --json` (the bulk read every session opens
  with)
- `status-all` — `kan status` with no subject (fold + summary per subject)
- `issues` — `kan issues`
- `context` — `kan context --budget 4000` (budgeted assembly)

Read ops are min-of-3 (min is the noise-robust statistic for latency on a
shared runner), adaptively: an op whose first run exceeds 5 s is measured
once — jitter is a rounding error at that size, and repeating a two-minute
op is how a job eats its own timeout. An op that hits the 240 s cap is
recorded *at* the cap as a floor, so the gate trips on the lower bound
rather than the job dying with no table. Append is a mean because it is
measured in passing.

## What is gated, and what is only recorded

**The gate is a growth-ratio bound per (op, axis), committed in
`tests/fixtures/perf-bounds.tsv`** with the same MEASURED/PREDICTED
confidence discipline as `migration-expectations.tsv`: bounds ship
PREDICTED, the first run converts them to MEASURED-informed values with the
run id, and a bound whose measurement contradicts it is corrected by a
human, in a commit, with the reason in the `why` column.

- ratio(claims) = t(2000,10) / t(125,10) — linear ≈ 16, quadratic ≈ 256
- ratio(subjects) = t(2000,1000) / t(2000,10) — linear ≈ 100, quadratic ≈ 10,000

Absolute times are **reported, never gated**: hosted-runner wall-clock
varies ±30% run to run, and a flaky red teaches people to re-run until
green, which is worse than no gate. The decade between linear and quadratic
is far wider than runner noise, which is what makes the ratio gateable at
all.

**Noise floor:** an op is gated only when its large-end time is ≥ 100 ms.
A 3 ms / 1 ms ratio is measurement noise wearing a ratio's clothes; such
rows are recorded in the report and marked `below-floor`, never judged.

**The full raw table is the artifact** (`perf-grid-report`): printed to the
job log, written to the step summary, uploaded. The gate is a projection
computed over it — raw data retained, simplification computed on demand,
which is the telos this instrument serves and the tension it lives inside.

## Where it runs

`.github/workflows/perf.yml`, ubuntu-latest only: PRs touching
`src/**`, `Cargo.toml`, `Cargo.lock`, the script, the bounds file, or the
workflow; every tag push; manual dispatch. One platform because the gate is
about shape, not speed — a ratio is comparable on any runner, and the
matrix already owns the platform axis for correctness.

Environment: `KAN_NO_KEYCHAIN=1`, scratch `mktemp` workspaces only — the
sanctioned combination (kan#146's history is why this is stated rather than
assumed). The v0.12+ writer roots in a plaintext `.kan/seed` on its own;
no identity file is named, so REQ-2 has nothing to refuse.

## Out of scope, deliberately

- **Cold-index reads** (delete the SQLite index, time the rebuild): a real
  plane, but it needs a decision about which on-disk artifact is "the
  index" that survives refactors. Follow-up, not v1.
- **Constant-factor regression gating**: absolute-time baselines with
  tolerances are the flaky-red generator the matrix's own history warns
  about. If a constant-factor cliff ships, the reported table is where a
  human sees it.
- **Cross-version comparison** (this build vs the released binary): the
  migration matrix owns cross-version questions.
- **macOS/Windows timing**: shape is platform-independent until proven
  otherwise; one runner keeps the instrument cheap enough to run on every
  relevant PR.
