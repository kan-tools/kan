# Capture latency review evidence

Initial review: actual Claude Code `claude-opus-5-5`, session
`f36a9a21-8b0e-4b9b-a6e2-0084c33c19fc`, range
`eedbc2f88e7ab2ff52ddc0c495cd99929d0fa332..b6427c31fd0dc412c0f4b170006eb58d46505de7`.
Final text SHA-256: `fde1cbc2c1ad7e07a1fa1fdc37c4969fbecc7ad63b0e6ee5f35aad250ae57959`.
The REDIRECT was accepted; its correction requires a fresh review.

**Hard verdict: REDIRECT.**

The latency correction does what it claims: with b6427c3 a locked spool no longer costs 5 s per observation, and all 45 claimed tests pass. But the way it bounds latency (zero SQLite wait, including at open, plus a lifetime latch on the sink) throws away most or all of an attempt's evidence under ordinary contention. Before this change, that same contention cost milliseconds and almost nothing was lost. Gaps stay visible and nothing unconfirmed is acknowledged, so I don't call it an invariant breach (BLOCK). But it trades away the slice's own goal (`telos/raw-data-and-projections`: raw data retained in full) for latency. The parent plan (`.design/kan-v2-buildout.md:362`) asked for *bounded* admission latency; this delivers *zero*. Separately, REQ-3's CI requirement isn't met. Any fix round needs its own cold review.

I'm independent: I didn't author this code. Live kan/day was not read or written, as instructed, so I recorded no verdict claim. The north star above comes from your stated purpose and the design summary. The partial claim view (two withheld claims) is a limitation of this review, not evidence that no teloi apply.

## Process incident (my error)
- **What happened:** your shell exports `CARGO_TARGET_DIR=…/kan-v2-capture-latency/target`. My first `cargo clean -p kan` deleted the author's `kan` artifacts (45 files, 225.8 MiB), and one no-run build wrote `kan` artifacts from my identical HEAD export into that target.
- **What was not touched:** author source, Git state and dependency artifacts. Afterwards I removed only my own stray artifacts (51 files). The author's next build will recompile `kan`.
- **After that:** every command set `CARGO_TARGET_DIR` explicitly to the scratch clone.

## Findings
1. **High: concurrent capture opens fail outright.** In probe P5, `Spool::open_for_capture` failed 25 of 80 times with "spool storage unavailable" when two connections simply opened together. Normal `open` failed 0 of 80. P6 traced the failure to the first read (`PRAGMA application_id`): the first opener of a WAL database has to set up the shared index, and a concurrent opener with zero wait gets `database is locked`. The CLI then sets `spool = None` (`src/bin/kan-v2.rs:247`), so the whole attempt is a gap. Every `capture-post` is a new process, so two inferences starting together hit this. In P3 (two concurrent captures), one capture recorded **0 of 66** observations.
2. **High: the latch turns brief contention into near-total loss.** In P4, another writer held the lock for 5 ms every 50 ms (about 9% of the time, roughly a drain acknowledging replies):

   | Variant | Recorded |
   |---|---|
   | Shipped | **4/86** |
   | Without the latch | 66/87 |
   | Pre-fix (5 s wait) | 87/87 |
   | 100 ms wait, no latch | 88/88 |

   The latch is at `src/evidence_capture.rs:80-84`. The design doesn't explain why a latch was chosen over a short bounded wait.
3. **Medium: REQ-3 isn't met in CI.** `tests/evidence_capture_deadlines.rs` only compiles with `v2-crypto`. ci.yml line 32 doesn't list it, and running it without the feature gives "running 0 tests". The file's header "now compiled into CI" is only true of clippy/check. The `no-zero-guard` mutant is killed **only** by this file, so in CI it survives.
4. **Medium: two REQ-1 properties have no shipped test.** The `cli-normal-open`, `capture-open-waits` and `no-restore` mutants all survive the shipped suite. Under WAL, a `BEGIN IMMEDIATE` holder doesn't block readers, so the existing tests can't tell the two opens apart. My P1 (exclusive-mode lock) and P2 (timeout restored after the sink) kill them.
5. **Low:**
   - AC-2's "without rewriting retained evidence" is never exercised: nothing is pending when the fresh sink queues.
   - These come from reading the code, not from running it:
     - A flush that blocks past the budget still reports completed, because there is no later wait (`src/evidence_capture.rs:343`).
     - If restoring the timeout fails after a commit, that queued frame is reported unconfirmed (conservative).
     - A panic inside `without_busy_wait` leaves the timeout at zero.

## REQ/AC coverage
| Item | Verdict | Evidence |
|---|---|---|
| REQ-1 | partial | Zero wait works (P1: 0.49 s vs 5.8 s pre-fix). FULL sync untouched (`src/evidence_spool.rs:161-172`), and success is only reported after commit. But the zero-wait open causes finding 1, and open/restore have no shipped test (finding 4). |
| REQ-2 | met as written, harmful | Latch verified (`no-latch` mutant killed), nothing deleted. Causes finding 2. |
| REQ-3 | partial | Tests pass locally (5/5) and help text is present. Not run in CI (finding 3). |
| AC-1 | met locally | CLI test passes within 3 s. Full-fix reversion fails it (`Elapsed`). |
| AC-2 | partial | Latch and recovery verified; "retained evidence" not exercised. |
| AC-3 | met locally, unmet in CI | `not-cumulative` mutant killed by 4 tests; `no-zero-guard` only by the deadlines file. |

**Scope narrowing:** "Async storage workers" and "physical disk latency bounds" are listed as out of scope up front, which is fair. Narrowing "bounded" to "zero wait + latch" is suspicious: it skips the hard part (a short wait that still records everything) without saying why.

**Forbidden patterns:** none found. Nothing is destroyed, there's no new persistence path (surface conformance 19/19 passes), and the no-retry and no-redirect settings are unchanged.

## Verification and mutants (scratch export of b6427c3)
- **Author's 45 tests:** confirmed (capture 17, adversarial 13, deadlines 5, spool 10), plus delivery 5/5.
- **All CI v2-crypto targets (ci.yml line 32):** 170/170 across 16 targets, plus the spool lib test.
- **Lint and format:** fmt check, clippy with `v2-crypto` and clippy on the workspace all clean.
- **Full-fix reversion:** the two named tests fail as the author claimed, and pass again once restored.
- **Mutants killed by the shipped suite:** `no-latch`, `admit-waits`, `no-zero-guard`, `not-cumulative`.
- **Mutants that survive it:** `no-restore`, `cli-normal-open`, `capture-open-waits`. P2 kills `no-restore` and P1 kills `cli-normal-open`.
- I did not run `capture_negative_controls.py`, Lean, Docker or any external calls.

## Suggested direction for the fix round
- Use a short, cumulatively capped wait for both open and admission.
- Latch only on failures other than lock contention, or once that cap is spent.
- Add `--test evidence_capture_deadlines` to ci.yml line 32.
- Promote P1, P2, P4 and P5 into the suite.

## Cleanup
The scratch target is removed and the author's stray `kan` artifacts are gone. The checkout is clean at b6427c3 and no processes are left running; 17 GiB free. Everything is in `/tmp/kan-latency-review-2XiE`:
- `src/`: the exported source
- `probes/`: `review_latency_probes.rs`, `mutate.py`, `probe_variants.py`
- `logs/`: 48 logs

## Correction prepared

The correction uses 100 ms capture-open waits and a scoped busy callback with
a one-second allowance per Recorder, counting actual sleep only. It keeps
attempting immediate admission after exhaustion and never latches off capture.
It retains P1–P5 as compiled tests, adds budget-exhaustion/recovery and final-flush
regressions, restores the caller timeout and thread-local state on unwind, and
wires contention/deadline tests into feature-enabled CI. No production format
or persistence-medium changes. The fresh correction verdict is APPROVE WITH FOLLOW-UPS; see [the retained report](kan-v2-capture-latency-correction-2026-10-18.md).
