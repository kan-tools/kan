# Cold adversarial review: kan v2 health coalescing child slice

Reviewer: Claude Opus 5.5 (claude-opus-5-5), fresh context. I wrote none of this code.
Range: `git diff HEAD` of the isolated export (HEAD b452aec = parent checkpoint 96c67f7).
Design: `.design/kan-v2-operations-polish.md`, section "Build checkpoint: cumulative health coalescing".
North star (from the user; no live kan store in this export, and I did not run kan/day): raw evidence and provenance, and honest coverage.
Not recorded in kan (`day review record` / `kan observe` not run): kan/day writes are forbidden here.

## Verdict: APPROVE WITH FOLLOW-UPS

See the "Findings" and "Unrun" sections below. All raw logs are in this directory.

## What I ran (my own runs, all in this export with its own COW target; jobs=4, debug=0, incremental=0)

| Check | Result | Log |
|---|---|---|
| `cargo build --features v2-crypto --all-targets` | ok | 01 |
| `--test evidence_operations` | 18/18 | 02 |
| `--lib evidence_operations::tests` | 3/3 | 03 |
| capture, capture_adversarial, capture_deadlines, capture_contention, gateway, surface_conformance | 18, 13, 6, 6, 17 (+1 ignored: needs `KAN_CLAUDE_BIN`), 19 | 04 |
| `--lib evidence_gateway::admission_tests` | 1/1 | 05 |
| clippy v2-crypto `-D warnings` / clippy workspace / `fmt --check` | ok / ok / ok | 06, 09, 07 |
| `node --test operations_ui + theme_ui` | 11/11 | 08 |

## Reversion (done by hand, not through the author's adapter)

The reverted tree is HEAD production code for `evidence_capture.rs` and `evidence_operations.rs`, with the current `#[cfg(test)] mod tests` kept. That adds only the 88-line burst test (diff vs HEAD).

- Burst test: FAILED on an assertion. Expected `(1002,1001,1)`, got `(257,256,1)`. The barrier assertion had already passed.
- Persisted-terminal test: FAILED at `tests/evidence_operations.rs:864` (the `outcome=None` regression was accepted).
- After restoring, all hashes matched and both tests passed (log 14).
- `app.js` whole-file reversion: the named Node test fails at the history-line assertion. After restoring it passes (logs 40, 41).
- `app.js` badge-only mutant: also killed (`'idle'` vs `'Stale · idle'`), so the badge assertion is independent of the history assertion (log 42).

Adapter audit: the TAP regex `(not ok|ok) \d+ - (.+)` with `fullmatch` and the exact-name comparison match Node 24's real top-level output. A SKIP or TODO suffix, an empty selection, or a syntax error gives no match, which reports NO-SUCH-TEST, so the parsing is conservative. Phases 1, 2 and 3 are baseline, reverted and restored, in that order.

## Mutants (every one compiled; production bytes restored and hash-checked after each)

Logs 30 to 34, summaries 31 and 33.

| Mutant | Killed by |
|---|---|
| M1: `finish` ignores revision | burst |
| M2: Full wake counted as a loss | burst |
| M3: try_lock contention not counted | **only probabilistic**: lazy_reporter test fails 6 of 8 runs |
| M4: no status retention | persisted-terminal |
| M5: no outcome retention | burst + persisted-terminal |
| M6: no observer check | persisted-terminal |
| M7: unbounded pending map | locked_journal pressure test |
| M8: pending map skips dominance | burst |
| M9: `record` skips dominance | journal_reopen + persisted-terminal |
| Parent D: regressed `next` | worker_refuses_history_outside_current_queue_lineage ("regressed-frontier") |
| Parent I: same `next`, different `previous` | same test ("different-head") |
| Parent F: ack beyond frontier | same test ("unacknowledged-position") |
| Parent UI m5: reporter future-clock guard | new Node test 7 |
| Removing the new history line | new Node test 7 |

The parent's survivors D, I, F and m5 are now killed by the promoted tests. I checked this myself; it was not checked by the earlier reviewer.

There were no `DatabaseBusy`/locked panics in any of my 15 full `evidence_operations` suite runs.

## Probes

Temporary `tests/zz_review_probe.rs`, since removed; source in `probes/`.

- **Backward compatibility:** a journal written by parent production code was opened by current code. A dominating update was accepted; status contradiction and terminal regression were refused; aggregates were exact (logs 12, 15).
- **Honesty invariant:** "final state persisted, or a loss is counted" held in every probe run (30 last-state rounds, all contention runs). I saw no silent loss.
- **Contention:** instrumented counters (log 21) attribute 100% of losses with a healthy journal to `try_lock` failure. There were zero record failures and zero dominance rejections.

Terminal-summary loss with a healthy journal:

| Setup | Terminals lost | Offers dropped | Log |
|---|---|---|---|
| 1 tight caller | up to 7/40 | 356 | 21 |
| 2 tight callers | 78/80 | — | 21 |
| 8 callers, 1 ms `sleep` spacing (OS-aligned wakeups) | 38–56/80 | ~55% | 22, 23 |
| 2 callers, 1 ms `sleep` spacing | 4/20 | — | 23 |
| Unsynchronised jittered spin spacing | 0 | 0–1.5% | 24 |

For comparison, the parent FIFO under the same tight load lost 310 of 320 attempts entirely (log 13). The slice is a strong net improvement.

## Findings

1. **Medium: healthy-system contention loss.**
   - Location: `src/evidence_operations.rs:412` (`pending.try_lock()`), together with the wake at `:418`. The wake makes the writer take the lock (`:385-388`) right after a caller's offer, which is exactly when a bursting caller makes its next offer.
   - Effect: with a healthy journal, concurrent or bursting callers lose terminal summaries (counted, never silent). "capture updates lost" also becomes nonzero noise during normal operation.
   - This is declared in the design ("contention … remain counted handoff losses"), but its magnitude is not.
   - Suggested follow-up: a blocking `lock()` on the I/O-free critical section, or a bounded retry; or count superseded and terminal losses separately.
2. **Medium: no deterministic regression for contention-loss accounting.** M3 (contention silently uncounted) is killed only by chance (6 of 8 runs) by a test written for another purpose. One of the slice's stated guarantees has no mandatory test.
3. **Low: the burst barrier can be established by the wrong write.** If the test thread stalls for more than 500 ms after spawning the reporter, `BLOCKED` can be set by the timeout-path `session()` write instead of `record(rev1)`. The test would still pass, but the "older revision in flight" condition would not be exercised.
4. **Low: unsampled sessions are labelled as lacking a heartbeat.** `app.js:36` puts `unseen` (sessions outside the 100-row sample) under "without a current heartbeat", but they are unsampled, not known to be stale. The notice wording ("no recent sampled heartbeat") is the accurate one.
5. **Low: the counter label now means summaries.** `telemetry_dropped` now counts lost pending summaries (one per failed revision), not individual updates, but the UI label still reads "capture updates lost". It is conservative in direction, but the unit changed silently.
6. **Low: the adapter's trailer can't be re-checked.** Its trailer names `node::future_clock_badge`, which the bundled `revert-demo.py --verify` cannot re-derive: it would try `cargo test --test node` and report NO-SUCH-TEST. No CI uses `--verify` today.

The following hold, from code reading plus tests:

- Raw capture and spool bytes are unaffected. The `evidence_capture.rs` diff only adds a derive; `Header` and frames are untouched.
- Schema and snapshot shape are unchanged.
- The callback does no I/O and never blocks.
- Revision-checked completion is correct.
- I found no lost wakeup. A Full channel implies a wake queued after the offer, and the 500 ms timeout is a backstop.
- The disconnect drain is correct: buffered wakes come before Disconnected, and the final batch runs before the clean-close write.

## Scope-narrowing, judged

These are legitimate, named before implementation, and separable:

- capacity/reserve and rotation
- stable reporter source identity
- exhausted-journal counter certainty and whole-device failure

The removed pressure-test assertion (`unconfirmed == 1`) is legitimate: its survivor depended on scheduling, and lock → release → persist is now covered deterministically by the burst test.

## Unrun / remaining

- Linux CI and the global-cap negative control: not run by me.
- Full `cargo test --workspace` and the remaining v2 integration targets: not run. Those are delivery, crypto, import, restore, migration, recovery, store, service, spool, http and contract, plus the other lib unit modules.
- The ignored real-provider gateway test.
- Any browser or real-device UI run. The UI was exercised only via the vm harness.
- The kan/day telos read and record. No live store; writes are forbidden.
- Contention under a real tokio gateway load: my probes used synthetic threads.
