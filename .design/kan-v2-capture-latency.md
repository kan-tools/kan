# Feature: Capture admission with short bounded SQLite waits

## Summary
Continue P6 from the reviewed body forwarder. Stop SQLite lock contention from imposing seconds of delay per observation; retain truthful gaps and durable queued evidence. This serves telos/raw-data-and-projections and the user's fail-open decision. The legacy claim view remains partial, with claim/bridge backfill pending.

## Requirements
- REQ-1: Capture-specific spool open uses a 100 ms SQLite busy timeout; admission uses at most 100 ms and a one-second busy-wait allowance per Recorder; normal offline queue/drain keep their existing policy. Never weaken FULL durability or acknowledge an unconfirmed write.
- REQ-2: An unconfirmed encrypted admission reports a gap but must not disable subsequent capture. Brief contention and simultaneous opens should recover; preserve pending bytes and writer coordinates.
- REQ-3: Retain cumulative provider-body read and zero-remaining I/O budget regressions in CI, and explain the budget in CLI help.

## Acceptance Criteria
- [x] AC-1: With a real SQLite writer lock, a multi-observation CLI request finishes within three seconds, returns exact provider bytes once, and reports completed with gaps. Normal open still works and existing spool tests pass. (REQ-1, REQ-2)
- [x] AC-2: The same sink successfully queues after unlocking without rewriting retained evidence; simultaneous opens and brief periodic writer contention retain capture. (REQ-1, REQ-2)
- [x] AC-3: Slow cumulative provider reads expire, ample-budget reads complete, and a synchronous output overrun cannot be called complete at the next wait. Help describes cumulative awaited I/O. (REQ-3)

## Architecture
`src/evidence_spool.rs` gains capture-only open using 100 ms busy timeout from the first connection operation, and a crate-local scoped admission helper restoring the original timeout. `src/evidence_capture.rs` uses that helper and retains its spool reference after unconfirmed admissions. `src/bin/kan-v2.rs` selects capture open. No persistent format changes: `src/persistence.rs` and `tests/fixtures/read-write-surface.tsv` remain the mutation boundary. Tests promote selected retained reviewer probes and exercise real contention. This bounds SQLite lock-wait policy, not filesystem latency, fsync, full startup audit, cryptography, user callbacks or blocked stderr. It is not a hard wall-clock guarantee. Each Recorder starts with a one-second admission allowance. Actual busy-handler sleep debits it; the next observation gets at most min(100 ms, remaining allowance) across all SQLite statements in that admission. Once spent, immediate admission continues, so healthy evidence is not suppressed. A scoped thread-local busy handler shares the allowance across statements, and restores caller policy even on unwind. OS scheduling can overrun a sleep; this is a busy-wait policy, not a hard real-time deadline. Healthy cryptography and fsync do not consume the wait allowance. Open/audit is separate. Each observation uses a distinct operation; neither inference nor an ambiguous operation is retried.

## Open Questions
None for this correction. Authenticated transport and selected real harness follow in child branches. Legacy design-record and bridge backfill remain pending under the documented partial-trust bug; no wrong-HEAD claims or invented witnesses.

## Out of Scope
Async storage workers, physical disk latency bounds, bounded health reporting, new persistence media, remote transport, production deployment, live migration and main merge.


## Review correction
Initial b6427c3 received REDIRECT: zero-wait WAL opens failed under simultaneous
opens, and a lifetime latch amplified brief contention into near-total loss.
The correction replaces both policies, retains the reviewer P1–P5 probes with
assertions for periodic contention/concurrent opens, and wires both deadline
and contention targets into feature-enabled CI. A fresh cold review and whole
production-fix reversion witness are required.
