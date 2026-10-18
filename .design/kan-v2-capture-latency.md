# Feature: Capture admission without SQLite contention waits

## Summary
Continue P6 from the reviewed body forwarder. Stop SQLite lock contention from imposing seconds of delay per observation; retain truthful gaps and durable queued evidence. This serves telos/raw-data-and-projections and the user's fail-open decision. The legacy claim view remains partial, with claim/bridge backfill pending.

## Requirements
- REQ-1: Capture-specific spool open and admission use zero SQLite busy timeout; normal offline queue/drain keep their existing policy. Never weaken FULL durability or acknowledge an unconfirmed write.
- REQ-2: After an encrypted capture sink's first unconfirmed admission, suspend further admissions for that sink's lifetime. All subsequent observations remain explicit unconfirmed gaps. A fresh sink on a later attempt may recover; preserve pending bytes and writer coordinates.
- REQ-3: Retain cumulative provider-body read and zero-remaining I/O budget regressions in CI, and explain the budget in CLI help.

## Acceptance Criteria
- [x] AC-1: With a real SQLite writer lock, a multi-observation CLI request finishes within three seconds, returns exact provider bytes once, and reports completed with gaps. Normal open still works and existing spool tests pass. (REQ-1, REQ-2)
- [x] AC-2: A failed encrypted admission latches even after unlocking; a new sink successfully queues afterward without rewriting retained evidence. (REQ-1, REQ-2)
- [x] AC-3: Slow cumulative provider reads expire, ample-budget reads complete, and a synchronous output overrun cannot be called complete at the next wait. Help describes cumulative awaited I/O. (REQ-3)

## Architecture
`src/evidence_spool.rs` gains capture-only open using zero busy timeout from the first connection operation, and a crate-local scoped no-wait admission helper restoring the original timeout. `src/evidence_capture.rs` uses that helper and removes its optional spool reference on any admission failure. `src/bin/kan-v2.rs` selects capture open. No persistent format changes: `src/persistence.rs` and `tests/fixtures/read-write-surface.tsv` remain the mutation boundary. Tests promote selected retained reviewer probes and exercise real contention. This bounds SQLite lock-wait policy, not filesystem latency, fsync, full startup audit, cryptography, user callbacks or blocked stderr. It is not a hard wall-clock guarantee. Recovery is explicit per new sink, never a retry of inference or an ambiguous operation.

## Open Questions
None for this correction. Authenticated transport and selected real harness follow in child branches. Legacy design-record and bridge backfill remain pending under the documented partial-trust bug; no wrong-HEAD claims or invented witnesses.

## Out of Scope
Async storage workers, physical disk latency bounds, bounded health reporting, new persistence media, remote transport, production deployment, live migration and main merge.
