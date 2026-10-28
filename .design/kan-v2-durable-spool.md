# Feature: Durable exact-request spool

## Summary

Provide a bounded, process-safe local queue for encrypted signed append requests. Both capture and migration must durably preserve original request bytes before attempting remote delivery, then retry those same bytes after uncertain network results. This is a queue primitive, not the forwarding adapter or migration completion claim.

## Requirements

- REQ-1: Bind each explicitly created spool to one scope, writer and destination audience. Admit only valid signed append requests extending its exact manifest chain; preserve original bytes.
- REQ-2: Serialize concurrent enqueue and acknowledgment, use durable SQLite transactions, and enforce a configured total pending-byte budget. Full or unavailable storage returns an explicit error for the capture adapter's visible-gap policy.
- REQ-3: Remove pending bytes only after a signed destination reply proves the exact expected manifest and matching receipt. Network failures and ambiguous delivery never advance acknowledgment or regenerate ciphertext.
- REQ-4: Reopen validates the queue and its frontier, refuses foreign schema or malformed bytes, and does not auto-create or overwrite existing state. Bound per-record reads and retain the last accepted signed acknowledgment for audit.
- REQ-5: Keep payloads opaque and credentials external; all persistence surfaces are inventoried. Do not claim that queue success proves remote durability, full capture, backup, migration completeness or secure erasure.

## Acceptance Criteria

- [ ] AC-1: Enqueue/restart/retry returns exact original bytes; wrong scope/writer/audience, altered signatures, reused operation and broken chain are refused. (REQ-1, REQ-4)
- [ ] AC-2: A full queue rejects admission without frontier advance; concurrent producers cannot fork the frontier; crash before/after publication preserves a whole old or new state. (REQ-2)
- [ ] AC-3: Real Service replies dequeue only the matching head; forged, wrong-request, failure and out-of-order replies preserve the queue. After simulated lost acknowledgment, retry returns the original receipt and drains once. (REQ-3)
- [ ] AC-4: Independent SQLite inspection agrees on exact signed bytes, no plaintext canary appears, malformed queue/schema refuses reopen, and the surface catalog describes every mutation. (REQ-4, REQ-5)

## Architecture

`src/evidence_spool.rs` will use the existing `src/persistence.rs` mutation boundary and `src/evidence_service.rs` signed request/reply contract. Caller-selected existing parent directories only; no home discovery, key creation or live traffic. One standalone SQLite file holds immutable queued request blobs and mutable queue/frontier metadata. No receipt with a remote-durable claim is manufactured locally. The only durable remote acknowledgment is the destination's verified signed reply.

The transaction checks total queued bytes, canonical request signature and exact chain coordinates before insertion. The first position is zero; a new spool cannot silently adopt an existing remote writer. Acknowledgment deletes only the oldest pending request, retains the exact signed reply and its manifest CID, and preserves the enqueue frontier even when empty. This means recreating or losing the spool requires an explicit writer recovery/new writer procedure, not guessing position zero.

WAL with synchronous FULL and an immediate transaction provides serialized publication. SQLite logical deletion is not secure erasure; ciphertext may remain in freelists/WAL/backups. Queue byte limits apply to pending payload bytes, not a promise about total filesystem allocation. Startup validates schema, lengths, canonical signatures and pending chain; large queues have bounded per-record memory but linear audit time. Keys and plaintext never enter this module. Grants and sender identities are deliberately separate from encryption recipients.

## Open Questions

Production owner custody, capture adapter selection and independent backup qualification remain open. This primitive cannot resolve loss of its frontier or revoke a captured append credential. The existing day partial-trust limitation still requires later record backfill.

## Out of Scope

- Production gateway forwarding, automatic migration/cutover, grants history, erasure, or claiming this primitive completes P5/P6.

## Reviewed operation-history correction

The initial queue forgot operation identifiers when an acknowledgment deleted a pending row. That allowed a reused identifier to enter the queue even though the remote ledger would permanently reject it. The corrected experimental spool profile 2 retains a compact `operations` registry (position, identifier, manifest CID) for every enqueue and audits it against pending rows, the latest acknowledgment and the frontier. Identifier history is not charged to the pending-payload budget, so local metadata grows with lifetime operations. Startup is linear in that history; no bounded-startup claim is made.

Enqueue returns distinct `Queued`, `AlreadyPending` and `AlreadyAcknowledged` outcomes. Any changed commitment under an existing identifier is a conflict, including after acknowledgment and restart. The profile change refuses earlier experimental spool files instead of silently upgrading or resetting them; no live spools have been deployed by this work.

SQLite disk-full maps to `Full`; busy, locked, I/O and related unavailable-storage failures map to `Unavailable`. Initialization sets FULL synchronization/fullfsync before its schema transaction. This is not a power-loss qualification. The queue is owner-trusted local state: coherent raw edits or rollback of the file and its operation registry can drop unacknowledged bytes without detection. Durable external rollback witnesses and explicit recovery of permanently rejected heads remain future operating concerns.
