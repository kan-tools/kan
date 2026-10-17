# Feature: Encrypted queue delivery and recovery commands

## Summary

Connect the reviewed recipient encryption, signed service and durable spool into a usable caller API and CLI. Input becomes an encrypted, signed request in the local queue before any network send. Delivery retries only retained bytes and releases them only against the pinned destination's proof. This advances P4–P6 without claiming a provider proxy or complete migration.

## Requirements

- REQ-1: Queue bounded raw input under an explicit recipient, existing signing key and caller-supplied operation identifier. Derive scope, audience and frontier from the selected spool; reject the wrong writer and reused identifiers, including after acknowledgment.
- REQ-2: Separate queue admission from delivery. Queue success means local durability only. Send exact retained bytes, verify the configured destination, and preserve the head on network failure, signed rejection or ambiguous acknowledgment.
- REQ-3: Provide consistent queue status and operation lookup for recovery after lost command output. Bound each drain invocation and report progress only after local acknowledgment publication.
- REQ-4: Provide explicit offline decryption of a signed request using a separately supplied recipient private key and pinned scope/writer. Emit plaintext only after complete authentication, and never create or discover credentials.
- REQ-5: Demonstrate the actual CLI against a real loopback service, including unavailable delivery, lost response, restart, reuse, capacity, wrong recipient/scope/writer and opaque stored bytes. Preserve the existing persistence contract.

## Acceptance Criteria

- [ ] AC-1: Input queues with no server available, survives reopen, and decrypts byte-for-byte; wrong writer, oversized input, exhausted budget and reused operation fail without advancing the frontier. (REQ-1, REQ-2)
- [ ] AC-2: Actual CLI drain handles a remote commit whose first reply was lost, stores one remote commit, and releases the original head only on verified acknowledgment. Network/signature/access failures preserve exact queued bytes. (REQ-2, REQ-5)
- [ ] AC-3: Status/operation lookup distinguishes unknown, pending and acknowledged operations; a finite drain cap leaves remaining work visible; concurrent acknowledgers cannot discard a different head. (REQ-3)
- [ ] AC-4: Offline request decryption rejects mismatched scope/writer/private key and emits no plaintext on failure; keys require owner-only regular files and input bounds are enforced. (REQ-4)
- [ ] AC-5: Surface checks, targeted integration tests and fresh actual Claude Opus 5.5 review cover the changed code; backups and queue inspection contain no synthetic plaintext canary. (REQ-5)

## Architecture

`src/evidence_delivery.rs` composes `src/evidence_crypto.rs`, `src/evidence_spool.rs` and `src/evidence_http.rs`. Queueing takes a consistent status snapshot, seals input and signs the explicit frontier, then uses the spool's immediate admission transaction. Concurrent producers may receive a frontier conflict; no networking occurs before enqueue success. Reusing an operation is always an error for this plaintext-to-request API: resealing is nondeterministic, so it cannot prove an exact retry. Operators inspect the retained operation and drain existing bytes after uncertain admission; they must not allocate another operation blindly. Source-plan identity/content verification belongs to the migration driver.

Signing uses the existing explicit-file identity in `src/sign.rs`. `src/bin/kan-v2.rs` exposes `spool-init`, `spool-status` (optional operation lookup), `spool-head` (exact retained request export without dequeue), `queue-input` (bounded stdin), `spool-drain` (1–1024 requests per invocation, default 128), and `decrypt-request` (explicit signed request file, scope, writer and raw 32-byte owner-only recipient private key file). Recipient public bytes and operation identifiers are explicit canonical hex arguments. There is no key creation, global home discovery, automatic server or implicit live traffic. CLI JSON contains metadata only; decryption is an explicit raw stdout operation. Queue/status reports disclose local durability and pending state, not remote backup or historical completeness.

Delivery has no credential beyond the retained signed append, and derives its issuer pin from the owner-trusted spool. A canceled process or failed stdout write may leave the remote committed or local acknowledgment published; status and exact retry reconcile these cases. Concurrent drainers can both send the same head; a stale acknowledger fails without deleting the subsequent head. No network lock is held in SQLite. The existing 30-second request timeout and HTTPS/literal-loopback restrictions apply. A permanent remote rejection stops draining and requires explicit recovery; no records are skipped.

All spool mutations remain within `src/evidence_spool.rs` and its existing typed persistence capability. The schema/profile remains 2. Queue totals are a consistent snapshot, not a reservation; the CLI operation lookup is a separate observation and can reflect a different instant during concurrent draining. Startup still audits lifetime history; physical disk usage and operational scale are not bounded by the payload budget. Small raw chunks are the unit here; multi-chunk migration metadata, capture streaming and gateway forwarding are subsequent build points.

## Open Questions

Production custody/recovery, deployment selection and large-scale qualification remain open in the parent design. This composition uses caller-supplied keys and synthetic fixtures only. The existing day partial-trust failure prevents safe new subject recording; this versioned design and its eventual review need later backfill. No absence of prior teloi is inferred from that failure.

## Out of Scope

- Provider traffic capture, source import completion, key installation, owner erasure, bounded startup, deployment, live migration or main-branch merge.
