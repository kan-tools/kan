# Feature: Continuous delivery, durable operations status and operator dashboard

## Summary
Continue the reviewed gateway toward a supervised personal service. A separate worker drains exact retained bytes, a private operations database records health independently of the encrypted queue, and a browser dashboard and CLI read one status contract. This serves telos/raw-data-and-projections: operational observations never replace raw evidence or prove completeness. The user explicitly requested a front end on 2026-10-18, superseding the older CLI/MCP-only UI fence for v2 operations.

## Requirements
- REQ-1: Continuously drain an explicitly selected spool through existing signed archive delivery, without keys, resealing, skipped heads or inference retries. Retry with bounded backoff; resume exact queued bytes after restart.
- REQ-2: Persist capture summaries and recording gaps independently of queue capacity. Capture callbacks use bounded nonblocking handoff; report dropped telemetry and storage failure honestly. Retain recorded summaries until owner erasure and never infer complete coverage from silence.
- REQ-3: Publish one versioned status contract for CLI and dashboard, with sample times, queue totals, archive acknowledgment progress, retry state, recent attempts and cumulative gaps. Distinguish stale observations and unavailable health from healthy operation. Queue age is time since this worker first observed a continuously nonempty queue, not the oldest event's creation time.
- REQ-4: Serve a usable responsive operator dashboard with an in-memory token and no payloads, credentials, external assets or browser persistence. Bind only to literal loopback; authenticate the private API, reject foreign Host/Origin, disable caching and enforce CSP. Remote operators use an authenticated tunnel.
- REQ-5: Replace pending connection eviction with bounded per-peer admission that cannot abort an already admitted handshake when another peer churns. Bound pending work and keep authentication before authenticated-slot reservation. Document same-peer and distributed saturation limits.
- REQ-6: Provide supervisor templates and stop/restart guidance; do not install services, choose production secrets or perform live cutover. Preserve v1 sources and backups.

## Acceptance Criteria
- [ ] AC-1: Fake archive outage/recovery and worker restart deliver identical retained signed requests, acknowledge only verified replies and retain a rejected head. Cancellation does not initiate provider traffic. (REQ-1)
- [ ] AC-2: Journal reopen retains gap summaries; missing/full/locked health storage cannot block capture callbacks; dropped telemetry appears as incomplete coverage, and database capacity never removes retained records. (REQ-2)
- [ ] AC-3: CLI and HTTP return the same status shape; samples retain timestamps, archive totals are distinguished from capture completion, and stale or missing observations render visibly. (REQ-3)
- [ ] AC-4: Authenticated browser flow renders real synthetic status, failure and empty states; unauthenticated API, foreign Host/Origin and unsupported methods fail. No token enters URL, storage or response bodies. (REQ-4)
- [ ] AC-5: A delayed legitimate handshake from a different peer survives churn; same-peer limits and global caps hold and existing authenticated streams survive. (REQ-5)
- [ ] AC-6: Document and validate example supervisor arguments against CLI help; fresh actual Claude Code Opus 5.5 audits this build before its draft PR. (REQ-6)

## Architecture
The existing `src/persistence.rs` capability boundary and `tests/surface_conformance.rs` catalog remain mandatory. `src/evidence_delivery.rs` remains the only archive send/ack composition. The new operations worker owns one audited spool connection for its lifetime and records a bounded status sample between deliveries. It backs off after all delivery errors and never discards an offending head. One worker per spool is the deployment convention; existing acknowledgment checks remain the concurrency defense.

`src/evidence_operations.rs` owns a separate owner-only SQLite operations database. It records sanitized cumulative capture snapshots per random attempt, process-session telemetry-loss counters, and the latest worker snapshot. Operational metadata is intentionally readable by the instance owner, matching the selected rich-metadata default. It contains no prompt/body/URL/key material. Existing encrypted spools remain authoritative for admitted evidence; this operations database is authoritative only for its own observations, not a projection reconstructible from the archive. Updates of a cumulative attempt snapshot preserve monotone gaps. No automatic retention expiry. A fixed SQLite page cap and bounded record count fail closed for telemetry persistence, not inference. Separate storage is a logical reserve from a full spool budget, not a guarantee under whole-device failure. Queue metadata timestamps are wall-clock observations, not trusted chronology.

The proxy's optional journal reporter uses a bounded nonblocking channel to a dedicated writer thread. Loss is counted and periodically persisted by that writer; a crash before persistence leaves an unclean session with explicitly unknown coverage. This bypasses synchronous stderr reporting when enabled. A failed writer remains observable through stale timestamps and unclosed session state. Clean shutdown flushes queued telemetry where possible, without promising a hard filesystem deadline.

`src/evidence_dashboard.rs` serves compiled local assets from `web/operations/` and a read-only status API. It has no decryption keys or mutation routes. Authentication is bearer-token based; the login form retains the token in memory only. The API and CLI read the same bounded database snapshot. HTML/JS uses text nodes for variable content and a same-origin restrictive policy. This expands v2's presentation surface without introducing another authority model or workflow store.

`src/evidence_gateway.rs` changes pending admission from oldest eviction to per-source-IP (IPv6 /64) caps and a global cap. New excess connections are refused; they cannot evict earlier legitimate admissions. This isolates a bounded distinct-source churn case, not an Internet denial-of-service guarantee or fairness between users behind one NAT. Private ingress remains recommended pending deployment capacity qualification.

The next production gates remain bounded capture/startup audit and asynchronous admission, production custody/erasure, independent-host backup/restore, migration rehearsal and explicit cutover. This batch implements the concrete operational features above and does not assert those gates have vanished. No local Mathlib builds or dependency duplication.

## Open Questions
No blocking product decision for the first read-only operator dashboard. Full evidence browsing, search and extraction views will extend the API after raw storage operations are trustworthy.

## Out of Scope
Public dashboard hosting, browser decryption, destructive controls, provider calls, installation of live services, main merges, live migration, automatic evidence expiration and extraction/day workflow merger. The operations database does not certify completeness during process death, disk failure or bypass traffic.

## Process record
Legacy kan reads still withhold two claims without subject attribution. The visible telos remains intentionally unwitnessed. Claim/bridge backfill stays pending; no fabricated CIDs or inferred witness completion. Git retains the design and independent review evidence.
