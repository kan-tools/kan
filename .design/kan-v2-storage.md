# Feature: kan v2 transactional opaque ledger

## Summary

Build the P3 storage core beneath draft RFC 4. Use a separate authoritative SQLite database for bounded ciphertext objects, canonical manifests and exact receipt statements, with transactionally maintained retry and slot constraints. This is distinct from v1's disposable SQLite projection. Add snapshot enumeration, integrity verification, a consistent backup/restore path and crash witnesses before routing live data into it. Feature `v2-storage` enables this experimental library; no current kan command or source repository changes storage.

## Requirements

- REQ-1: Stage bounded ciphertext chunks independently of total archive size; hash their exact bytes and never overwrite a conflicting or corrupt object.
- REQ-2: Commit a manifest, receipt and transport bindings atomically after checking object closure, per-writer predecessor, retry identity and immutable slot binding. Duplicate operations recover the original receipt even after lost acknowledgment.
- REQ-3: State the durability boundary precisely and test abrupt process failure before and after it; no durable receipt is returned before commit.
- REQ-4: Enumerate immutable evidence at an explicit pinned snapshot in bounded pages, preserving raw records independently of consumer trust or the current metadata projection.
- REQ-5: Verify authoritative bytes, derived bindings and record reachability with bounded memory; produce consistent backups using SQLite's snapshot API and verify restores independently.
- REQ-6: Register every persistence artifact, database field and mutation owner in the surface catalog, and keep the production v1 storage path unchanged.

## Acceptance Criteria

The following local witnesses pass. Remote CI and independent review are reported separately.

- [x] AC-1: Chunk tests reject zero/oversize content, preserve duplicate bytes, reject digest corruption, and commit more than 10 MB without a whole-store serialization. (REQ-1)
- [x] AC-2: Retry/conflict tests exercise identical operations, changed commitments, stale heads, missing objects and slot rebinding; failed commits expose no partial manifest or receipt. (REQ-2)
- [x] AC-3: Child processes terminate at staging, manifest insertion, binding insertion, pre-commit and post-commit boundaries. Reopening recovers all acknowledged objects and exact receipts; retry never adds a second operation. (REQ-3)
- [x] AC-4: Append during paginated reads cannot change a pinned page's coverage; genesis is explicit and invalid snapshots are rejected. (REQ-4)
- [x] AC-5: Python's SQLite reader and independent CBOR/CID oracle agree on every committed manifest/object; restore from an online backup passes closure verification and reproduces snapshot and receipt bytes. Corrupt objects and bindings fail verification. (REQ-5)
- [x] AC-6: Surface-conformance and existing claim tests pass; new schema columns and mutation sites are exhaustively inventoried. (REQ-6)

Local validation:

- AC-1: `tests/evidence_store.rs::chunks_and_total_archive_exceed_legacy_cap` checks reachability after every insertion and stores 15 MiB of distinct opaque object data.
- AC-2: `tests/evidence_store.rs::retry_conflicts_and_atomic_validation` and `tests/evidence_store.rs::concurrent_retry_has_one_commit_and_identical_receipts` cover missing objects, conflicts, concurrent duplicates and recovery of the original receipt despite a changed proposed issue time.
- AC-3: `tests/evidence_store.rs::abrupt_exit_matrix_recovers_atomic_commits_and_exact_retries` checks six abrupt-exit boundaries in child processes. This is process-crash evidence, not a power-cut claim.
- AC-4: `tests/evidence_store.rs::snapshot_pages_survive_appends_and_reject_unknown_frontiers` checks explicit genesis, bounded pages and a pinned frontier after further writes.
- AC-5: `tests/evidence_store.rs::backup_restore_and_independent_oracle` runs a separate Python SQLite/CBOR/SHA256 reader and compares measured counts and exact restored receipts. `tests/evidence_store.rs::corruption_is_not_an_empty_archive` makes both verifiers reject changed object bytes, bindings and indexed operation metadata; opening the corrupt store also fails.
- AC-6: `tests/evidence_store.rs::database_columns_match_independent_surface_catalog` and the 19 surface conformance tests pass. No v1 caller selects the new engine.
- `cargo test --workspace --all-features` passes with process-local `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false`, needed because fixture Git commits otherwise inherit a passphrase-protected signing key. Personal Git configuration is unchanged. The final storage-only refinements were rechecked with the storage, evidence-contract and surface suites.

## Architecture

`src/evidence_store.rs` is the sole database owner and consumes the validated records in `src/evidence.rs`. `src/persistence.rs` owns filesystem creation and permission changes. `src/surface.rs` declares evidence artifacts; `tests/surface_conformance.rs` and `tests/fixtures/read-write-surface.tsv` independently register them. `tests/evidence_store.rs` supplies crash, pagination and restore witnesses. The independent oracle extends `scripts/evidence_reference.py` through a separate SQLite verifier.

The database uses WAL with synchronous FULL and fullfsync enabled. It lives on a local filesystem on the service host; clients use the later service API rather than opening SQLite over a network filesystem. The database and WAL hold authoritative data; the shared-memory file is coordination only. A successful transaction is the receipt durability boundary, subject to the OS/filesystem/device honoring sync. Process-kill tests do not establish immunity to hardware faults or lying storage controllers.

Objects are at most 4 MiB; events and imports consist of any number of chunks and batches. No raw event body is limited to one chunk. A transaction stores at most one manifest's bounded metadata and bindings; objects are staged beforehand. The canonical manifest is authority for bindings. Opening performs a bounded-memory full integrity/closure audit before writes; the long-lived connection then serves the hot path. This deliberately trades startup time proportional to archive size for explicit corruption detection in the first engine. Verification checks indexed coordinates against canonical records; corruption is an error, not an empty archive or permission to rebind slots. SQL uniqueness enforces per-writer position and operation identity under concurrent writers. Committed data has no update/delete API. Unreferenced staged objects remain explicit retained data, not invisible garbage collection.

An internal snapshot is `(through, tip)`, where through is the global local journal sequence and tip is its exact manifest CID. Genesis is `(0, null)`. Each manifest still carries its RFC 4 writer-specific position. These local snapshot coordinates are not a new public wire format. Query indexes for decrypted subjects remain a later layer.

Backup uses SQLite's online backup API into a newly created owner-only database, then independently verifies its contents. It is a local recovery copy until copied and verified at an independent destination. A failed backup leaves an explicitly incomplete destination for inspection; existing backup files are never overwritten. No source rewrite, identity adoption, key export or live cutover occurs in this slice.

Receipt records supplied to this lower layer are structurally bound, not authenticated. P4 must authenticate writer and receipt issuer and add their exact proof envelopes before exposing commits through a service. P3 does not imply approval of a cryptographic profile. Existing v1 sources remain ground truth while later migration copies their bytes into encrypted storage.

## Resolved Questions

- The user explicitly prefers completing v2 and migration over repairing day, while retaining backups and original evidence.
- Use the same storage engine for local and hosted operation, with bounded per-object memory and a single atomic commit owner.
- Extend draft RFC 4 to name the SQLite durability profile; this is an experimental implementation, not RFC acceptance.

## Open Questions

Owner-held archive-key custody, initial deployment and the independent backup destination have been asked separately. Storage tests and source discovery do not depend on their answers. Actual encrypted migration and deployment do.

## Out of Scope

- Inference integration, semantic extraction, automatic erasure, production network admission and private-key migration.
- Claims that local backups alone establish independent disaster recovery.
- Fixing day or changing v1 trust policy.
