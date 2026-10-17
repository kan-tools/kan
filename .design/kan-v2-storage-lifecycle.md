# Feature: resumable archive initialization and isolated backups

## Summary

Finish two P3 storage lifecycle gaps: explicitly resume an interrupted initialization without replacing evidence, and protect backup destinations from SQLite sidecar collisions. This continues the existing storage design and the operator's authorized v2 buildout; it does not select a production key profile or deploy a service.

## Requirements

- REQ-1: `Ledger::create` remains exclusive. A separate explicit resume operation can finish an empty interrupted SQLite initialization or reopen a fully initialized archive after a lost acknowledgment; it never replaces tables or evidence.
- REQ-2: Initialization publishes the complete schema and profile in one durable transaction. Termination before or after publication must have a safe, testable continuation; malformed or foreign databases are rejected.
- REQ-3: Backup refuses overlap with the source database's SQLite namespace and refuses preexisting destination sidecars before creating output. Existing files remain unchanged on these preflight failures.
- REQ-4: Inventory all backup media, including transient WAL and SHM, through the existing persistence capability and conformance catalog. Successful backup is standalone DELETE-journal SQLite with independently verified evidence.
- REQ-5: Expose explicit initialization resume through the experimental CLI, and reject non-UTF-8 JSON output paths before init/backup mutations. Preserve v1 behavior.

## Acceptance Criteria

- [ ] AC-1: Process-exit tests at file creation, schema writes, schema commit and ready boundaries resume successfully; duplicate create still fails; repeated resume preserves exact populated evidence. (REQ-1, REQ-2)
- [ ] AC-2: Foreign tables, wrong profile/version and malformed files are rejected; their main-file bytes remain unchanged. Symlink and permission checks apply to resume. (REQ-1, REQ-2)
- [ ] AC-3: Backup namespace collision tests preserve source and sentinel sidecars, including hard-link aliases; no output is created on preflight rejection. (REQ-3)
- [ ] AC-4: Observe backup after copying and normalization; catalog actual/possible sidecars, verify owner-only permissions and standalone closure using the independent Python verifier. Surface conformance passes. (REQ-4)
- [ ] AC-5: Actual CLI tests cover explicit resume, exclusive create, foreign rejection and non-UTF-8 preflight. (REQ-5)

## Architecture

`src/evidence_store.rs` continues to own SQLite, with filesystem writes through `src/persistence.rs`. Initialization's schema and profile markers are committed together under an immediate transaction with FULL synchronization. WAL configuration follows schema publication. Explicit `resume_initialization` opens an existing owner-only file: an existing recognized profile takes the normal audited open path; profile/version zero plus an empty schema is initialized under a writer lock. Any other profile/schema is an error. No deletion, truncation, replacement or trust reset is offered. SQLite may recover a hot journal/WAL while opening the explicitly selected file; this operation is not a forensic read-only tool. Empty foreign SQLite files are indistinguishable from interrupted initialization, so only explicit resume authorizes their adoption.

Crash observers expose file-created, schema-written, schema-committed and ready boundaries. After publication a retry verifies the archive rather than reinitializing it. Directory synchronization completes the successful return; process faults test SQLite atomicity, not power-loss guarantees. Owner filesystem races and hostile replacement of paths remain outside the existing personal-instance filesystem trust boundary.

Backup reuses the recovery destination namespace validation, obtaining the source filename from the live SQLite connection. The destination is exclusive and has no existing journal/WAL/SHM. The online backup API can copy WAL mode to its destination, so all four possible files belong in `EvidenceBackup`, `src/surface.rs` and `tests/fixtures/read-write-surface.tsv`; WAL/journal contain authoritative recovery material, SHM is disposable coordination. Observers inspect copy-complete and normalized boundaries. The final close/sync/verify behavior remains unchanged. Failed output is retained and must not be treated as a certified backup; no automatic promotion occurs.

The migration branch's `src/bin/kan-v2.rs` adds `init --resume`. Its JSON says whether resume was requested and validates JSON path representation before creating output. No production migration, networking or crypto is added. Core changes land on the storage parent, then merge normally into migration for CLI work and a fresh combined review.

## Resolved Questions

- Continue the established v2 direction and preserve existing archives; no new product decision is needed for these defect fixes.
- Use explicit resume rather than silently treating any existing empty file as an archive.
- Keep the fresh Claude Code `claude-opus-5-5` review gate. Private kan/day telos reads remain unavailable to external review; review uses the published design as its stated purpose, not an assertion that no teloi exist.

## Open Questions

None for this slice. Key custody, deployment, provider selection and independent backup location remain prerequisites for later live operation.

## Out of Scope

Normal startup's full-history audit, encrypted service admission, real import, independent disaster recovery certification, and day trust repair remain separately tracked work. This slice does not claim the parent scale or production-readiness criteria complete. Day recording remains blocked by the previously diagnosed incomplete trust-filtered inventory; this tracked design awaits back-fill without fabricated claim IDs.
