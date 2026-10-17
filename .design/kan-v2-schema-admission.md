# Feature: exact schema admission for writable v2 archives

## Summary

Reject a database whose profile markers match kan but whose schema no longer enforces the storage contract. Extra triggers can otherwise delete evidence during an append, and missing uniqueness constraints can invalidate idempotency. This closes the schema-admission prerequisite found in fresh lifecycle review while retaining permissive forensic access to damaged derived data.

## Requirements

- REQ-1: `Ledger::open` and initialized-archive resume must validate the complete main SQLite schema before journal-mode configuration or returning a writable handle.
- REQ-2: Reject extra tables/views/triggers/indexes, missing constraints and changed table definitions, including schemas that happen to verify with no records. Preserve quiescent DELETE-mode bytes on rejection.
- REQ-3: RecoveryReader still reads intact raw evidence when derived bindings are missing or changed and rebuilds into the canonical schema. Physical page size, encoding and auto-vacuum are distinct from SQL schema admission.
- REQ-4: Existing archives created by the experimental engine, standalone backups and rebuilt archives remain writable after admission. Existing staged/committed evidence survives attempted admission of hostile schemas.

## Acceptance Criteria

- [ ] AC-1: Tests reject extra foreign table, deleting trigger, view/index, objects without its constraints and commits without uniqueness; both ordinary open and explicit resume reject without changing main bytes or adding sidecars to quiescent DELETE-mode fixtures. (REQ-1, REQ-2)
- [ ] AC-2: Canonical archives and normalized backups reopen and accept append; existing recovery tests still reconstruct missing bindings and reopen the result. (REQ-3, REQ-4)
- [ ] AC-3: A causal control removing writer schema admission makes the hostile-schema test fail; restored admission passes. Existing evidence and independent verifier tests remain passing. (REQ-1, REQ-2, REQ-4)

## Architecture

`src/evidence_store.rs` owns `SCHEMA`. Build a reference schema in a private in-memory SQLite connection using that exact schema, and compare ordered `(type,name,tbl_name,sql)` rows from each main `sqlite_schema`, including implicit indexes. Compare rows incrementally and reject any difference. This uses SQLite's own normalization of stored DDL instead of a second SQL parser or a hand-maintained duplicate. It adds no disk artifact and no writer beyond the existing `src/persistence.rs` capability boundary. The profile version is still experimental version 1; generated archives share this exact DDL.

Admission happens after marker validation but before the full content audit and WAL configuration in ordinary open. Explicit resume of an already initialized archive goes through this path. New creation and rebuild use the same canonical schema directly. The raw reader keeps its marker-only `check_schema` check, because it must tolerate missing derived tables. `verify_file` remains structural evidence verification, not a promise that arbitrary schema is admitted for writes; re-opening a backup for writes performs the new check.

Additional indexes or ANALYZE statistics tables are intentionally rejected in this experimental profile. A future performance or schema migration needs an explicitly versioned/qualified schema rather than silently broadening admission. SQLite physical settings are not SQL schema and remain separately qualified. This is an admission check, not protection against a hostile file owner changing the database after open or forging SQLite recovery media; that owner already controls the trusted local filesystem.

## Resolved Questions

- The operator authorized continued v2 functionality and fresh Opus 5.5 reviews. This is a concrete data-preservation prerequisite, not a new product choice.
- Keep raw recovery accessible independently of writable-schema admission.

## Open Questions

None for this bounded experimental profile.

## Out of Scope

Full-history-independent startup, runtime schema migration, non-default SQLite physical profile qualification, cryptographic authenticity, and protection against concurrent owner-issued DDL remain separate work. Day recording remains unavailable because the legacy inventory withholds claims; retain this versioned design for later back-fill without inventing claim identifiers.
