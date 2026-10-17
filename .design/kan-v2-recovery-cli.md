# Feature: explicit experimental recovery commands

## Summary

Expose the storage recovery library through `kan-v2`, so damaged derived lookups
do not prevent inspection or reconstruction of intact evidence. This is synthetic
archive maintenance, not v1 migration, deployment or automatic cutover.

## Requirements

- REQ-1: Read one manifest/receipt or ciphertext object from a database file without
  opening a writable ledger or requiring valid derived metadata.
- REQ-2: Rebuild to an explicitly supplied new file, preserving the original and
  reporting verified counts/snapshot without implying authentication or completeness.
- REQ-3: Make failure visible through nonzero status and stderr; never output a
  successful result for missing/raw-corrupt input or an existing destination.

## Acceptance Criteria

- [x] AC-1: Real executable tests read exact bytes from a binding-damaged archive;
  output identifies encoding and structural-only checks. (REQ-1)
- [x] AC-2: Real executable rebuild produces a separately verified file with exact
  evidence and original bytes unchanged; existing output cannot be overwritten. (REQ-2)
- [ ] AC-3: Missing sequence/object, invalid CID, raw corruption, and incomplete
  rebuild return nonzero with no success JSON. Surface checks and fresh Opus 5.5
  review cover the CLI integration. (REQ-3)

## Architecture

`src/bin/kan-v2.rs` adds `read-record <database> <sequence>`,
`read-object <database> <cid>` and `recover <database> <new-destination-file>`.
All three use `RecoveryReader`; the recovery design and mutation capability remain
owned by `src/evidence_store.rs` and `src/persistence.rs`. No new mutation surface.
`tests/recovery_cli.rs` invokes the actual binary against synthetic archives.
Raw bytes are hex in JSON with explicit encoding; manifests/receipts are canonical
DAG-CBOR, object bytes are opaque ciphertext. No decoding into semantic claims or
decryption is attempted. Outputs explicitly state admission and historical
completeness are not verified. Recovery verifies structural closure of the pinned
source snapshot, retains failed output, and never changes the installed v1 command.

## Out of Scope

Encryption, live user archives, v1 trust repair, automatic promotion/erasure, and
proving historical completeness without external receipt/frontier witnesses.

## Validation

The three real-binary recovery tests, six migration-preflight tests and 19 surface
tests pass. The tests run without legacy kan on PATH and compare source and rebuilt
bytes directly; Python independently checks the recovered archive. The separate
core recovery review and fresh CLI review remain pending.

## Review corrections and operating limits

The first fresh Opus 5.5 review approved with follow-ups. Recovery path strings are
now validated for JSON representation before any destination is created, preventing
a non-UTF-8 path from causing a post-rebuild JSON panic. Errors name the failed
source/destination and record/object; output-field assertions cover encoding, CIDs
and snapshot coordinates. A Unix argv test rejects non-UTF-8 output before creation.

Read-only refers to authoritative evidence access, not a promise of zero filesystem
coordination writes: SQLite can create `-wal`/`-shm` beside a WAL-mode source and
needs existing usable sidecars or a writable source directory. A WAL database copied
alone to read-only media may fail with a readonly-database error. This release does
not silently use immutable mode or ignore a WAL; either can hide committed data.
DELETE-mode backups/recovered files avoid this WAL coordination requirement. Keep
original database and any WAL together; forensic/media-level repair is outside this
slice. Ordinary API error context now identifies the source when this limitation
is encountered.

All staged objects are retained and hash-checked, including unreferenced orphans;
object counts are not committed-event counts and a hash check does not prove a
committed reference. A failed rebuild may leave an empty/unrecognized output, or a
complete committed output if a later sync/reverification failed. It is never
promoted automatically; the failed invocation does not certify durability. Errors
retain the file and a retry needs a fresh destination. Successful `verify` establishes
structural closure only, not an independent backup or historical completeness.
