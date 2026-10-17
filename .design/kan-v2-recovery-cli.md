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
- [x] AC-3: Missing sequence/object, invalid CID, raw corruption, and incomplete
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


First CLI review: base 1bdcda28b5fa4842a9432e3f4aee7a7293a48807, head
1d89ec56ac5024e25629bd877ca597e19f0c5156; fresh `claude-opus-5-5` session
`fae0f036-197c-4281-8860-21bbcd781b0f`, verdict APPROVE WITH FOLLOW-UPS.
Unedited final report `.local-state/reviews/recovery-cli-round-1-report.md`, SHA-256
`7889d7f4a59372d7f2dbe9677837e2177c0e0bb00788b3cb20e8b3ea8435f2f9`.
It independently passed 28 tests, build, lint, format, feature-gate refusal and
synthetic CLI probes. Private teloi/process atoms and the full legacy matrix were
not reviewed. The reviewer could not set environment prefixes in its tool policy;
the launcher configured profiles, but that was not independently confirmed.

The branch now inherits storage correction 0b15b91: bounded SQLite value allocation,
a scan for recovery object reads (ordinary ledger reads stay indexed), sidecar
namespace protection, and explicit source-coordination capabilities. Recovery object
lookup can scan all keys; its CLI help now says so. These are offline recovery
operations, outside ordinary bounded-query performance targets. The combined fresh
correction review remains pending.

Integrated correction validation: all 59 targeted tests pass (23 storage, seven
codec, six preflight, four recovery CLI and 19 surface tests), as do all-target
feature Clippy, formatting and whitespace checks. The parent independently passed
all eight causal negative controls. Fresh combined correction review is pending.


## Final correction outcome

Fresh `claude-opus-5-5` review of 1d89ec5..f2419ad returned **APPROVE WITH FOLLOW-UPS**,
with 59 independently passing tests and executed hostile memory, alias, WAL and hot-
journal probes. See `.design/reviews/kan-v2-recovery-2026-10-16.md` for exact hashes,
model/session evidence, test limits and dispositions. A later regression adds one
passing witness for the documented raw-key scan limitation; runtime code is unchanged.

An unrelated corrupt raw-object page or oversized raw key can stop `read-object`
before it reaches an intact requested object. This limitation is additional to its
linear scan cost. It fails explicitly; use preserved backups/specialist recovery for
raw table damage. Damaged derived bindings and cached commit coordinates are the
supported repair case. More specific hot-journal diagnostics, old init/backup JSON
path behavior and non-UTF-8 aliases for direct library callers remain follow-ups.

## Initialization and verification continuation

The lifecycle extension adds `kan-v2 init --resume <archive>` and preflights JSON paths for init/backup, while exclusive `init` still refuses an existing file. See `.design/kan-v2-storage-lifecycle.md` and `.design/kan-v2-schema-admission.md` for the reviewed behavior. Writable open and resume require the canonical schema. `kan-v2 verify <database>` currently verifies structural evidence only; success does not establish writable-schema admission, cryptographic admission, historical completeness or independent backup. Its help/JSON still needs explicit writable-admission disclosure. Raw `read-record`, `read-object` and `recover` remain available for damaged derived data under their documented limits.
