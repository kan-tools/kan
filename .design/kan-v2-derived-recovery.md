# Feature: recover intact evidence despite damaged derived data

## Summary

Close storage review F2 with a read-only evidence handle and an out-of-place
rebuild. Derived bindings and cached commit coordinates must not be prerequisites
for reading raw evidence. Never repair the only copy in place. This is an explicit
offline recovery operation, not normal bounded writer startup (F1 remains open).

## Requirements

- REQ-1: Read intact canonical manifest/receipt pairs and ciphertext independently
  of bindings and cached commit coordinates, without enabling writes to a damaged store.
- REQ-2: Reconstruct all derived commit fields and first-use bindings from one
  consistent raw snapshot, preserving exact raw bytes, sequence and staged orphans.
- REQ-3: Reject corrupt raw records, gaps in the observed sequence, missing referenced
  objects and inconsistent history. Never silently
  skip a bad row, fabricate a receipt, overwrite a destination, or modify the source.
- REQ-4: A failed or interrupted rebuild must not expose a valid partial archive.
  Inventory its persistent artifacts and verify the complete result before success.

## Acceptance Criteria

- [x] AC-1: Missing/poisoned bindings (including a missing table), incorrect commit
  CID/coordinates and cross-scope/later-use pointers fail normal verification but
  allow bounded raw reads and successful rebuild. Compare raw bytes directly. (REQ-1, REQ-2)
- [x] AC-2: Raw corruption, missing objects, receipt mismatch and sequence gaps
  reject rebuilding; a separate intact record remains readable. Concurrent source
  appends do not change the pinned recovery snapshot. (REQ-1, REQ-2, REQ-3)
- [x] AC-3: Child-process exits during object copy, record copy, after verification
  and after commit leave either an invalid incomplete file or the complete verified
  archive. Existing output and source are unchanged; retry uses a fresh destination. (REQ-3, REQ-4)
- [ ] AC-4: Independent Python verification agrees on rebuilt counts and closure;
  source corruption remains detectable; surface tests, lint and fresh Claude Code
  Opus 5.5 review pass. (REQ-4)

## Architecture

`src/evidence_store.rs` gains `RecoveryReader`, which owns a read-only SQLite
connection and pins a read transaction immediately. Opening checks only the profile,
not lifetime history or derived tables. Individual record reads validate canonical
bytes and receipt binding; ciphertext reads validate length and digest. These checks
are structural, not authentication. The handle exposes no stage/commit methods.
Errors remain errors; a missing sequence is distinct from a successful empty page.

Rebuild creates an owner-only standalone destination database through a new typed
`EvidenceRecovery` capability in `src/persistence.rs`. Its schema, raw copies and
recomputed coordinates/bindings are installed in ONE rollback-journal transaction.
Full integrity/closure verification runs inside that transaction before commit.
The SQLite profile markers become visible atomically with the entire history;
before commit an interrupted file is unrecognized, never a valid prefix. After
commit, close and sync the file and parent, then reopen and verify. No automatic
promotion, source deletion, overwrite, or live cutover is provided. A failed output
is retained for inspection and must not be reused as a destination.

Copying streams one bounded object/record at a time; the offline transaction and
verification are proportional to archive size on disk and in I/O, not an in-memory
archive. A pinned reader can retain WAL history until dropped; operators should
finish/drop it promptly and provide capacity for a full additional database plus
journaling. The source's authoritative `objects.cid` is a retained content commitment:
its mismatch is raw damage, not permission to rename changed bytes. Commit cached
CIDs are derived from canonical manifests. Schema/page corruption affecting raw
tables, absent authoritative tables, unsupported records and detectable raw byte loss require
backup/specialist recovery and must not be presented as repaired. Without an external
trusted receipt/frontier inventory, a coherently removed suffix cannot be detected;
recovery reports the snapshot present in the source, not proof that all historical
data ever captured survives. Authentication and external completeness witnesses
remain later admission/backup work.

`src/surface.rs`, `tests/fixtures/read-write-surface.tsv` and
`tests/surface_conformance.rs` register the recovery database and rollback journal.
`tests/evidence_store.rs` supplies hostile fixtures and crash witnesses. The existing
independent Python verifier is reused without accepting weakened recovery semantics.
The downstream migration branch will expose the library through `kan-v2` commands.

## Out of Scope

Ordinary writer startup performance, interrupted ordinary initialization, encryption,
admission, v1 trust repair, automatic erasure, production deployment and live migration.
No live user archive is rewritten by development or tests.

## Process evidence

`day design check` passes structural checks. It resolves referenced source paths
against the original checkout, so two new worktree paths are warnings. The known
v1 trust issue still withholds two claims; no claim IDs or process state are
fabricated to bypass it. Tests use synthetic archives only.

## Local validation

All 19 storage, seven codec and 19 surface tests pass. The recovery matrix covers
six derived-damage forms, eight raw-damage forms, valid-but-inconsistent raw history,
exact original/rebuilt bytes, orphan preservation, snapshot isolation, no overwrite
and four child-process crash boundaries with page spill. The independent Python
verifier accepts each rebuilt derived-damage fixture. Feature all-target Clippy,
formatting, whitespace, citation and RFC/ADR checks pass; the codec oracle reports
27 positive and 58 negative vectors.

`scripts/recovery_negative_controls.py` demonstrates four compiling, executing
regressions: gating raw access on derived verification, removing snapshot pinning,
publishing the profile before copying, and using an unregistered mutation capability.
Each named test fails under its mutant and passes after restoration. The typed
facade's implementation digest was updated only for the new capability inventory.
Fresh independent review and downstream CLI integration remain pending.
