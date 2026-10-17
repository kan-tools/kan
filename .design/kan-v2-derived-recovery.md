# Feature: recover intact evidence despite damaged derived data

## Summary

Implement the library part of storage review F2 with a read-only evidence handle and an out-of-place
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
- [x] AC-4: Independent Python verification agrees on rebuilt counts and closure;
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

## First independent review and correction scope

Fresh Claude Code `claude-opus-5-5` approved c557451 with follow-ups. Its hostile
probes recovered physically corrupt commit-index/binding pages and rejected raw
page corruption, unknown records, duplicate raw pairs and real page-spill crashes.
Before CLI exposure, fix its M1 (SQLite can materialize an oversized value before
`substr` bounds Rust output) and L1 (destination can collide with source sidecars).
The fresh correction review remains pending.

The recovery connection now sets `SQLITE_LIMIT_LENGTH` to 8 MiB, enough for a valid
4 MiB object plus key/row encoding, before reading the schema. This caps SQLite's
value/row materialization, including corrupt fields, while per-object and canonical
record format bounds remain 4 MiB and 64 KiB. Oversized database values fail with
SQLite `TooBig` before the Rust length/digest check; this is not a constant total
process-RSS guarantee. Two 96 MiB poison fixtures exercise reads and rebuilds.

Destination validation resolves its existing parent and rejects intersecting source
and output SQLite filename namespaces, source-base aliases, and preexisting output
sidecars. It includes reverse collisions where the output journal would name the
source, case-insensitive ASCII comparison, symlinked parents and Unix hard links.
It does not defend against an owner racing path replacement after validation.

Read-only means no authoritative evidence rewrite. SQLite can initialize source
`-wal` and `-shm` coordination files; a distinct `EvidenceRecoverySource` capability
and catalog rows now cover this connection-opening boundary. A WAL source requires
usable sidecars or a writable directory; read-only media may fail closed. Hot
rollback journals also fail closed. Preserve database and journal/WAL together,
then use SQLite crash recovery on a separate writable copy before inspecting it;
never discard a hot journal or silently assume immutable/no-WAL state. A pinned
rollback-mode reader can block writers; a WAL reader can retain checkpoint history.

A failed rebuild can leave an empty/unrecognized file or, after commit, a complete
file when subsequent sync/reverification fails. No error certifies durable success,
no output is promoted automatically, and retries require new destinations. Raw
corruption errors currently retain the underlying SQL/codec category where useful;
a unified diagnostic taxonomy is a later operator-experience improvement.


The author's RSS probe exposed a second allocation route: a WITHOUT ROWID primary
key seek can load an entire poisoned object row before SQLite's value limit. Thus
`RecoveryReader::read_object` deliberately scans keys using `NOT INDEXED` and unary
`+cid`, preventing a seek; the ordinary verified `Ledger` retains indexed reads.
Recovery object lookup has worst-case linear metadata I/O, explicitly outside the
ordinary bounded-read performance target. Rebuild already streams a table scan.
Unix child-process tests measure peak RSS below 64 MiB for 96 MiB poisoned manifests
and objects; Windows still checks rejection but does not run the Unix RSS witness.
Removing the SQLite limit or restoring the unsafe seek independently fails a test.


First-review identity: base ff8d57c1b20eb2c95eeb4512c7eac53e18105533,
head c557451d501b86c8022d7f222d8809b7b2eaf28e; session
`da152494-9f34-4f5f-abad-8a975027315c`, actual model `claude-opus-5-5`.
The unedited final report is `.local-state/reviews/recovery-round-1-report.md`,
SHA-256 `04d097ddc3e1da98a2965cdaacccd23ef8333b97f2006d77c9ba2c00ee2d60ec`.
The reviewer independently ran 45 targeted tests, build, lint, formatting, the
codec oracle and hostile scratch probes. It did not run the full legacy matrix,
private day process state or author mutation scripts. Its approval covered the
original library slice with follow-ups, not the subsequent corrections.

Correction validation: 23 storage + seven codec + 19 surface tests pass, along with
feature all-target Clippy, formatting and whitespace checks. All eight compiling
negative controls fail their named tests and restored fixes pass. The maximum
valid 4 MiB object is readable and rebuildable. A separate macOS RSS probe measured
approximately 9.2 MB peak for both 9 MiB and 96 MiB poisoned manifests/objects after
the fixes (versus about 110 MB for a 96 MiB object with the unsafe key seek).
Fresh combined core/CLI correction review is pending on the dependent branch.

## Final correction review

Fresh Claude Code `claude-opus-5-5` review of the integrated correction
`1d89ec56ac5024e25629bd877ca597e19f0c5156..f2419adf42ca2f6a17d1caba5a053f6a7d6b951a`
returned **APPROVE WITH FOLLOW-UPS**. This includes storage implementation
0b15b9119f71e3f85e492513841a1f185491a7a5 unchanged. The reviewer independently
passed all 59 integrated tests, lint/format and feature-gate checks, and ran probes
for memory, Unicode/hard-link/sidecar aliases, WAL-only committed evidence, hot
journals and non-UTF-8 CLI paths. Exact review identity/digest is recorded in the
dependent branch's `.design/reviews/kan-v2-recovery-2026-10-16.md`.

The remaining medium finding is an availability boundary under RAW table damage:
a recovery object scan may encounter an unrelated corrupt page or oversized raw
key before reaching an otherwise intact requested object. It returns an error,
never empty success or fabricated content. Bounded indexed access across such raw
damage would require a separately isolated recovery process or another qualified
storage format; the library does not impose a process-global SQLite heap limit.
This limitation is distinct from damaged derived bindings/commit indexes, which
remain recoverable. Use preserved backup copies/specialist recovery for raw page
loss; a canonical record at an intact journal sequence may still be readable.
A new regression demonstrates the raw-key case and retained record access.

Remaining low/informational follow-ups: unified SQL/codec/hot-journal diagnostics;
non-UTF-8 hard-link alias coverage in direct library callers (the CLI rejects those
paths); and the older CLI init/backup JSON-path behavior, outside this recovery
change. Later commits document this verdict and add the raw-key regression only;
they do not change the reviewed production implementation.
