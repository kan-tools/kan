# Next build: physical KNB1 acquisition and read-only verification

Draft implementation plan; not format approval or a completed capability.
Parent contracts: kan-v2-recovery-bundles.md and kan-v2-recovery-bundle-codec.md.

The next checkpoint should expose a read-only, owner-only bundle inspection API.
It accepts a path, complete independently supplied Context, optional external
Checkpoint, and explicit acquisition/replay budgets. It returns the verified
Replay and bounded source identity. It exposes no Connection, unverified rows,
writer activation, generic standalone fallback, or publication-complete flag.

## Physical boundary

Use the proposed seven-table outer schema, application_id KNB1, user_version 1,
UTF-8 encoding. Freeze the actual DDL in one source file and independently pin
its sqlite_schema representation, column order, constraints and indexes. Require
exact schema: extra/missing tables, indexes, views and triggers refuse. Check
identity row cardinality and every field against caller pins before loading
bulk contents. All text is checked by byte length, ASCII where applicable, and
NUL exclusion; physical CID spellings must equal canonical parsed output.

Every column is independently checked for SQLite storage class and protocol
length even if the DDL has CHECK constraints. Writable-schema tampering and
ignored constraints must not turn TEXT or truncated values into BLOB evidence.
Canonical source records remain exact bytes; no derived fields are invented.

Check the main file and every existing reserved SQLite sidecar for private regular
file custody, symlink refusal and mutual inode aliasing before open. Bound their
observed total byte size with a separate owner-selected source budget. This is a
pre-open measurement, not a hostile namespace-replacement or later-growth fence.
Acquire the source with the existing private-file/path-custody conventions and
an explicitly catalogued SQLite coordination capability. A read-only SQLite open
may create WAL/SHM coordination files, and must not claim filesystem purity.
A hot rollback journal refuses; preserve all source media. Configure query-only,
SQL length limits, bounded cache, busy timeout, deadline/cancellation before the
first schema/data read. Pin one transaction before checking identity and scan all
contents through that snapshot. Do not use immutable=1 on an unproven live file.

An inspection has no output path. Later creator/restorer/publisher entry points
must check all participating paths and output/sidecar collisions before any
SQLite open; the inspection API does not discharge those future obligations.

## Acquisition and resource contract

Current pure replay consumes borrowed slices, so its first physical adapter must
explicitly budget acquisition before materializing data. Count rows and encoded
field bytes separately from replay's repeated scan-byte work. Charge each bounded
field before allocating/copying it; reject count/byte overflow. The owner chooses
the total budget; this is not a fixed repository-size limit. Refusal retains the
file and returns no partial verification. The API must report which limit failed.

SQLite probes use bounded substrings and length/type checks. Avoid WITHOUT ROWID
key seeks that materialize oversized corrupt payloads before SQLite's allocation
limit; scan in canonical primary-key order without an arbitrary sort. Preserve
empty or hash-invalid original BLOB bytes within the 4-MiB cell limit; candidates
must remain nonempty and hash-valid. A non-BLOB, malformed key or oversized cell
is a forensic-format refusal, not a missing-row conversion.

Acquisition bytes are not an exact RSS promise: bound item overhead, configure
SQLite cache, and document transient per-cell/replay overhead. A streaming adapter
is the next scaling step if real workloads exceed a chosen memory budget; do not
silently load an arbitrarily large archive or add a universal 10-MB cap. Duration
includes acquisition and semantic replay; filesystem stalls cannot be preempted
by a Rust deadline. Busy wait and SQLite VM cancellation behavior must be tested.

## Validation required before accepting the opener

Independently construct Python SQLite fixtures from the signed replay corpus;
keep raw canonical bytes and authority pins independent of Rust. Test profile 2,
complete and partial profile 3, corrupt/empty originals, restored candidates,
multiple attempts and external checkpoint extensions. Refuse altered schema,
UTF-16, missing history, foreign identity, noncanonical CID spelling, non-BLOB
cells, oversized corrupt cells, false row counts, unobserved candidates and
signed-but-invalid state histories. A fully restored bundle still refuses every
ordinary standalone opener/admission/backup/rebuild entry point.

Verify source main bytes/authoritative rows remain unchanged, distinguish allowed
coordination sidecars, and exercise pinned-snapshot concurrent changes. Include
byte/item budget boundaries, cancellation, busy source and malformed-file cases.
Run strict Clippy/fmt, surface conformance, affected lifecycle suites and fresh
actual Opus review. Mutation controls must prove schema, encoding, context,
physical-type/canonical-key and replay checks are exercised. Only then proceed
to creator/restorer transactions and publication crash windows.

## Draft implementation checkpoint

`src/evidence_store/bundle.rs` and `bundle.sql` now draft this read-only adapter.
`recovery_bundle_files.py` uses Python SQLite to construct physical files from
the 45 independent signed replay cases. It uses the previously reviewed proposed SQL fixture; the runtime DDL copy must
match that fixture exactly, and this is not a second semantic-schema oracle. Hostile
physical mutations and snapshot/cancellation regressions are locally qualified:
117 pre-merge integration checks, two snapshot units, selected controls, strict
lint, and a 45-function combined run after replay correction. Raw failures and
classified survivors are retained in the author review directories. Fresh
independent review remains required. No writer or public UI is
introduced by this draft, and no parent acceptance criterion closes.

## Independent review and correction qualification

Fresh actual Opus 5.5 reviewed frozen 01bc49b: scope A **BLOCK** because
SQLite projects an empty original BLOB as NULL, while the physical reader
rejected that projection. Scope B (the replay correction) is **APPROVE WITH
FOLLOW-UPS**. The full unmodified report and every probe/control are retained
in `.design/reviews/kan-v2-recovery-opening-opus/`. The earlier claim that empty
originals were qualified was incorrect; none of the 45 initial physical vectors
contained one. No parent acceptance criterion closed.

The correction admits that projection only after proving original storage class
BLOB and byte length zero. Source NULL/TEXT and empty candidates still refuse.
Five signed physical vectors cover initial loss/restoration and partial profile 3;
the original three reviewer cases are retained unchanged. Review follow-through
adds parser-accepted noncanonical spellings in all three key tables, timed SQLite
VM cancellation, explicit SQL refusal-code checks and pinned replay writer-pass
scan costs. The maximal-envelope Rust assertion is labelled as a Python-fixture
echo, not a second encoder.

`Error::Sql` preserves SQLite refusal codes: TooBig and DatabaseCorrupt identify
physical-format failures, and READONLY_ROLLBACK (776) identifies a hot source
journal. None is missing evidence. Owner-job presentation remains separate;
this API does not yet expose the later forensic capability enum. Root-based
standalone openers and namespace/hard-link limits are explicitly carried into
`.design/kan-v2-recovery-mutations.md`.

Author qualification passes 49 affected integration tests, three snapshot/cell
units, strict all-target v2 Clippy and formatting. The first new test run failed
because mutations targeted empty original-object tables; its logs are preserved,
and corrected fixtures assert that each targeted mutation changes a row.
Three selected semantic controls now fail when canonical spelling, SQLite VM
interruption or writer-pass accounting is removed; the restored 20-test subset
passes. Whole production fix reversion reproduces the empty-original failure and
restoring it passes. Raw qualification, failures, controls and reversion evidence
are retained in `.design/reviews/kan-v2-recovery-opening-correction-author/`.
Fresh review remains required; no production bundle writer has been introduced.

### Fresh correction review

Actual cold Claude Code Opus 5.5 reviewed frozen `eb4f471` (the reader bytes
match `b6a4f3f`) and returned **APPROVE WITH FOLLOW-UPS** for the correction.
The previous BLOCK remains attached to `01bc49b`. The unmodified combined report,
independent reversion, ten physical probes, controls and exact Git/SHA256 custody
are retained in `.design/reviews/kan-v2-assembly-opening-opus/`.

Follow-up A-N1 adds physical-file refusals for an empty TEXT original and empty
BLOB/TEXT restoration candidates, asserting refusal without forcing a diagnostic
label where replay independently backstops acquisition. Fifteen physical-reader tests, strict all-target v2 Clippy and formatting pass
with that addition; production reader logic is unchanged. Parent writer,
job, RPC and frontend acceptance remains open. All 21 CI checks passed at
`b6a4f3f`; later commits must receive their own CI results.
