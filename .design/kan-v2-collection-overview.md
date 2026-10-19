# Feature: Bounded, deduplicated operations collection overview

## Summary
Continue the preserved-history work in `.design/kan-v2-operations-polish.md` by
building a collection-wide projection over cumulative observations. Ordinary
status polling must remain cheap; a refresh builds an explicitly bounded,
rebuildable in-memory overview, naming every included generation and the active
snapshot. This serves `telos/raw-data-and-projections`: a total is a view over
retained observations, never proof that all raw traffic was captured.

## Requirements
- REQ-1: Pin the collection binding, ordered generation membership and active generation from `src/evidence_operations_collection.rs`; verify each sealed hash and binding before including its rows. Unknown, missing, changed or malformed sources fail visibly.
- REQ-2: Deduplicate attempts by their retained attempt identity within the collection binding, and reporter sessions by retained session ID. Repeated cumulative observations must never be summed. Preserve a whole dominating attempt observation; never synthesize a state from independent counter maxima.
- REQ-3: Distinguish a complete projection of the selected observation snapshots from capture completeness. Report the selected frontier, exclusions, retained gap observations and lower-bound telemetry loss. An incomplete/failed build cannot publish a plausible whole-collection zero or partial total as complete.
- REQ-4: Bound concurrent builds, generations, source bytes, distinct identities and aggregate memory. Refresh is explicit, cancellable and isolated from capture callbacks. Normal status polling returns a small published result and does not scan sealed journals.
- REQ-5: Source journals, collection manifest and encrypted evidence are never rewritten by aggregation. The first implementation adds no persistent projection or temporary plaintext copy. Process restart loses the cache and visibly requires rebuilding.
- REQ-6: Expose the same typed overview to CLI and Operations UI. Keep current active-generation health separate from sampled historical totals. Refreshing a disposable read projection grants no rotation, erasure, signing or reader-decryption authority.
- REQ-7: Test semantic negative controls, snapshot changes, conflicting repeats, capacity exhaustion and refresh races. Use a fresh actual Claude Code Opus 5.5 review before treating this as a completed build point.

## Acceptance Criteria
- [ ] AC-1: A fixture with repeated attempts and sessions in three generations yields the deduplicated whole-observation totals; conflicting observers, counter regressions, changed terminal outcomes and arithmetic overflow refuse publication. Reverting deduplication fails a named assertion. (REQ-2, REQ-3, REQ-7)
- [ ] AC-2: Hash mismatch, binding mismatch, missing generation, reordered membership and rotation during refresh either refuses on the held collection lock or occurs after publication and leaves an explicitly old frontier. Hashes of source files and manifest before/after are identical except for fixture-authorized concurrent writes. (REQ-1, REQ-5, REQ-7)
- [ ] AC-3: Refresh publishes a pinned active SQLite snapshot and included sealed-generation identities. Later active writes or rotation leave its sampled frontier visibly old, never silently relabeled current. Worker status and collection totals remain separately labeled. (REQ-1, REQ-3, REQ-6)
- [ ] AC-4: A deterministic barrier demonstrates that repeated HTTP polling reads only published memory while a slow build runs; one-build admission, cancellation, connection limits and identity/memory limits hold. Exceeding a bound preserves the last result with an explicit failed-refresh state. (REQ-4, REQ-7)
- [ ] AC-5: Real CLI and authenticated browser flows cover unavailable, building, completed, capacity-limited, failed, cancelled and superseded states. Lock clears displayed metadata and prevents a late result repaint; refresh cannot invoke owner mutation operations. (REQ-3, REQ-4, REQ-6)
- [ ] AC-6: Process restart starts with no overview and no new persisted surface. Fresh Opus review, meaningful baseline/revert/restored assertions and runbook limitations are committed; the full frontend matrix remains open for unrelated workflows. (REQ-5, REQ-7)

## Architecture

### Current implementation and missing input

`Journal::snapshot` in `src/evidence_operations.rs` returns sums and only 100
recent attempts/reporters. Reporter rows omit their IDs. It cannot be used as
input to exact deduplication. `history` in
`src/evidence_operations_collection.rs` verifies a sealed generation but returns
that same limited view. `generations` correctly says its counts are not additive.
`new_generation` seeds worker history, so adding worker counters across rotations
would immediately count the same failures twice.

The build therefore needs a private typed row iterator over a read-only SQLite
transaction, preserving attempt and session identities and validating every row.
Keep it separate from the public 100-row recent sample. Refactor existing health
validation/dominance into shared internal functions rather than implementing a
second counter interpretation. Validate body identity and summary columns agree;
negative values and malformed JSON cannot be quietly filtered out.

### Snapshot and projection lifetime

A refresh acquires the existing collection shared lock, validates and captures
the manifest, and copies one consistent active-generation snapshot into an in-memory SQLite
database in short online-backup steps. Bound that
single journal by its existing 32 MiB profile, 100,000 attempt ceiling and 1,024
session ceiling. Parse typed row values from the memory copy; the live journal is no longer held
in a read transaction during row decoding. A busy or continuously changing source
may refuse refresh after five seconds. Cancellation is checked between 64-page
backup steps and parsed rows. The build must not hold a live-source read transaction while
waiting for a browser, sleeping, or awaiting another generation. SQLite lock
contention fails the refresh within the existing bounded busy interval; capture
callbacks still never wait on this process.

Process the sealed generations one at a time: verify the complete bounded file
hash, open read-only, validate binding/schema and stream typed rows. Check
cancellation between bounded row batches and generations. Hold the shared collection lock for the build: capture writers also take shared
locks and continue, while owner rotation refuses promptly until refresh is
cancelled or finished. Test that coordination explicitly. Do not mix generations
from two manifests. Rotation after publication leaves the prior result visibly
at its old frontier until another refresh. The active snapshot is identified by its
generation, sampled start/end times and a deterministic digest of the exact typed
rows used. That digest names a derived read selection, not a new authority or a
canonical evidence URI.

The published result is immutable and in memory. Normal `/api/status` polling
continues to read only active health; a small distinct overview endpoint returns
current build state and the last completed result. It performs no history scan.
A refresh request starts at most one background build; duplicate requests return
the existing job identifier. Cancellation drops unpublished work. A later refresh
replaces the published result only after all validation succeeds. Error state
must not conceal that the prior result predates the failed refresh.

### Whole-observation aggregation

Within one validated binding, the attempt ID is the deduplication key. A repeated
ID with a different observer is a conflict, not a new attempt. Equal observations
coalesce. A later observation replaces an earlier one only if it dominates under
the existing health contract: cumulative observed/queued/unconfirmed counters do
not regress and terminal status/outcome cannot change. Preserve the selected
whole row and its source generation; never manufacture a component-wise maximum.
An incomparable duplicate makes the projection invalid. Sum only the final
selected rows using checked arithmetic.

Reporter sessions retain ID, sampled update, dropped count and clean flag.
Duplicates must have nondecreasing cumulative dropped count and cannot reopen a
cleanly closed session. Wall-clock timestamps are presentation evidence, not a
sufficient ordering key. Generation order and compatible whole observations
select the retained value. Report telemetry totals as lower bounds because lost
health observations need not have been durably recorded.

Worker delivery state remains the active snapshot's sampled observation, with its
existing queue-lineage and timestamp semantics. Do not sum cumulative worker
failure or acknowledgment fields. Historical incompatible worker values remain
inspectable in their generation and must not be promoted to current liveness.

### Bounds and completeness

Use one background builder per Operations service, the existing maximum of
1,024 manifest generations and 32 MiB per source file, plus explicit ceilings of
250,000 distinct attempts, 65,536 distinct sessions and 128 MiB of accounted
working storage. Account payload lengths before retaining a new row; container overhead
also needs a conservative allowance. A build reaching any ceiling returns
`capacity-limited` and publishes no new whole-collection total. It names the
bound and processed frontier; it does not silently omit older history. These are
first-profile limits, not a guarantee that every legal 1,024-generation collection
fits. Larger collections still have paginated generation/history access; an
external-memory projection is a required later capacity extension if needed.

The 48-MiB working reserve leaves less than 80 MiB for rows, keys and source
metadata. A row is charged its serialized length plus 1,024 bytes. For
example, a 1,300-byte charge fits fewer than 64,528 simultaneously retained rows
before other charges; buffered active rows and deduplication entries can overlap.
The 250,000 identity ceiling is therefore not a promised practical capacity.
Actual capacity depends on row lengths, repeats and active/sealed overlap.

The result names included generations, sealed hashes, active snapshot digest,
build time, sampled window, deduplicated counts, and `observations-only` coverage.
A complete result means complete for those validated inputs, never complete raw
capture. Rotation/new writes do not refresh it automatically. UI must show
“sampled collection overview” and the separate current-generation health.

### Persistence and authority

An in-memory first implementation avoids adding a second on-disk truth source or
blocking on a durable cache design. No new file paths, SQLite projection tables,
WAL or plaintext temporary files are introduced. Any later persisted accelerator
must first extend `src/surface.rs`, `src/persistence.rs`, the fixture catalog and
`tests/surface_conformance.rs` with rebuild/poisoning/revocation behavior. It
cannot authorize reads, rotate journals or become an input to raw evidence.

## Resolved Questions
- This continues the already approved deduplicated-overview requirement; it does not replace the full frontend or the separate Library reader.
- Start with a bounded in-memory projection. Losing a derived overview on service restart is acceptable; losing source history is not.
- Exceeding the first profile limits is explicit incomplete capacity, never a fabricated collection total. No automatic retention or source deletion is introduced.

## Open Questions
No new owner preference is required for this read-only projection. Use the
existing shared collection lock for a build lifetime and the existing exclusive
rotation refusal; cancellation releases the build lock. Qualification must prove
that active capture still proceeds and no browser wait extends a SQLite read
transaction.

## Out of Scope
This work does not implement archive-wide evidence search, session normalization,
annotation signing, extraction jobs, admin execution, deployment or cutover. Those
remain required by `.design/kan-v2-human-frontend.md`. A durable external-memory
accelerator is a later capacity extension; this design explicitly discloses the
first profile's incomplete state instead of claiming unbounded aggregation.

## Process record
This is a continuation of the approved operations design, grounded in current
collection, journal and dashboard code. It is a build contract, not an implemented
feature or closed acceptance criterion. The existing two-withheld-claim/day
composition limitation still applies; Git records are preserved for later
backfill. No witnesses are invented for the deliberately unwitnessed maintenance
telos. The permanent worktree is `.worktrees/kan-v2-collection-overview`; no build
cache or `.lake` was created here.

Validation: `day design check` refuses this worktree because it has no private
kan workspace (known day#168 / kan#197); this is not an empty-claims result.
Read-only validation from the main checkout passes sections, seven requirements,
six criteria, mappings and placeholder checks. It warns that two branch-only
source paths are absent in the main checkout and that two claims are withheld.
Both named source paths exist in this branch. No claim-recording write was run.

## Build checkpoint

Implementation is in progress in permanent worktree
`.worktrees/kan-v2-collection-build`, branch `feat/kan-v2-collection-build`.
`evidence_operations::projection` reads complete typed rows inside one SQLite
read transaction; `evidence_operations_collection::overview` validates sealed
hashes, applies chronological whole-observation dominance and publishes a bounded
in-memory result. The active snapshot is read first and buffered within the same
memory budget, then applied after sealed generations so intermediate regressions
remain detectable. Existing recent-history behavior is unchanged.

The owner CLI is `kan-v2 ops-overview <collection>`. Dashboard endpoints are
`GET /api/overview`, `POST /api/overview/refresh`, and
`POST /api/overview/cancel`, with the same header bearer token, loopback and
origin checks as the existing operations surface. POST actions accept no body
and cannot perform owner rotation or erasure. A standalone journal cannot supply
a collection overview. Status reads only published memory; a previous successful
sample retains its original job and frontier during failed/cancelled refreshes.

Overview totals serialize as decimal strings, preserving every u64 digit in the
browser. Coverage is explicitly observations-only and capture completeness is
unknown. The source list includes sealed hashes and typed-row snapshot digests;
historical worker details remain in per-generation history rather than being
added or promoted to current health. The active worker sample stays with its
original active snapshot. Hashing streams 64-KiB buffers; the 128-MiB accounting
includes a 48-MiB allowance for the bounded in-memory active database, SQLite, manifest and transient buffers, conservative
per-row/container allowances, buffered active rows and retained source metadata.
Caller-specified test limits can only reduce the production ceilings.

The UI offers explicit load/build/cancel controls, keeps failed-refresh samples
visibly old, formats exact integer strings and clears results on lock. Rust and
browser checks for the initial checkpoint passed 58 Rust checks, 54 Node checks, strict v2 Clippy and six demonstrated negative controls. This was not the full AC-5 state matrix. The browser confirmed a deduplicated three-generation result, source disclosure, light/dark/mobile layouts and clearing on lock. Evidence is preserved in `.design/reviews/kan-v2-overview-author/`. The subsequent review and corrections are recorded below; no parent AC is marked complete.

### Review correction in progress

The cold review of 67c1263 reproduced health-writer failures during a large
active row scan and found Build/Cancel clicks discarded during in-flight polling.
The reviewer returned APPROVE WITH FOLLOW-UPS for the overview, with O1 a required code correction; the checkpoint is not merge-qualified. The separate a1007a6 storage correction round received APPROVE. Raw reports are retained unchanged under `.design/reviews/kan-v2-overview-opus/`. The correction copies active SQLite
pages into memory using short backup steps, releases live-source locks before
parsing, and preserves a five-second/cancellable refusal path for a busy source.
A fixed 32-MiB image allowance is added to the previous 16-MiB working reserve
inside the same 128-MiB ceiling. This conservative accounting means some formerly
accepted large inputs can return capacity-limited; it does not increase the limit.
Snapshot timestamps name the copy window, not the later parse. Copied schema and
control rows are revalidated. Build/Cancel preempt polls; actions remain serialized
and stale replies cannot overwrite newer action state. The corrected checkpoint passes 74 Rust checks, 26 Operations Node checks, strict Clippy and 13 semantic mutants; fresh re-review remains required.

The follow-up distinguishes file-lock and SQLite contention from invalid history.
The status API adds `active_generation` (null for standalone journals). The browser
compares that value with the cached sample and derives a superseded label; this is
not a new server publication state. It shows sample age and keeps prior-result
labels on failed requests. Age uses the browser clock and explicitly handles a
sample ahead of that clock. Restart responses clear stale displayed totals.

Coverage is deliberately split: the original real browser exercise covers completed
results and lock clearing in light/dark/mobile layouts. Node tests cover unavailable,
building, failed, capacity-limited, cancelled, cached/superseded and request races;
those tests do not close the full authenticated browser acceptance matrix. The
new HTTP socket regression checks eight held header requests, refusal of a ninth,
and permit reuse after completion. The 40,000-row active-source regression runs
100 real health writes during refresh. Qualification and fresh review of these
corrections must be recorded before closing their acceptance criteria.
