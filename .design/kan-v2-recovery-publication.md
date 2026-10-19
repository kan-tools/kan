# Feature: publish a complete output from a retained recovery bundle

## Summary
Continue the reviewed KNB1 protocol after physical creation and restoration. An
owner selects a bundle checkpoint, attempt ID and new destination. Publication
records intent, builds and verifies a separate complete standalone archive, then
records the durable observation. The bundle and unsuccessful outputs remain
retained. Completion never switches the service's live writer.

This is an implementation plan, not delivered functionality or a closed parent
acceptance criterion. It uses the frozen events, R1/O1 framing and historical
selection in `kan-v2-recovery-bundle-codec.md`; no new wire schema is proposed.

## Requirements
- REQ-1: Require independently retained bundle context/checkpoint, matching observer, owner-selected attempt ID and destination. Validate all SQLite participants and collisions before opens. A path is routing data, not authority.
- REQ-2: Reacquire and replay the entire bundle under a bounded write transaction. A new attempt requires the exact latest checkpoint. Compute and verify the deterministic complete output and R1 before signing its intent. Incomplete profile-3 metadata or any unavailable required original/staged/orphan key blocks publication.
- REQ-3: Durably record intent before reserving a new output. Select only restorations preceding that intent. Keep output markers transactional with complete rows and verification. Preserve original canonical metadata/proofs/plan/membership and derive lookup columns from those bytes.
- REQ-4: Independently verify the normal standalone profile, writer signatures, issuer proof chain, copy completion and exact O1. Synchronize output and parent before appending publication-observed. Reinspect the bundle's resulting checkpoint before reporting completion.
- REQ-5: Resume the exact existing attempt explicitly, using its historical selection. Never overwrite an existing destination. Reverify an existing complete output against that attempt. Preserve failed artifacts and uncertain outcomes across both database commits; do not infer completion from a filename or a valid output alone.
- REQ-6: Keep publication-failed as an attributed unsuccessful check, not proof of output absence. An explicit resume may append observed after failure; no event follows observed for the same attempt. Preserve idempotent completion checks without signing duplicate observations.
- REQ-7: Bound acquisition, work, pages, cancellation and total elapsed time, including both databases. Extend typed persistence capabilities and the independent call inventory. Qualify crash windows, semantic controls, independent output comparison and fresh actual Opus review.

## Acceptance Criteria
- [ ] AC-1: Complete profile-2 and profile-3 bundles publish independently valid outputs with exact original metadata/proofs/plan/membership and deterministically selected objects. Partial profile-3 and missing/corrupt required staged/orphan objects refuse before intent. (REQ-2, REQ-3, REQ-4)
- [ ] AC-2: Wrong pins/observer/checkpoint, reused attempt with incompatible intent, participant aliases, preexisting conflicting output and exhausted budgets refuse without rewriting authoritative evidence. No output is created before a durable intent. (REQ-1, REQ-2, REQ-3, REQ-7)
- [ ] AC-3: Later restorations do not change an earlier intent's R1/O1. Explicit resume after a failed check verifies the same output selection. Exact retry after observed returns the original attribution and current verified checkpoint without appending again. (REQ-5, REQ-6)
- [ ] AC-4: Abrupt process death before/after intent commit, file reservation, row insertion, output verification/commit/fsync/reopen, and observed commit/fsync/reopen leaves an honest retained state. A valid output with pending intent never returns completed recovery. (REQ-3, REQ-4, REQ-5)
- [ ] AC-5: A complete output independently passes ordinary profile checks and exact O1; a substituted valid archive, modified proof, added object, missing object, changed plan or later candidate is rejected. The source bundle/member/history remain byte-identical except for the prescribed appended observations. (REQ-3, REQ-4, REQ-5)
- [ ] AC-6: Compiled controls detect missing intent, premature observed, skipped ordinary verification, stale selection, overwritten history and profile downgrade. Affected tests, strict lint, independent oracle and fresh Opus review pass with failures and survivors retained. (REQ-7)

## Architecture
Implement a dedicated `src/evidence_store/bundle/publish.rs`. Share bounded
physical acquisition and mutation setup with restoration only after extracting
those helpers under unchanged tests. Keep public results distinct: a verified
bundle inspection, a durable intent checkpoint, a physically verified output,
and an observed completed publication are different values.

`evidence_recovery_replay::output_commitments` already computes historical R1
and O1 during replay. Add a bounded crate-private preparation helper that uses
the same audited member/key/candidate logic and returns the deterministic
selection for either a new attempt or a specified retained intent. It must not
accept an unsigned caller-provided candidate subset. For resume, reconstruct
candidates strictly before that intent, then verify the resulting R1/O1 against
its signed bytes. Full replay still checks all later history.

New-intent processing holds BEGIN IMMEDIATE only while acquiring, checking and
appending intent. Commit, synchronize and independently reopen that checkpoint
before allocating the output. Release the bundle write lock during output work.
Later append operations reacquire and replay the current bundle, establish that
the original intent is still retained and unchanged, and append to its current
head. Later restorations or unrelated attempts may advance that head; they do
not change the selected output. A new attempt still requires exact latest-head
agreement. No unbounded lock covers a separate output build.

Use `RecoveryReader::rebuild_with_plan` as a reference for ordinary derived
columns and full profile verification, not as an opener for the bundle. Bundle
rows cannot be exposed as standalone or passed to an API that assumes missing
payloads were already verified. Build the ordinary output in one transaction
from the authenticated owned selection, including exact issuer proofs and
original copy inventory. Verify contents and profile before the transaction
publishes recognizable markers. Reopen through the ordinary profile verifier,
then recompute the output commitment from the actual retained output bytes;
matching a count/frontier alone is insufficient.

An output that exists on resume is never overwritten or automatically deleted.
A fully verified matching output may be synchronized and observed. An incomplete
or conflicting output remains retained and requires a new owner-selected path
and attempt, or a separately authorized forensic operation. This plan does not
introduce automatic cleanup or a file-repair guess.

After output verification, reacquire the bundle and append publication-observed
using its existing intent and selected O1/frontier. Validate the proposed whole
history before commit. An existing observed result is an idempotent lookup only
after checking the actual current output; a historical observed claim does not
prove that today's file still exists. Report the original observation and the
latest independently verified bundle checkpoint.

Return explicit phase and retained paths/checkpoints on any error after intent
commit is attempted. A failure during final observation commit remains uncertain
even when the output is valid. Do not hide a second failed append while trying
to record the first failure. Provide an explicit bounded owner operation for
publication-failed using the existing closed reason enum; failure attribution
never removes the intent or asserts that an output is absent.

The main-file ceilings cover the bundle and output separately. Rollback journals,
owned snapshots and filesystem stalls need separately documented limits; elapsed
time is checked between filesystem calls, not described as preempting blocked
kernel I/O. Reuse DELETE journaling/4096-byte pages and private participant checks
from the initial writer. Do not claim protection against hostile replacement of
parent directories after those checks.

## Backup and rebuild follow-through
A separate bundle-aware backup API copies one consistent entire outer database,
preserving bundle ID and every member/candidate/observation byte, then independently
verifies the caller's pinned checkpoint. A logical bundle rebuild recreates the
same seven tables and all authoritative bytes in a new outer KNB1 database;
missing original bytes remain missing. Neither operation emits a new observation
or falls back to standalone recovery. They require their own custody, crash,
resource and history-omission tests. Future writes to multiple copies require
explicit owner selection of one history writer; no automatic merge is implied.

## Process and boundaries
The source references were inspected against the restoration candidate6a09d6e.
Implementation waits for the current Content/creation review and restoration
qualification so corrections propagate before another dependent checkpoint.
Git-first documentation continues under day#168/kan#197, without live-log access,
invented witnesses or reconstructed excluded claims. `day design check` was attempted and refused the worktree without its own
kan workspace. The diagnostic is retained in `.local-state/publication-design-check.txt`;
this is unavailable validation, not a passing check. No main-log redirect occurred.

Remote APIs, durable owner jobs, human recovery controls, backup placement and
writer cutover remain subsequent slices of the approved full frontend roadmap.
No live archive, keys, migration, installation or activation is authorized by a
passing development publication test.
