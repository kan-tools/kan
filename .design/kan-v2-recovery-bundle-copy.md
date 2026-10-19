# Feature: back up and rebuild a retained recovery bundle

## Summary
An owner must be able to copy a recovery bundle without turning its incomplete
original member into a supposedly complete archive. Provide two explicit local
operations: a consistent physical SQLite backup and a logical rebuild of the
same seven-table KNB1 bundle. Both preserve bundle identity, original bytes,
candidates and every observation. Neither signs a new event or activates a writer.

This continues the backup/rebuild requirement in recovery-publication and the
retain-until-explicit-erasure policy. It does not install a backup service or
access live archives. Publication and bundle copying remain distinct operations.

## Requirements
- REQ-1: Require owner-supplied context and an independently retained checkpoint. Validate all source/destination SQLite participants, private-file custody, aliases and output exclusivity before opening or reserving. No overwrite or automatic failed-artifact deletion.
- REQ-2: Acquire one source snapshot and fully replay its original member, restorations and observations with the external checkpoint. Copy that snapshot's entire history, including valid events after the supplied checkpoint. Do not substitute a later snapshot between inspection and copy.
- REQ-3: Physical backup copies the entire outer database using bounded SQLite backup steps. Logical rebuild reproduces all seven tables and every authoritative cell under the exact supported schema. Missing original objects remain absent; empty/corrupt original bytes remain exact. No standalone fallback, omission of failed attempts or candidate/history cleanup.
- REQ-4: Keep recognizable profile markers transactional with complete rebuilt contents. After copying, synchronize the new file and its parent, independently reopen and replay the destination, and compare its complete logical cell inventory plus selected latest checkpoint against the captured source. A matching head alone is insufficient evidence of a complete copy.
- REQ-5: Bound source/sidecar size, acquired bytes/items, replay work, output pages, cancellation and elapsed time. Document temporary-memory and rollback-journal overhead separately; do not promise to preempt arbitrary filesystem stalls. Failed or uncertain copies remain visible and retained.
- REQ-6: Extend the typed persistence capability and independent catalog/call inventory. Qualify live source appends, both supported source profiles, missing/corrupt evidence, complete historical restoration/publication states, crash windows, output substitutions and semantic controls. Obtain fresh actual Claude Code Opus5.5 review before acceptance.

## Acceptance Criteria
- [ ] AC-1: Both modes preserve exact identity, plan, membership, records/proofs, original object cells, candidates and observations from one verified snapshot, including unavailable evidence and failed/observed publication history. The original is unchanged. (REQ-2, REQ-3)
- [ ] AC-2: Wrong pins, missing retained checkpoint, unknown schema, participant aliases, unsupported journal modes and conflicting output refuse before mutation. A late source append cannot appear in only part of the copy. (REQ-1, REQ-2)
- [ ] AC-3: Successful return follows independent destination replay and full logical-content comparison; truncated history, omitted candidates/originals, changed plan/membership or a substituted valid bundle is rejected. No signing or writer activation occurs. (REQ-3, REQ-4)
- [ ] AC-4: Abrupt death and cancellation at reservation/copy/verification/commit/sync/reopen phases leave either an unrecognized partial artifact or a complete inspectable bundle, without a false success report. Exact source and failed artifacts remain retained. (REQ-4, REQ-5)
- [ ] AC-5: Page/item/byte/time budgets have targeted checks; compiled fault controls kill omitted-table/history, skipped external pin and skipped destination-comparison mutations. Affected tests, strict lint, independent oracle and fresh review pass with failures retained. (REQ-5, REQ-6)

## Architecture
Implement `bundle::backup` and `bundle::rebuild` as owner-side APIs returning a
verified destination inspection plus the captured source checkpoint. The APIs
use a destination path, not a service root, and cannot become admission openers.

For physical backup, hold a read transaction on the source through replay and
SQLite backup steps. Validate the captured page count against the output ceiling
before copying; the backup operation must not silently replace a page limit by
copying a larger source header. Check cancellation/deadline between bounded steps
and install SQLite progress/busy limits. Restrict supported journal/page modes
explicitly. Any normalization of a new backup's coordination mode occurs on the
new artifact only and precedes final verification.

For logical rebuild, use the bounded owned acquisition shared by inspection and
restoration. Preserve every exact cell and the exact latest authenticated history
from that acquisition. Insert all seven tables and supported markers in one
transaction. Derived SQLite storage details may differ; authoritative values may
not. This is not a reconstruction from only successful events or a lossy export.

After either mode, independently acquire the destination and compare every
logical row/byte with the captured source, as well as replaying its pinned
history. Comparison is bounded by the same item/byte ceilings. Keep the original
snapshot alive until its required source evidence is owned or copying completes.
Return explicit uncertainty once a durable-copy commit has been attempted.

Multiple retained copies have the same bundle identity. The owner must choose
one history writer before any later restoration/publication; no automatic merge,
lease or divergent-history repair is introduced. Backup placement, encrypted
remote backup transport and the human owner-job interface are subsequent layers.

## Process
This design is prepared alongside publication draft309. Implementation has not
started, and all acceptance criteria remain open. Git-first recording continues
under day#168/kan#197; the worktree has no independent live kan workspace. Prior
checks in this branch family refused that configuration. No log redirect,
reconstructed excluded claims or invented witnesses are used. The actual parent
review remains in its isolated export and cannot be modified by this worktree.
