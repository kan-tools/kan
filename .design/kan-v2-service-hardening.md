# Feature: Incremental service audit and serialized admission fence

## Summary

Close the service review's F1/F2 follow-ups before relying on the ledger for capture: service responses must not certify a tip that hides an unverified raw append, and same-scope admission must not scan the entire commit index under the write lock. Preserve raw evidence and existing receipt/retry semantics.

## Requirements

- REQ-1: After authentication and authorization, validate every newly observed committed service record before returning a successful service response. Keep the audit frontier only in memory; restart revalidates all history. Historical records do not require current grants.
- REQ-2: Serialize append admission against the exact audited ledger frontier inside the existing immediate transaction. A concurrent append after audit causes a retryable conflict, including for exact retries. No automatic retry loop or unbounded lock-held signature audit.
- REQ-3: Replace the single-scope inequality scan with indexed range existence checks. Reuse the current schema and indexes; preserve single-scope admission and immutable receipts.
- REQ-4: Return corrupt for observed invalid retained service evidence, including missing referenced objects. Unauthorized requests still return access-limited without disclosing that state. Inventory responses cover a pinned audited prefix, not records arriving after that prefix.
- REQ-5: Preserve storage format, surface ownership, raw-ledger APIs, backup/recovery, delivery and resumable imports. Never repair, discard, or relabel raw evidence as a side effect of auditing.

## Acceptance Criteria

- [x] AC-1: A same-scope raw invalid record followed by a valid service-profile record cannot hide behind the latter tip: snapshot, page, read, append and exact retry fail corrupt, with retained bytes unchanged. Denied principals still see access-limited. (REQ-1, REQ-4, REQ-5)
- [x] AC-2: Multiple service instances observe each other's valid suffixes, preserve revoked writers' history, and preserve exact retry bytes. More than 128 newly observed records exercise audit pagination. (REQ-1, REQ-5)
- [x] AC-3: A storage test inserts a raw commit between an observed frontier and fenced admission, including stale retry and same-height wrong-tip cases; fenced writes fail without changing committed history. A refreshed frontier permits valid work. (REQ-2, REQ-5)
- [x] AC-4: Execute the production scope query on a large synthetic same-scope index, assert indexed range searches and a bounded SQLite VM-step count; lower and upper foreign scopes both conflict. A deliberate reversion to the original scan fails this witness. (REQ-3)
- [x] AC-5: A missing committed request object fails corrupt at restart and on direct retrieval after startup; reverting the missing-object error mapping fails the regression. (REQ-4)
- [ ] AC-6: Run service/store/delivery/import and surface checks, formatting and Clippy, then obtain a fresh actual Claude Code Opus 5.5 review of the published commit range. (REQ-5)

## Architecture

`src/evidence_service.rs` retains an in-memory `Snapshot` naming the last fully audited prefix. Each authorized dispatch captures a new ledger snapshot, validates its continuity with that prefix, and scans only the new suffix through bounded pages, requiring contiguous sequence numbers and valid signed request/manifest/receipt bindings. Publish the new in-memory frontier only after the full suffix succeeds. Snapshot and read use that pinned frontier; page requests cannot request beyond it. Selected returned records remain individually checked. A same-height tip change or retreat is corrupt.

`src/evidence_store.rs` adds `commit_partition_at` alongside the existing low-level partition method. Its exact `(sequence, CID)` comparison happens after `BEGIN IMMEDIATE` and before duplicate lookup or insertion. Any intervening commit yields conflict; callers retry the same signed bytes after another audit. A successful new service commit advances the in-memory frontier to its returned sequence/CID, since the service constructed and admitted that record inside the fence. An exact retry leaves the frontier unchanged. Staged objects may remain orphaned after a conflict, as in the existing profile.

The scope guard uses two indexed range-existence subqueries over the existing scope-leading unique indexes. It neither creates schema nor writes new artifacts; the existing typed ledger mutation capability in `src/persistence.rs` and the catalog in `tests/fixtures/read-write-surface.tsv` remain authoritative.

## Trust and limits

This addresses concurrent append through the supported `Ledger` APIs. It does not defend against an owner using arbitrary SQL to rewrite a previously audited prefix or replace the database beneath a live process. Startup still performs full ledger verification and a full service audit. The in-memory frontier is disposable and is never a persisted completeness certificate. Incremental signature verification moves backlog work outside the write transaction but is not a hard per-request time bound; a large newly appended backlog can take time. Full-history startup, production file custody, receipt/grant history, historical signature provenance, idle HTTP admission, 10/100-GiB qualification and operational cutover remain separate build points.

Existing wire error vocabulary is unchanged. An already observed mixed/invalid partition now returns corrupt even on exact retry (previously some paths returned conflict). A commit arriving after the captured read snapshot is outside that response; append observes it at the transaction fence. Valid concurrent service appends can therefore conflict even for different writers, and should retry exact bytes. No sleeps or automatic retries are introduced here.

## Open Questions

No new product decision is needed for this correction. The existing production key-custody/operating-profile choices remain pending and are not selected here.

## Out of Scope

Live data migration, main-branch merge, deployment, raw capture, owner erasure, durable audit caches and local Lean builds. Day claim/review backfill remains pending because the existing log read withholds untrusted claims; unavailable records are not treated as an empty telos set. The user's v2 continuation and this explicit design are the review target.


## Author validation

The integrated v2 run passed 119 tests across the twelve integration suites and
two unit tests (scope-query planner and spool quota), 121 total. All-target
`v2-crypto` Clippy, formatting and `git diff --check` passed. The new scope query
runs against 20,000 same-scope synthetic rows with two indexed searches and fewer
than 100 VM steps for each equality/foreign-direction probe; this is a regression
bound, not large-archive qualification. Three executed runtime controls killed
the original scope scan, disabled frontier fence and incorrect missing-object
classification. The day revert-demo algorithm also reverted both production
source files while retaining tests: the hidden-suffix regression failed at
runtime, then passed after byte-exact restoration. Fresh external review remains
pending at this implementation commit.

`day design check` passes structural checks when run from the original checkout,
with warnings for the two v2 source paths absent there and the two withheld
claims. Both source files exist in this permanent worktree. Running day directly
here still refuses the missing local kan workspace; no trust setting or claim
was changed to bypass that restriction.
