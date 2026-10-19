# Feature: create and restore retained recovery bundles

## Summary
Continue the approved KNB1 design with owner-side physical creation and restoration. A stopped or pinned profile-2/3 source becomes a new retained bundle; restoration appends verified ciphertext and its signed observation together. The original source, member evidence and previous observations remain unchanged. This is a dependent implementation plan, pending the physical-reader review; it does not report these APIs as implemented.

## Requirements
- REQ-1: Before opening any SQLite participant, check source and destination main/sidecar custody and collisions using the existing evidence-store conventions. Creation exclusively reserves a new private file; neither retry nor error overwrites an existing output.
- REQ-2: Acquire the exact canonical metadata, proof bytes, original plan/membership and every bounded original object from one source snapshot. Validate independently supplied archive/scope/issuer/profile and selected metadata frontier. Ignore repairable derived columns, but refuse unknown schema, malformed physical types, extra proof coordinates, noncanonical keys and oversized cells without silently omitting them.
- REQ-3: Construct the created event and exact initial loss partition from the verified member. Commit the complete member, history and KNB1 markers together, then synchronize the file and parent and independently reopen before returning success.
- REQ-4: Restoration requires the owner-pinned observer and exact latest checkpoint under a write transaction. Verify candidate membership, length, CID, and referenced writer signature/binding before signing. Append candidate and observation atomically; never modify original rows or old observations. An exact repeat is idempotent and reports its original observation without appending another.
- REQ-5: Enforce explicit acquisition, semantic-work, item, time/cancellation and output-size limits. Limits do not introduce a universal archive-size ceiling. Preserve failed output artifacts and distinguish pre-commit refusal from an outcome uncertain after commit.
- REQ-6: Extend typed mutation capabilities and the independent persistence catalog with the implementation. Exercise abrupt process death, source invariance, stale checkpoint/concurrent writers, invalid candidates and standalone refusal, and obtain fresh actual Opus review.

## Acceptance Criteria
- [ ] AC-1: Profile-2, complete profile-3 and partial profile-3 sources with missing, corrupt, empty and staged originals produce independently verifiable bundles with byte-identical metadata and retained originals; source physical-format violations refuse. Independently generated commitments and loss histories match. (REQ-2, REQ-3)
- [ ] AC-2: Source/output main and sidecar aliases, preexisting outputs, wrong owner pins, stale selected frontier, invalid observer and cancelled/insufficient budgets refuse without rewriting source or an existing output. Checks precede SQLite opens and repeat when reserving the output. (REQ-1, REQ-2, REQ-5)
- [ ] AC-3: Restoring a valid missing/corrupt request appends one candidate and one observation; invalid signatures, valid signatures with wrong manifest binding, foreign CID, wrong length and stale checkpoint refuse. Exact retries do not duplicate history, including after a lost response. Two writers cannot both append from the same expected checkpoint. (REQ-4)
- [ ] AC-4: Kill child processes at output reservation, row insertion, initial-history insertion, marker publication, commit, synchronization and successful reopen; repeat at candidate insertion, observation insertion and restoration commit. Reopening yields an unrecognized retained output, the prior valid bundle, or the complete new state. No half-restoration, recognized incomplete bundle or false completed response occurs. (REQ-3, REQ-4, REQ-5)
- [ ] AC-5: Independent SQL inspection and bundle replay reproduce every authoritative byte; ordinary standalone APIs continue refusing even fully restored bundles. Typed capabilities, independent surface inventory and selected semantic controls fail on actual mutation-boundary weakenings. All affected tests, strict lint and fresh review pass with failures/survivors preserved. (REQ-6)

## Architecture
Use `src/evidence_store/bundle.rs` for bounded KNB1 acquisition, sharing a private owned snapshot representation with mutation entry points rather than returning unverified rows publicly. Refactor acquisition only under unchanged reader regression coverage. `src/evidence_recovery_member.rs` remains the logical source verifier; `src/evidence_recovery_replay.rs` remains the complete observation-history verifier. `src/evidence_recovery_observation.rs` supplies the existing signature domain and codec. No new observation event or schema field is introduced.

Creation reads standalone profile-2/3 schemas from `src/evidence_store.rs`, `src/evidence_store/attested.rs` and `src/evidence_store/copied.rs`. It cannot use normal full-payload verification as its opener because missing/corrupt payloads are the intended input. It still validates all raw metadata/proof coordinates and exact existing schema. Source snapshot acquisition and all output path checks precede any mutation. The caller supplies the selected metadata frontier from an independently verified owner inventory; creation rejects a different frontier rather than silently changing the selection.

Use existing `sqlite_destination`/private-file checks, exclusive owner-only reservation through `src/persistence.rs`, DELETE journaling and FULL synchronization conventions. Set bounded SQLite page growth for the output and document its relation to main-file, rollback-journal and transient allocation; a sampled file-size check alone is not a disk quota. A filesystem stall cannot be preempted by the deadline. No simultaneous heavy jobs or large dependency installs are needed for qualification.

Creation first audits the source member and prepares the complete initial observation chain. It verifies the proposed history before publishing the bundle marker in the transaction. A failure retains the new file, including its sidecars if needed; it does not remove or relabel a potentially committed result. Success requires synchronization and a fresh read-only inspection using the exact resulting checkpoint. The caller retains this checkpoint separately for rollback detection.

Restoration takes a complete expected checkpoint, not merely a path or a previously returned Inspection. BEGIN IMMEDIATE and bounded acquisition establish the current bundle snapshot before accepting the transition. A same-bytes retry with an already-recorded restoration may succeed without an append only when the requested checkpoint is present and the original observation/candidate is verified; it returns the actual current checkpoint and original restoration identity. A stale request for a new transition refuses. This makes the retry exception explicit instead of disabling compare-and-append generally. Source keys and original/member tables are never updated.

Candidate validation must be shared with replay so that a newly signed restoration cannot precede writer verification. Existing signatures are reverified from retained raw bytes. The candidate and observation become visible in one transaction; any error after commit is an uncertain operation until a subsequent explicit inspection/retry proves the result. A completed restoration is never publication or live-writer activation.

## Resolved Questions
- The next mutation implementation follows the existing retained-bundle contract and seven-table schema; it adds no new wire format.
- Owner-selected checkpoints and source frontiers are mandatory mutation preconditions; a path is routing information only.
- Exact restoration retries can resolve an earlier uncertain outcome without appending duplicate attribution; other stale transitions refuse.
- Invalid physical source cells require retained forensic handling; no successful bundle or guessed repair is reported.

## Open Questions
No new product preference is required. Implementation findings that change protocol or authority semantics must return to the governing design rather than silently narrowing it.

## Out of Scope
This checkpoint precedes separate publication, bundle-aware backup/rebuild, durable owner jobs, RPC and human recovery controls. Those remain required by the parent design. It does not close full recovery/frontend acceptance criteria, activate a writer, migrate live archives or authorize deployment.

## Process record
Continuation of `.design/kan-v2-recovery-bundles.md` and `.design/kan-v2-recovery-bundle-opening.md`, following the user's approved build sequence and fresh-review standard. Git-first documentation remains necessary while day#168/kan#197 prevent reliable worktree-local recording; no live-log read, invented witnesses or restored excluded claims are asserted. Backfill into kan remains required after the recording boundary is repaired. This draft must be validated with day and independently reviewed with the implementation; hand counting is not represented as tool validation.

Validation attempt: `day design check .design/kan-v2-recovery-mutations.md` returned exit 2 with the explicit worktree-without-kan-workspace refusal (day#168 / kan#197). This is unavailable validation, not a passing design check. No redirection to the main checkout or log mutation was attempted.

## Reader review obligations carried into mutation work

Opening review A-F6/A-F7 requires explicit KNB1 refusal tests for root-based
Ledger/Archive opens and inventory/source/copy-upgrade entry points, preserving
the bundle when an opener requests READ_WRITE before checking its profile. The
reader checks final path components and mutual participant aliases; it permits
symlinked parent directories and extra hard links elsewhere. The writer must
perform all-participant namespace and inode checks before SQLite opens, and
must not present those existing checks as a hostile path-replacement fence or
a promise that no other hard link exists. These remain mutation qualification
obligations, not properties established by read-only inspection.


## Creation draft under implementation
The first mutation slice is `bundle::create`/`create_observed` in `src/evidence_store/bundle/create.rs`. It acquires profile2/3 raw bytes in one read transaction, checks the selected frontier, constructs and replays the initial signed loss history, exclusively reserves a new output and commits member/history/markers together. After commit begins, failure carries the expected checkpoint as an uncertain outcome. Files are synchronized and independently reopened before success. The source and failed output remain retained. The creation result does not activate a writer.

The draft exposes an explicit main-file page ceiling and names rollback-journal/RAM overhead separately; it does not promise a whole-filesystem quota. Acquisition counts include newly constructed history. Each semantic audit/replay is bounded by the configured replay limits, with a shared overall deadline and cancellation flag; the combined CPU/byte pass count is a fixed multiple of that per-pass ceiling, not an exact RSS measure. Reopen uses the output-size allowance and the remaining deadline. Tests drafted for loss preservation, physical types, pins/frontier, all-participant aliases, cancellation/outcome uncertainty, source invariance and abrupt process death at eight boundaries. Compilation, behavioral controls, independent oracle comparison and fresh review are pending. Restoration/publication/jobs/RPC/UI remain required next slices.

Restoration follow-through must reuse the replay candidate validator rather than
signing first and asking replay whether the claim was true afterward. Extract the
existing membership/length/CID/writer-binding checks behind a bounded private
helper and retain all existing hostile candidate controls. Under `BEGIN IMMEDIATE`,
acquire and replay the exact bundle again with the caller's external checkpoint.
Only an existing verified same-bytes restoration may resolve an older checkpoint
as an idempotent retry; a new transition requires equality with the latest
checkpoint. Return the original restoration observation and the actual latest
checkpoint for a retry, not a newly signed claim. Candidate insertion and its
observation share one transaction; uncertain commit results retain the intended
checkpoint. Publication and writer activation remain distinct subsequent actions.

The current worktree's repeated `day design check` still returns exit2 for the
shared-workspace refusal. The diagnostic is preserved locally; it is not counted
as successful validation and was not redirected to the main checkout's log.

## Creation author qualification — 2026-10-19

Source22002e7 passes70 selected integration checks (including ten creation
checks and eight abrupt-death boundaries), strict all-target v2 lint and format.
The SQL/history oracle and seven compiled mutation controls pass with restored
source identity. Evidence is in`reviews/kan-v2-recovery-creation-author/`.
Initial fixture and lint failures remain recorded. Fresh Opus review is pending;
restoration/publication/full recovery acceptance remain open. Remote performance
generation exposed an unresolved legacy claim-codec canonicality refusal;
it is not represented as a passing scaling result.
