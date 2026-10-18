# Feature: Explicit journal capacity and retained generations

## Summary
Implement the remaining capacity and owner-rotation operations requirements from `.design/kan-v2-operations-polish.md`. Preserve every existing journal and expose observations honestly, separately from encrypted evidence capacity. This serves `telos/raw-data-and-projections`; operational summaries never certify complete capture.

## Requirements
- REQ-1: Read old standalone v1 journals without schema migration, and create v2 journals with reserved control capacity and a sticky exhaustion observation. Count limits, page use, persistence timestamps and lower-bound loss semantics are explicit.
- REQ-2: Continue inference/delivery when status writes fail. Exhaustion never clears through restart or a later heartbeat; owner rotation selects a fresh generation. Whole-device failure can still prevent recording and must remain unknown.
- REQ-3: Adopt journals by verified copying into a new owner-only collection; preserve the source byte-for-byte. All upgraded collection readers/writers hold a shared lifetime lock; rotation requires a nonblocking exclusive lock and stopped older binaries.
- REQ-4: Rotate through unique staged journals and an atomically published versioned manifest. Retain sealed generations with verified hashes/bindings, reject conflicting or unsafe paths and recover without treating unreferenced files as committed history.
- REQ-5: Expose active generation status and explicitly paged historical snapshots. Do not add cumulative snapshots across generations as if they were disjoint raw events. No live polling scans the whole retained collection.
- REQ-6: CLI and read-only dashboard share the new versioned status contract. Display journal capacity separately, preserve privacy boundaries, and leave rotation execution to the owner CLI until the separately authorized admin API is implemented.
- REQ-7: Catalog every new persisted surface and verify exhaustion, compatibility, interrupted rotation, locking and preserved evidence with synthetic fixtures and fresh Opus 5.5 review.

## Acceptance Criteria
- [ ] AC-1: Open v1 without changing its bytes; v2 survives actual SQLITE_FULL with retained attempt history, a sticky exhaustion marker and usable reserved metadata space. Verify independent attempt/session limits and lower-bound semantics. (REQ-1, REQ-2)
- [ ] AC-2: Missing, denied and locked status storage never stops capture/delivery; versioned CLI/UI reports stale or unavailable evidence rather than precise completeness. (REQ-2, REQ-6)
- [ ] AC-3: Adoption preserves source hash, owner permissions and binding; rotation refuses active writers, symlinks, reused paths, unknown manifests and conflicting history. (REQ-3, REQ-4)
- [ ] AC-4: Inject interruption before/after sealing and manifest publication. Reopen deterministically selects the committed generation; old bytes and historical snapshots remain readable, staged files remain unselected. (REQ-4, REQ-5)
- [ ] AC-5: Active polling visits only the selected generation; historical pages name their scope and cannot be mistaken for deduplicated whole-collection totals. Duplicate attempt/session identities never produce a false summed total. (REQ-5)
- [ ] AC-6: Test capacity, exhausted, unknown/legacy and incompatible status in the real client; preserve authentication/Host/Origin/CSP and browser memory-only token behavior. Review the layout at desktop/mobile. (REQ-6)
- [ ] AC-7: Surface catalog, capabilities and conformance tests cover collection manifest, generations, temporary files and lock. Independent review and real reversion evidence accompany corrections. (REQ-7)

## Architecture
The standalone reader in `src/evidence_operations.rs` accepts exact schema v1 or v2. New v2 adds a preallocated control row with 256 KiB of reserve, the last successful persistence timestamp and sticky exhaustion. On a record capacity failure, a separate transaction releases reserve and sets the sticky marker; later attempt writes are refused. Reporter/worker metadata can use the finite freed pages, but whole-device failure and session exhaustion remain possible. Every reported loss count is a lower bound, including legacy values. No exactness is inferred from a successful read. v1 is not rewritten or silently adopted.

Journal connections hold an advisory shared lifetime lock on a private `.lock`
sidecar, and maintenance takes it exclusively. This is a separate inode because
flock and SQLite's fcntl locking interact on macOS; locking the SQLite inode
blocked ordinary writes in the first test run. Lock files carry no evidence and
are retained coordination artifacts; old binaries still require explicit stop.

A versioned collection module will resolve one active generation from an owner-only manifest, taking a shared lifetime lock before reading it. Rotation takes the same lock exclusively, validates all existing membership and selected bindings, creates/fsyncs a unique empty v2 journal, preserves the old file under its existing name with a sealed hash, then publishes a new manifest using a unique write-new temporary file, rename and parent-directory fsync. Failed publication leaves the prior manifest authoritative; successful publication names the new active generation. No generation is deleted or renamed under an open writer. The collection path itself is never a symlink. A malformed or unsupported manifest is an error, not a request to scan filenames and guess.

Adoption uses an SQLite-consistent verified copy under exclusive source ownership for upgraded clients; the runbook also requires stopping older binaries, which cannot participate in the new locking protocol. It does not mutate the source. History is accessed by named immutable generation with a matching manifest hash. Active snapshots remain bounded to one generation; the UI labels this scope. Until a rebuildable, deduplicated overview is implemented, no collection-wide additive total is exposed. That overview remains required by the parent design before its full completion claim.

`src/bin/kan-v2.rs` will expose owner adoption/rotation/history commands. The existing dashboard remains read-only and consumes the same status object. Owner-triggered browser execution is part of the later full frontend admin plan/job boundary, not granted to the dashboard token.

## Open Questions
The authorized reader deployment remains open in the full-frontend design. It does not affect journal capacity or rotation. No product decision is needed to implement the finite reserve, locking and publication protocol; their correctness is an engineering obligation.

## Out of Scope
- Automatic expiration, deletion, live-user adoption, deployment, main merges or production credential use.
- Claiming full operations completion before the bounded deduplicated overview, or full frontend completion before real reader, annotation, analysis and admin workflows.

## Process record
The main bulk kan read still withholds two claims. Worktree day commands refuse to infer an empty workspace; no kan/day writes or fabricated witnesses are used. Git-first design/review backfill follows the standing user decision. Parent correction fcd8c6f received APPROVE WITH FOLLOW-UPS; its follow-up correction 68acb0e is under a second fresh independent Opus 5.5 review. This child remains preparatory until that verdict is resolved. No heavy job runs here during the parent review.

## Operations interaction completion in this slice
The parent design already requires bounded recent-attempt search, metadata
inspection, identifier copying and focus-safe polling. This slice implements them
on the real status client, with native modal focus, explicit sample scope and
lock-time clearing of private DOM contents. The shared theme remains System by
default. Browser evidence is retained under `reviews/capacity-browser/`; it uses
the production assets with a synthetic API and is not a backend verification.
