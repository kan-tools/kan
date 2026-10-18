# Feature: Reliable operations history and the technical studio console

## Summary
Close the six follow-ups from the operations correction review, then supply the operations area of the full Kan front end as a compact technical studio: light surfaces, strong typographic hierarchy and an electric blue accent. Current service observations and retained historical gaps remain separate judgments. This serves `telos/raw-data-and-projections`: operational summaries never become proof of raw-evidence completeness.

This is a design, not an implemented correction. It starts from operations commit `0729bbb250da61c26db17c25cc17ed7793329554`, draft #279. The full-app interactive artifact under `.design/kan-studio/` uses synthetic data and no service connections. The broader product design is `.design/kan-v2-human-frontend.md`.

## Requirements
- REQ-1: Preserve worker acknowledgment history and cumulative telemetry failures when health storage becomes available after startup, including contention on the first history read. Delivery remains independent of journal availability and sends only retained archive requests.
- REQ-2: Expose health storage capacity, successful persistence freshness, and counter certainty independently of capture-spool capacity. Full, missing, invalid and locked storage must not silently render as healthy or as a precise zero-loss count.
- REQ-3: Provide explicit owner-triggered journal rotation that retains prior journal bytes and readable history, refuses concurrent writers, and recovers from interrupted publication without dropping records or selecting an unverified generation. No automatic expiration or deletion.
- REQ-4: Replace the FIFO health handoff with bounded coalescing of cumulative snapshots per attempt. Callbacks remain nonblocking; coalescing does not erase a recording gap, terminal observation or loss disclosure. Distinct-attempt overflow remains bounded and visible.
- REQ-5: Distinguish fresh active reporters, stale unclosed reporters, clean closed reporters, and absent reporters. Current-service status and retained coverage gaps are independent; a currently fresh service can have historical gaps.
- REQ-6: Promote recovery and binding probes into mandatory regression tests; demonstrate the Linux global-admission negative control fails at the named assertion, not because of a compile error, timeout or unrelated failure.
- REQ-7: Deliver the responsive operations area of the full Kan console with light neutral surfaces, electric blue interaction accents, compact metrics, a delivery summary, separate queue/journal capacity, searchable recent attempts and a metadata inspector. No decorative charts imply unrecorded time-series data.
- REQ-8: Preserve the existing loopback, bearer authentication, Host/Origin, CSP, no-store and memory-only token boundaries. The production UI and CLI consume one versioned status contract; the first operations-only integration keeps read-only rotation guidance. The complete frontend adds owner-authorized rotation through a separate admin plan/job API, never through the read-only operations token.
- REQ-9: Verify keyboard operation, visible focus, semantic labels, contrast, narrow layouts, long identifiers and status transitions. Motion must respect reduced-motion settings and never suggest network activity unsupported by observations.
- REQ-10: Keep all new persisted operational fields and rotation artifacts in the persistence surface catalog. Compatibility is explicit; old journal files remain readable, and unsupported collection versions fail visibly without modifying them.

## Acceptance Criteria
- [ ] AC-1: Start with stored acknowledgment position 41 and seven failed telemetry writes; make the journal absent or locked at worker startup, deliver new records, restore access and verify history merges once without a decreasing failure count or replacing a newer acknowledgment. Repeat restart and snapshot-read failure. Revert the production correction and observe the named failure. (REQ-1)
- [ ] AC-2: Exercise real SQLite page exhaustion, attempt-count exhaustion, denied writes, lock contention and missing storage. The API/CLI/UI distinguish their observations or honestly report unknown; lost-update values carry exact/lower-bound/unknown semantics. Inference and archive delivery remain available. A full journal cannot persist a false "healthy" marker after recovery. (REQ-2, REQ-5)
- [ ] AC-3: With writers stopped, rotate a full journal and verify byte hashes, bindings, unique generation membership, no erased records and readable pre/post history. Inject crashes at staging, sealing, manifest publication and reopen. Refuse active writers, reused output paths, conflicting bindings, symlinks and malformed manifests. Duplicate attempts/sessions across generations are counted once. No live-user journal is used. (REQ-3, REQ-10)
- [ ] AC-4: Flood one attempt with cumulative snapshots while the writer is paused; after recovery its final summary is retained. Flood more distinct attempts than capacity and observe explicit lower-bound loss without blocking callbacks. Interleave stale and terminal snapshots and verify counters and outcome do not regress. Memory stays bounded under a long run. (REQ-4)
- [ ] AC-5: Render a state matrix covering fresh operation with/without retained gaps, no reporter, stale reporter, clean stop, retrying delivery, exhausted journal, failed fetch, empty activity and incompatible status version. Fresh reporters do not create an unclean-exit warning; old gaps do not disappear on recovery. Unsupported live data is not replaced with zeros. (REQ-5, REQ-7, REQ-8)
- [ ] AC-6: Mandatory tests kill the lazy reporter binding/loss mutants, worker-history and worker-failure UI mutants. Linux CI establishes a passing baseline, changes the global pending limit to 64 in an isolated export, records the specific 32-limit runtime failure, restores and passes. Near-equivalent queue-check mutations are labeled accurately. (REQ-6)
- [ ] AC-7: In an actual browser, verify recent-list search/filter, row inspection, full identifier copying, state badges, timestamps and retention guidance using synthetic fixtures at 1440px, 768px and 390px. Controls with no implementation are absent; historical lists are explicitly bounded. No horizontal document overflow at 390px; dense tables may scroll within their labeled region. (REQ-7, REQ-9)
- [ ] AC-8: Verify existing HTTP/security regression tests still pass; browser tokens remain memory-only and lock clears private rendered data. Keyboard-only operation reaches every control, inspector close restores focus, live announcements do not repeat every poll, and production assets request no external fonts/scripts. (REQ-8, REQ-9)
- [ ] AC-9: Surface conformance covers every new file/field and permission boundary. Old standalone journals open without mutation; conversion copies and verifies before opting into collection format. Schema/version and crash-recovery tests reject unknown or inconsistent generations. (REQ-10)
- [ ] AC-10: Each substantive build/fix round receives fresh actual Claude Code `claude-opus-5-5` review. Finding fixes retain whole-production-fix reversion evidence. Record exact reviewed commits, CI runs and remaining limits without implying deployment or cutover. (REQ-1, REQ-2, REQ-3, REQ-4, REQ-5, REQ-6, REQ-7, REQ-8, REQ-9, REQ-10)

## Architecture

### Findings and sequence

The retained correction review is `.design/reviews/kan-v2-operations-correction-2026-10-18.md`. Its six follow-ups are fully mapped here:

| Follow-up | Design treatment | Build sequence |
|---|---|---|
| Lazy reporter/binding/recovery and UI test gaps | REQ-6; promote reviewer P2–P4, add worker mismatch/history and failure-display tests | First, alongside each correction |
| Full journal undercounts losses | REQ-2/3; explicit capacity/certainty, owner-triggered preserved-history rotation | Second |
| Worker history resets after late recovery | REQ-1; one-time reconciliation before any overwrite | First |
| Healthy reporters always warn | REQ-5; separate freshness, delivery progress and retained gaps | First, shared status model |
| FIFO loses latest cumulative snapshot | REQ-4; bounded per-attempt coalescing | First |
| Global-cap mutant survives locally | REQ-6; Linux baseline/negative-control/restoration | First |

Then implement the studio UI against the reviewed status contract. Rotation and interface work can be separate stacked commits/PRs, each with a fresh review; do not gate ordinary capture on operator maintenance. The existing #279 remains a distinct reviewed implementation checkpoint.

### Worker history and cumulative updates

`src/evidence_operations.rs::drain` currently reads prior worker state only during initialization. `persist_worker` later opens a journal and immediately replaces its worker row; a failed first snapshot read has the same loss risk as missing storage. Reconcile bound history before the first successful status write, not merely after a successful open.

Keep this run's unsaved failure delta distinct from the persisted baseline. Read and merge under the journal transaction, add the local delta once, then advance the local persisted watermark only after commit. A failed or ambiguous commit must not add the same delta twice; a stable worker-run identity and persisted per-run watermark make retry idempotent. Choose the acknowledgment with the greatest valid position within the same queue lineage and retain its paired timestamp. Do not independently maximize wall-clock time. An empty current queue does not erase the prior acknowledgment. Never carry history across a binding/lineage mismatch.

### Health capacity and loss certainty

The current SQLite cap is 32 MiB plus rollback-journal space; attempts also have a separate 100,000 ceiling. Both remain distinct from the encrypted spool's budget. Extend the shared snapshot with sampled page usage/limit, attempt usage/limit, last successful write observation, journal generation, and explicit persistence/coverage status. Page occupancy alone means near-capacity, not proof a future update will fail; expose a recorded SQLITE_FULL observation separately.

Maintain bounded operational control records independently of growing attempt rows, with reserved capacity for current writer checkpoints and a sticky incomplete-coverage marker. Reserve is finite: repeated unknown writers or whole-device failure can still exhaust it. If it cannot be updated, freshness expires and the reader reports unknown. Never promise an exact count across process death or a disk that cannot record the loss. Report a retained loss count as a lower bound whenever the record cannot establish an exact value. Recovery can restore current health but cannot repair missing historical evidence.

### Owner-triggered preserved-history rotation

Existing CLI arguments point to a single SQLite file and open connections live for the process lifetime. Renaming that file underneath a worker is not a rotation protocol. Introduce an explicitly versioned operations collection containing an atomically published manifest, immutable sealed journal generations, one active journal, and bounded operational control state. Existing standalone paths continue to work; owner adoption copies, verifies and preserves the original before switching configuration to a collection. No implicit in-place conversion.

All upgraded writers hold a shared collection lock for their connection lifetime. A proposed local `ops-rotate` command obtains an exclusive lock or refuses promptly; the runbook stops the relevant supervised writers first. The transition from older clients requires explicit operator shutdown because old binaries do not participate in this lock. The existing read-only dashboard initially displays a rotation plan and instructions. The complete frontend must also support owner-authorized execution through a distinct admin plan/job API that invokes this same rotation primitive. Its operations/read-only token cannot execute rotation or delete history. This avoids treating a CLI-only workaround as the completed human frontend.

Under exclusive ownership: validate bindings and current generation; create and fsync a unique new journal; checkpoint/close the old connection; retain and seal the old journal with its hash and binding; publish a manifest referencing both through write-new, fsync, atomic replacement and directory fsync. No old history is removed. If publication has not committed, the old generation stays authoritative; after commit, the new one is active. Unreferenced staged files remain identifiable recovery artifacts, never silently admitted or deleted. Recovery validates the manifest and refuses ambiguous/conflicting generation histories.

Historical reads name their generation and remain available after rotation. Counts across generations deduplicate cumulative attempt and reporter-session identities rather than summing duplicate snapshots. Derivable summaries have declared source-generation membership and can be rebuilt; they do not become authority. Ordinary live polling must not scan all sealed history. Page historical results explicitly, report the active/query scope, and maintain bounded rebuildable summaries for overview totals. New persistence paths and derived summaries require rows in `tests/fixtures/read-write-surface.tsv`, capabilities in `src/persistence.rs`, declarations in `src/surface.rs`, and `tests/surface_conformance.rs` coverage.

### Coalescing without hiding loss

The existing `reporter_inner` sends every update into a 256-item FIFO. Replace that with a fixed-capacity pending map keyed by attempt plus a bounded wake mechanism. Admission uses a nonblocking operation; no callback waits on a journal or contended writer lock. Replacing an admitted cumulative update with a newer dominating update is coalescing, not a lost capture. Preserve monotone counters, gap flags and terminal state together; reject or disclose contradictory/out-of-order updates rather than inventing a component-wise state that never existed. Overflow of distinct attempts and failed handoff remain separate counted losses. The writer removes a pending entry only if its revision still matches what it persisted; a concurrent newer value must survive.

### Shared status semantics

Update `src/evidence_operations.rs::Snapshot`, `src/evidence_dashboard.rs`, `src/bin/kan-v2.rs`, and `web/operations/app.js` together. Use an explicit next contract version for the new nested status model; retain old journal readers through an adapter and reject unsupported HTTP versions visibly. Browser and CLI use the same facts; UI presentation never rewrites persisted observations.

| Dimension | States | Meaning |
|---|---|---|
| Fetch | current / disconnected / incompatible | Whether the browser can obtain supported snapshots |
| Reporter | fresh active / stale unclosed / clean closed / absent | Heartbeat evidence, not a claim that all harness traffic was seen |
| Delivery | idle / delivering / retrying / stale / unavailable | The worker's timestamped observation |
| Journal | writable observed / near capacity / exhausted observed / unavailable / unknown | Capacity and persistence evidence, independently sampled |
| Coverage | retained gaps / lower-bound loss / unknown / no gaps reported | Historical observations; never a completeness certificate |

Freshness is computed from timestamps, with explicit clock limitations. A fresh unclosed session is active, not an unclean-exit alarm. A stale unclosed session is uncertain, not proven dead. Current retry/exhaustion/disconnection takes priority in the main state area. Historical gaps retain their own badge and filter even when current operation recovers. No live status is inferred from an old historical row.

### Technical studio visual direction

The user chose clean light surfaces, dense data and a vivid accent. Replace the large pastel sidebar and serif card grid in `web/operations/index.html` and `style.css` with a compact header, restrained section navigation, an asymmetric typographic hierarchy and thin structural rules. Use ink text on white/cool-gray surfaces; electric blue denotes selection and primary actions. Green, amber and red carry labeled state, not decoration. Rounded corners are small and consistent.

Typography uses locally available system sans and monospace with tabular numerals, no remote font dependency. The largest numeric value is archive progress; queue pressure and retained gaps remain prominent through position and explicit labels. A compact delivery strip reports capture observation, retained queue and archive acknowledgment without suggesting a verified provider outcome. No animated traffic, fabricated sparkline or invented throughput appears without supporting samples.

Below the summary, a dense recent-attempt table uses explicit observer/outcome labels, local search, gap filtering and a metadata inspector. The inspector shows full IDs, timestamps, counts and their meanings; it does not claim to retrieve message bodies. Searching is labeled as limited to the returned recent page. The retention panel separates queue budget from health journal usage and exposes the owner rotation plan as read-only guidance. Avoid empty navigation for unbuilt evidence/session views; reserve the information architecture in the design rather than shipping dead tabs.

At narrow widths, maintain status, counts and controls first; panels stack and the inspector becomes a full-width dialog. Tables scroll inside their own region or become labeled rows without losing fields. State is never communicated solely through color. Native controls, visible focus and semantic headings remain. Production scripts/styles stay self-hosted under the existing CSP, with no external analytics or font calls.

### Prototype and implementation boundary

`.design/kan-studio/index.html` is an interactive design artifact. Its Operations area selects synthetic current, retrying, exhausted, disconnected and empty states. Search/filter and row inspection work locally; rotation guidance explains the proposed workflow and performs no writes. The prototype does not exercise authentication, persistence, networking or real health classification. Browser checks of the prototype are design evidence only; all runtime ACs above remain unchecked until implementation and review.

## Resolved Questions
- Q1: Use the technical studio direction: clean light surfaces, dense data, vivid accent color. The user selected this over the proposed dark and editorial alternatives.
- Q2: The initial operations-only selection was superseded by the user’s subsequent clarification: design a complete human frontend, including rich browsing and administration. This document governs its operations workstream; `.design/kan-v2-human-frontend.md` governs the whole application.
- Q3: Rotation is explicitly owner-triggered and preserves all history. No automatic rotation, expiration or erasure is introduced.

## Open Questions
No blocking product question remains for this design. Implementation must prove the rotation crash protocol and bounded overview aggregation before claiming AC-3 or AC-9; those are engineering obligations, not assumed successes. Exact accent and spacing values can be iterated against the preview without changing the storage/authentication contract.

## Out of Scope
- Implementing these corrections during the design pass; the preview is synthetic.
- These operations requirements do not by themselves implement the broader reader, search, annotation or extraction interfaces. Those are explicitly included in the companion full-frontend design. Public dashboard hosting and browser decryption remain separate deployment decisions.
- Destructive browser controls, automatic journal expiration, live service installation or migration/cutover.
- Closing the separate production gates for bounded capture/startup audit, custody/grants/erasure and independent-host restore qualification.

## Process record
Context was read from the operations branch and the main checkout's bulk kan view. `day doctor` still reports two withheld claims without subject attribution and cannot establish complete process composition. The raw-data-and-projections maintenance telos deliberately has no witnesses; none are invented here. Design/bridge/claim backfill remains pending under that known limitation, following the user's prior decision to preserve ground truth and proceed in Git. `day next design` reports generative-build. Source files are unchanged in this design pass; the permanent worktree is `.worktrees/kan-v2-operations-polish`.

## Build checkpoint — theme and worker recovery

The first child build adds System/Light/Dark to the production operations client
and the full synthetic Studio preview. Appearance storage is cataloged separately
from credentials. Current reporter/worker freshness and retry state are separated
from retained gap/failure counts; fresh unclosed sessions are active, while stale
or unsampled unclosed sessions remain uncertain. Clock samples materially in the
future are not treated as current.

Worker checkpoints now reconcile history transactionally on every write, including
late journal open and startup read contention. The existing JSON worker row gains
an optional run identity and cumulative run-failure watermark; legacy rows read
with an empty identity and zero watermark. This preserves the existing SQLite
schema and snapshot version. The counter delta is deduplicated on retry, and the
highest valid prior acknowledgment keeps its paired timestamp. A regressed queue
frontier or mismatched stored binding fails reconciliation. A previously committed
run cannot overwrite a successor's checkpoint. Deployment still requires one
supervised worker per spool; this is not worker election. Public legacy
`save_worker` is a low-level replacement API, not the drain checkpoint path.

This is a separable first implementation slice, not completion of the 10 runtime
ACs. Capacity certainty/reserve, preserved-history rotation, coalescing, the new
nested snapshot model, reader API and full frontend integrations remain in the
already declared sequence. The Linux global-cap negative control now has a CI
runner; a successful Linux run is required before claiming the earlier survivor
was killed. New persistence fields live in the already cataloged operations
journal, under its existing typed creation capability.

## Build checkpoint — cumulative health coalescing

The next child slice replaces the volatile FIFO with a 256-distinct-attempt map
and a one-item wake channel. A callback only attempts a memory lock; contention,
invalid/contradictory updates, distinct-attempt overflow and a dead writer remain
counted handoff losses. An accepted newer cumulative observation replaces the
whole pending observation. That coalescing is not counted as missing raw traffic.
No capture callback waits on database I/O or a writer-held lock.

The writer snapshots one bounded batch and releases its memory lock before I/O.
Each pending entry carries a revision. Completion or failure removes only that
revision, so a newer update received during the write survives for the next pass.
A queued wake covers concurrent updates; disconnect drains the final bounded batch
before the existing clean-close observation. Failed persistence remains counted;
this does not solve exhausted-journal counter certainty or whole-device failure.

Both pending replacement and durable `Journal::record` enforce whole-observation
monotonicity: same attempt/observer, nondecreasing consistent counters, and retained
HTTP/terminal outcomes. A conflicting summary is refused rather than assembled
from independent maxima. SQLite schema, public snapshot shape and the existing
cataloged journal persistence surface do not change. Raw capture and encrypted
spool records are unaffected. The capacity/reserve and preserved-history rotation
workstream remains required before claiming the operations design complete.

The child also closes the reviewed badge mismatch: a single worker freshness
predicate controls both badge and notice, including future/non-finite samples.
Unclosed sessions without a current heartbeat are listed in retained coverage.
They still conservatively affect current certainty; distinguishing superseded
reporters from required-but-missing sources needs stable source identity in the
future status contract and is not inferred from an arbitrary age cutoff.

The burst test establishes an exclusive SQLite read barrier via the connection's
busy handler, then sends newer cumulative observations and a terminal update while
an older revision is in flight. It verifies exact final counters, terminal/gap
preservation and a separately counted contradictory update. This avoids a timing
assumption about when a background writer has started. The bounded distinct-attempt
pressure test retains its independent callback deadline and overflow accounting.


Fresh actual Opus 5.5 review of cde8b0f returned APPROVE WITH FOLLOW-UPS. The
independent report and author disposition are in
`.design/reviews/kan-v2-coalescing-2026-10-18.{txt,md}`. Its probes found substantial
counted terminal-summary loss under synchronized healthy-journal contention.
Before claiming normal-load reliability, add deterministic contention accounting,
qualify callback concurrency, and tighten the burst barrier to the record write.
Unsampled-session wording, summary counter units and native mixed-language
reversion replay also remain explicit follow-ups. Capacity/rotation and the full
reader/frontend sequence remain unchanged.


## Build plan — health admission reliability

Address the six coalescing-review follow-ups before capacity/rotation. Shorten
the memory-lock critical section by retaining immutable shared observations and
cloning references for the writer batch. Partition attempts over 64 memory locks
with one global 256-attempt bound; a writer never locks all shards together. Retry a contended `try_lock` a fixed
number of times with CPU hints only: no blocking lock, scheduler yield, sleep or
I/O on the callback. Exhaustion remains counted exactly once per rejected offered
summary. Qualification includes synchronized callers below distinct-attempt
capacity and an explicit held-lock test; no finite retry budget guarantees lossless
health telemetry under arbitrary scheduling. Raw capture remains independent.

Bind the SQLite burst-test barrier to the record transaction, not a heartbeat,
and force a heartbeat first to test that distinction. Clarify UI units as summary
loss observations (a lower bound, potentially including older update units), and
separate stale sampled sessions from unclosed sessions outside the sample. Add a
repository reversion runner that accepts real exact Rust/Node names and replayable
committed correction ranges, with baseline/revert/restore evidence and failure
classification. The bundled day tool remains the authority for generated trailers;
the repository runner supplies the mixed-language execution adapter explicitly.


## Reliability review correction

Fresh Opus 5.5 approved fcd8c6f with follow-ups. The next correction adds a
deterministic transient-contention retry test (independent of the workload
threshold), bounds global capacity reservation to 64 compare-exchange attempts,
and replaces the deprecated atomic API flagged by the newer Linux CI compiler.
The callback uses at most 512 shard-lock tries; semantic refusal is not retried.

The mixed-language runner now owns a POSIX process group so a timeout kills test
descendants in that group, reports untracked source files, and tests export
isolation and timeout cleanup. Build-cache sharing through an explicitly supplied
CARGO_TARGET_DIR is documented separately from tracked-source isolation. The loss
label is broadened to health telemetry observations because initial session and
dead-writer wake failures also contribute. Small fixed-size allocation remains;
there is no hard-realtime scheduling claim.
