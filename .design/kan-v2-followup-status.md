# Kan v2 follow-up ledger — 2026-10-18

> Development flow update (owner decision, 2026-10-19): complete the full v2
> feature set with continuous integration, then conduct one thorough integrated
> Opus 5.5 review campaign. The active checklist and policy are in
> [kan-v2-next-build-status.md](kan-v2-next-build-status.md). This supersedes older
> per-checkpoint review/reversion instructions below, without reducing product scope.

This is a navigation aid to implementation and review evidence, not an authority
for acceptance. The complete human frontend remains required by
`kan-v2-human-frontend.md`; partial slices do not close that design.

## Current build position — 2026-10-19

This section supersedes the historical status tables below. Accepted means the
named review disposition, not a main merge or operational cutover.

| Slice | Exact current checkpoint | Remaining acceptance |
|---|---|---|
| Library/codec follow-ups through inventory | #290–296, through `8b5fab90` | All current heads have green CI; prior named follow-ups remain in their reports |
| Frame decoder, recovery codec/state/member/replay | #297–301, through `c0a74313` | Current CI green; physical mutation and remote/UI consumers remain separate |
| Physical bundle reader | #302 `6bf681a1` | Fresh approval with follow-ups; promoted empty physical-type regressions pass; mutation custody/refusal obligations carry forward |
| Capture assembly | #303 `a65e2a67` | Fresh approval with follow-ups; absolute accounting/order/duplicate regressions promoted; CI green |
| Provider interpretation / Content | #305`aef1067` | Frozen baselinebb1e0ab received fresh Opus APPROVE WITH FOLLOW-UPS; corrections now author-qualified with103integrations+12units+47UI,17backend controls and retained browser evidence; fresh correction review pending; download still unverified |
| Physical bundle creation | #306`22002e7`, `feat/kan-v2-recovery-mutations` |70integration checks,strict lint/format,seven semantic controls and independent SQL/history oracle pass; fresh review pending; restoration/publication remain required |
| Legacy codec qualification | Recovery616ff64 performance run39315201306 | Claim canonicality refusal during synthetic generation; unresolved, not timing noise or a passing performance result |

The next implementation order is:

1. Resolve the frozen provider+Content review and its final exact-head CI result.
2. Qualify retained bundle creation; implement checkpointed atomic restoration,
   publication, and bundle-aware backup/rebuild. Preserve all failed artifacts
   and explicit uncertain outcomes; never activate a restored writer implicitly.
3. Connect proof-bearing inventory/source and descending pinned cursors to remote
   authorization. Carry Available/Missing/Corrupt evidence through Library,
   including startup with lost historical objects. Preserve admission authority.
4. Build archive-wide attempt/session discovery and navigation on the now-versioned
   adapters. Explicit selection in #305 is not archive discovery or a full session.
5. Add authorized search/facets, stable references and saved trust-aware views;
   then the evidence/claim adapter and separately authorized append-only annotations.
6. Implement inspectable background analysis runs, scheduler/worker grants and
   quotas, dependency/frontier invalidation and day process-assessment integration.
7. Connect typed owner plans/jobs to the human admin surface for storage, recovery,
   import/migration, access, keys and explicit erasure, with retained job provenance.
8. Complete actual browser download delivery and operational placement/cutover
   qualification. Live keys, deployment and migration remain separate owner actions.

Each substantive implementation/fix checkpoint receives fresh actual Claude Code
Opus5.5 review. A draft or design does not close parent acceptance. Merge remains
sequenced by PR bases, with exact-head checks and review evidence rechecked; no
main merge was performed. Permanent worktrees are under `.worktrees/`; a single
shared Cargo target is used, and no `.lake` or background preview server is left.

## Historical roadmap snapshots

| Workstream | Current evidence | Remaining work |
|---|---|---|
| Health admission/reporter reliability | #283, a04f288; fresh Opus approval with follow-ups; all CI green | Qualification under wider production load; no universal zero-loss claim |
| Capacity and owner rotation | #284, 771341e; fresh Opus approval with follow-ups; all CI green | Merge only with #285 corrections; whole-device/power-loss qualification remains distinct |
| Session-cap continuation, WAL refusal, runner cleanup | #285, 9d300b4; fresh Opus approval with follow-ups; all CI green | Commit the surviving focused test improvements listed below |
| Real Library reader and source/provenance UI | #286, df74506 and corrections through a8cbf21 independently approved with follow-ups; record 21c883d | Per-record unavailable evidence and browser file delivery remain open; #288 implements partial catalogs and stronger boundaries |
| Library resilience | #288, source 8124878; final fresh Opus approval with follow-ups; both source CI runs and migration pass | Performance repeat pending after a near-bound context ratio; spent-wait assertion, deadline tolerance, client entry shape and real download verification remain open |
| Deduplicated collection overview | `kan-v2-collection-overview.md` | Implement and qualify the bounded projection, typed status, refresh/cancel and human states |
| Normalized sessions and navigation | Parent human-frontend design | Versioned adapters and exact source mapping for messages, tools, branches, attachments and gaps |
| Search and views | Parent human-frontend design | Authorized encrypted projections, filters, frontiers, saved trust-aware views and stable URI extensions |
| Knowledge and annotations | Existing v1 semantic foundations | v2 evidence/claim read adapter and separately authorized append-only annotation signer |
| Human administration | Existing CLI backup/restore/migration/rotation primitives | Typed plan/job APIs and UI for storage, recovery, migration, access, keys and retention |
| Background analysis/day | Server-first architecture | Inspectable run/assessment records, scheduler/worker contracts, grants/quotas and source lineage |
| Deployment and migration cutover | Runbooks and synthetic evidence only | Reader placement decision, real installation/key placement and owner-approved cutover remain separate |

## Current checkpoint overlay — 2026-10-19

The preceding table and delivery-order text retain the earlier roadmap state.
Use these later checkpoint records for implementation status:

- #290 Library/codec follow-ups: source through 5784efa; actual browser file
  delivery remains unverified.
- #291 proof storage: a1007a6; independently reviewed corrections and CI green.
- #292 bounded collection overview: d94359c; fresh Opus APPROVE (scope C in
  `reviews/kan-v2-purpose-gate-opus/evidence/REPORT.txt`), CI green, real browser
  restart evidence. Sustained-write refresh starvation and memory refusal remain
  declared bounds, not universal performance guarantees.
- #293 proof-preserving lifecycle: 58ba158; reviewed corrections, CI green.
- #294 source-copy planner and codec: 619613d; CI green. The independent oracle
  sort and named-reason follow-ups are closed in #295.
- #295 destination: d9b2110; fresh Opus APPROVE WITH FOLLOW-UPS, preserved in
  `reviews/kan-v2-copy-destination-opus/evidence/REPORT.txt`. Plan-file custody
  and coverage follow-ups are being qualified separately. Linux/MSRV/migration
  passed; the performance run initially failed the unchanged context ratio
  (8.3 > 8), with its single retry still pending at this writing.
- Degraded inventory and recovery-bundle designs are on the permanent
  `feat/kan-v2-degraded-inventory` worktree branch. Inventory implementation is
  an unqualified draft. No bundle writer, remote proof adapter, or full human
  conversation workflow is accepted by these storage checkpoints.

The next sequence remains inventory/bundles and remote integration, followed by
conversation reconstruction, search/views/annotations, background assessment and
integrated administration. All PRs remain stacked drafts; no live cutover.

## Accepted delivery order

The owner approved this roadmap after #286/#287:

1. Library resilience: partial healthy browsing, request bounds, regression gaps
   and real-browser export qualification. Implementation is now in
   `.design/kan-v2-library-resilience.md`; source 8124878 has fresh actual Opus
   approval with follow-ups, retained under `reviews/kan-v2-library-final-opus/`.
   The intervening test-fixture BLOCK and its correction remain recorded. Source
   CI and migration pass; a performance repeat is pending after a near-bound
   legacy context ratio. Actual download delivery is still unverified in IAB.
2. Missing-evidence rows with authenticated metadata surviving payload loss;
   preserve the admission boundary described below. Draft #289 specifies the new
   proof/profile and owner-copy upgrade in `kan-v2-evidence-availability.md`;
   that draft is not an implemented storage format.
3. Implement the bounded deduplicated collection overview in #287.
4. Human conversation browsing: messages, tools, attachments, branches and gaps,
   with exact mapping back to retained evidence.
5. Search/filters, annotations/saved views, analysis and integrated human admin.

These are cumulative workstreams, not permission to call the frontend complete
after step 1. Deployment placement and live cutover remain separate.

## Exact #285 review follow-ups

The authoritative report and disposition are
`reviews/kan-v2-admission-audit-2026-10-18.txt` and `.md`.

1. Test the first-reason no-rewrite guard directly, not only the earlier sealed
   admission filter. The review contains a focused probe that kills the survivor.
2. Replace modal focus assertions against old element flags with activeElement
   checks. Test that polling leaves focus inside the inspector and closing returns
   focus to the replacement row.
3. Test 90% capacity boundaries exactly, including just below/at/above, for both
   attempts and reporter sessions. A 99% mutant survived broad high-pressure tests.
4. Bind retry tests to production wrappers as well as injected helpers. Helper
   mutation kills do not demonstrate the wrapper actually calls those helpers.
5. Add exact alias and Python output-prefix rejection cases to the reversion
   adapter tests; do not count parse errors as assertion failures.
6. Keep the documented conservative freshness interpretation visible. The
   five-second UI threshold can report a worker unknown during a legitimate
   longer request; separate capture/worker cadence presentation remains a refinement.

Older v2 session-limited journals with a released reserve are deliberately
accepted and writable; this compatibility decision is documented in #285. No
source repair or automatic reserve rewrite is implied.

## Exact #286 correction-review follow-ups

The authoritative report and disposition are
`reviews/kan-v2-library-correction-2026-10-18.txt` and `.md`. Fresh actual Opus 5.5
session efa9d730-4e15-4369-b0cd-ca2869a01b29 approved the corrections with follow-ups.
The review does not close any missing full-frontend workflow.

1. Per-occurrence unavailable evidence, including startup and snapshot behavior
   when historical payloads are absent (see the admission boundary below).
2. Per-scope catalog errors so one unreachable or unverifiable scope does not
   prevent inspection of valid neighbours.
3. Deterministic tests of four executing requests, twelve accepted sockets,
   queue timeout and whole-connection timeout. The committed fifth-socket test
   does not distinguish queuing from unbounded execution; reviewer timing probes
   are retained as separate evidence.
4. API-side capability-list assertions and client malformed/duplicate cases.
5. UI 401 locking, Previous-during-loading and remaining Unicode-control cases.
   The production 401 branch is present; K03 is a surviving mutant, not a
   demonstrated current 401 disclosure.
6. Real browser file-delivery and remaining state/external-request qualification.
7. Composed call/connection deadlines and constant-time token comparison.

## Missing-source browsing: preserve the admission boundary

The Library follow-up is more than replacing one error with a placeholder.
`Service::new` and `Service::execute` in `src/evidence_service.rs` audit retained
signed requests before advancing the admitted frontier. `Page` revalidates those
objects, and `Snapshot` revalidates the tip. After restart, a missing historical
object can therefore prevent service startup; after startup, a missing tip can
prevent a fresh snapshot. A page-local UI change alone does not solve this.

The next source-availability design must separate authenticated retained metadata
from payload availability without promoting a privileged raw-ledger append to
verified service admission. Preserve the current foreign-partition, writer-signature,
and audited-frontier negative controls. Specify what independent retained proof
allows a missing payload to be represented after restart, how old stores acquire
that proof without inventing historical signatures, and how authenticated absence
differs from corrupted metadata. Until that contract is implemented and reviewed,
retain the explicit unavailable-page state; do not remove `read_signed` checks to
make the UI appear complete. The current read-only Library cannot manufacture the
missing authority.

## Review and merge discipline

Fresh actual Claude Code Opus 5.5 remains the build checkpoint reviewer. Preserve
model/session evidence, exact verdicts and surviving mutants. Reversion evidence
must compile, fail a named assertion, and pass after restoration. The first
Library review was interrupted before a verdict and is not an approval.

PRs remain stacked drafts. Merge order follows their bases; no main merge,
installation, production archive read, key placement or cutover is implied by a
passing development checkpoint. Permanent worktrees live beneath `.worktrees/`.
All temporary fixture servers are stopped after use. Active review exports remain
immutable; author corrections receive their own review afterward.

## Final Library checkpoint follow-ups

The authoritative final report is `reviews/kan-v2-library-final-opus/result.txt`.
Fresh actual Opus 5.5 session 9f7d88b1-03df-462a-b017-d91b22364ff7 approved 8124878
with follow-ups. Remaining test refinements are the first admission's actual
spent wait (rather than window timestamps alone), optional wait-value forwarding
assertions, repeated Linux contention qualification, one-second upstream/body
bounds and client scope-entry shape checks. Actual browser file delivery is
still unverified. The initial performance failure and single rerun request are
retained with the review record; no threshold was relaxed.

The missing-evidence proposal in #289 now includes statement-CID chain/snapshot
commitments, low-S P-256 encoding, two independent exact byte fixtures and twenty
negative checks, with its oracle wired into CI. This is protocol preparation,
not an implemented proof-bearing archive or completed missing-row UI.
