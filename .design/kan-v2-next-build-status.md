# Kan v2 continuation status

This is the execution ledger for the approved remaining roadmap. Permanent
worktree: `.worktrees/kan-v2-build-next`; branch: `feat/kan-v2-build-next`.
It builds on the stacked evidence-availability design, preserving existing drafts
and the root checkout's unrelated edits. No production archive, key, deployment,
installation, live migration or main merge has occurred.

## Current continuation checkpoint (2026-10-19)

The sections below retain the history of individual checkpoints. For the current
dependency order, use this table; a passing component review does not close the
full recovery or human-frontend acceptance criteria.

| Layer | Current evidence | Still required |
|---|---|---|
| Pure KANC2 decoder (#297) | Strict decoder and promoted independent regressions; latest independent scope-C review APPROVE | Occurrence assembly, provider adapters, source spans and real session UI |
| Observation wire codec (#298) | Authenticated bounded envelopes and independent signed vectors; review APPROVE WITH FOLLOW-UPS | Semantic replay, physical format and publication checks |
| Streaming M1/O1/R1 (#299) | Reviewed framing; promoted boundary and deterministic cancellation tests; current CI green | Fresh review returned APPROVE WITH FOLLOW-UPS; UTF-8 test follow-through is in #300; digests alone confer no authority |
| Logical member (#300) | Fresh combined Opus scope-B review APPROVE for 5edb505; controls and whole-guard reversion reproduced | Physical consumers remain separate; replay constraint coverage is tracked in #301 |
| Observation replay (#301) | Frozen b52aa48 review APPROVE WITH FOLLOW-UPS; correction immediately verifies restored request signatures/bindings and adds 23 design-derived cases | Fresh combined review verifies writer-pass accounting and maximal-envelope labeling follow-through in #302; no physical publication authority |
| Physical recovery and delivery | Read-only opener #302 correction received fresh Opus APPROVE WITH FOLLOW-UPS at eb4f471; physical empty-value follow-through passes 15 reader tests and strict lint | Creator/restorer/publisher, crash/reconnect jobs, RPC, spool proof integration and Library unavailable-evidence UI |

The Library's actual browser download remains unverified: native access is locked,
and the earlier IAB download event timed out; IAB DOM access is not thereby disproved.
Full sessions, search/facets, annotations, saved views, analysis/day and owner
administration remain build work. No release, merge, deployment or live cutover
is implied by the green component CI results.

## Library qualification

Commit 4b0ebc1 validates all scope entries before navigation, adds malformed
catalog recovery cases, and requires the contention fixture to observe actual
SQLite wait. Fresh actual Claude Code Opus 5.5 reviewed that exact checkpoint:
APPROVE WITH FOLLOW-UPS. The original report, mutation traces and identity are in
`.design/reviews/kan-v2-library-scope-opus/`. Reviewer boundary/state probe tests
have subsequently been incorporated. Test wrapper spent-return fidelity remains
a small open regression gap, with implementation forwarding it unchanged.

Native browser access remains blocked by a locked Mac. A new in-app browser
attempt displayed the exact 64-byte binary fixture but timed out awaiting the
actual download event. Delivery remains unverified. Tab and fixture were stopped;
see `.design/reviews/kan-v2-library-scope-followup/browser-delivery.txt`.

## Missing-evidence prerequisites

The first protocol review returned BLOCK (weak negative fixtures, issuer ambiguity,
pagination linkage). The correction at b81eb4f received APPROVE WITH FOLLOW-UPS
for design readiness only. Both raw reports are retained. Later follow-ups now
specify current-audience RetryImported confirmation, historical-source audience
checks, archive provisioning, purpose ordering and append-only recovery observations.
Those later rules require runtime implementation and review.

The Rust attestation codec is a separate first implementation slice. It shares
strict bounded canonical decoding, verifies exact issuer/archive/scope/metadata
and chain commitments, signs P-256 low-S proofs and verifies descending rows against
a pinned frontier. It consumes two independent exact-byte signed vectors and sixty
labelled negative vectors. Some vectors intentionally exercise individually valid
proofs in a purpose order that the future store must refuse; they do not model an
admissible upgrade/capture history.

Author validation: 95 integration checks across attestation, canonical codec,
store, service, reader, real CLI and surface conformance; all-target v2 Clippy;
14 compiled semantic mutations fail named assertions, exact source restored;
27 whole-check oracle mutations fail. These bounded mutation sets do not prove
all possible weakenings are detected. Fresh actual Claude Code Opus 5.5 reviewed
2e96685: APPROVE WITH FOLLOW-UPS for the codec only. Its unmodified report and
probes are preserved in `.design/reviews/kan-v2-attestation-codec-opus/`. It independently
passed the 95 integration checks, 50 Node checks, Clippy/fmt and 13,420 hostile
byte variants. Short-issuer and descending error-label regressions are required
before storage integration; detached proof authority, fuller independent source
schemas and independent page vectors remain follow-ups for the consuming slices.

No profile-2 table, admission transaction, copy upgrade, backup/restore extension,
Inventory RPC, cursor MAC, proof-aware spool release or unavailable-evidence UI is
implemented by the codec. All six storage-design acceptance criteria remain open.

## Profile-2 storage checkpoint (under qualification)

Permanent worktree `.worktrees/kan-v2-proof-storage` adds an owner-side Archive API,
explicit archive binding, atomic proof insertion, stored-byte retries and strict
whole-chain audit. The legacy Ledger, recovery and resume APIs refuse the new
profile. Fresh capture requires a current matching append grant and issuer.
The schema, typed SQL mutations, independent surface catalog and CI test list
are extended together. No RPC, CLI, migration, degraded-read or UI behavior is
claimed from this storage API alone. All six parent acceptance criteria remain open.

Ten storage checks include eight abrupt-exit phases, restart/retry byte identity,
valid same-height proof replacement, unproven concurrent raw append, purpose
ordering, wrong owner binding, metadata damage and missing payload refusal. Codec
short-key and descending-error-label regressions address review F1/F2; the Verified
doc now states its relative authority. Author evidence is preserved in `.design/reviews/kan-v2-proof-storage-author/`: ten
storage checks, seven codec checks, existing compatibility suites, nineteen surface
checks, strict Clippy, and six compiled negative controls. Fresh storage review
approved 9f1dffa with follow-ups (106 core + 58 lifecycle/service checks). The
original report is retained in `.design/reviews/kan-v2-proof-storage-opus/`. Its
non-tip retry, historical-issuer and canonical-key regressions are incorporated;
small error-class/limit-propagation corrections pass 37 storage/surface checks and
strict all-target v2 Clippy. Fresh Opus review of those corrections at a1007a6 returned APPROVE; the raw combined review is preserved under `.design/reviews/kan-v2-overview-opus/`.
The complete pre-admission audit is deliberately unoptimized; see the storage
checkpoint scope in the governing design for its concurrency threat boundary.

## Proof lifecycle continuation (draft)

Permanent worktree `.worktrees/kan-v2-proof-lifecycle`, branch
`feat/kan-v2-proof-lifecycle`, builds on the collection/storage checkpoint.
It adds explicit profile-2 initialization resume, fully verified standalone
backups, and proof-preserving raw recovery into a new file. The owner CLI uses
all-or-none archive/scope/issuer pins; legacy commands still refuse profile 2.
No schema field, lifecycle side store, implicit conversion or promotion is added.

Draft regression coverage includes exact bytes, derived repair, wrong owner pins,
legacy-profile refusal, copied-proof verification, pinned source transactions,
process death at initialization/rebuild boundaries and real CLI output. Five
semantic negative controls fail named assertions and restored checks pass. Local
qualification passes 81 Rust checks and strict all-target v2 Clippy; evidence is
in `.design/reviews/kan-v2-proof-lifecycle-author/`. Fresh actual Opus5.5 review at7ab1afa returned APPROVE WITH FOLLOW-UPS;
the raw report is in `.design/reviews/kan-v2-overview-lifecycle-opus/`.
Follow-up qualification at9aca45d closes the named test, CLI and catalog gaps
(`.design/reviews/kan-v2-proof-lifecycle-followup-author/`); its fresh correction
review is pending. No parent acceptance criterion is closed by this slice.

## Remaining ordered build

1. Profile-2 authoritative proof storage in permanent worktree
   `.worktrees/kan-v2-proof-storage`, branch `feat/kan-v2-proof-storage`;
   atomic admission/retry and process-death/hostile-append qualification.
2. Owner-copy upgrade and proof-preserving backup/recovery with surface conformance;
   explicit degraded inventory server, descending RPC/cursor framing, source
   authorization and available/missing/corrupt Library rows.
3. Bounded deduplicated collection overview is drafted in permanent worktree
   `.worktrees/kan-v2-collection-build`, branch `feat/kan-v2-collection-build`.
   Complete typed source scans, bounded deduplication, asynchronous refresh/cancel,
   CLI, authenticated dashboard routes and UI are implemented. Author qualification
   passed 58 Rust and 54 Node checks, strict v2 Clippy, six negative controls,
   and real completed/lock light/dark/mobile browser inspection. The initial Opus verdict was APPROVE WITH FOLLOW-UPS; correction qualification is recorded below;
   evidence is in `.design/reviews/kan-v2-overview-author/`.
4. Versioned human-readable conversation adapters with source lineage.
5. Authorized search/filters, annotations, saved views, background analysis/day
   integration and owner admin workflows from the full frontend design.

Every substantive build/fix checkpoint receives fresh actual Opus 5.5 review.
Browser delivery, deployment placement and live cutover remain explicit unresolved
operational gates; they do not justify pretending the software roadmap is complete.
Git-first design/review records await backfill while day#168 / kan#197 prevent
worktree-local recording. The existing raw-data-and-projections telos is deliberately
unwitnessed; no witnesses or omitted claim contents were invented.

## Overview review corrections in progress

The review of 67c1263 reproduced live health-writer exclusion during a large
active scan and Build/Cancel requests discarded during polling. Draft corrections
use a bounded in-memory active database copy and prioritize actions over polls.
The existing 128-MiB ceiling now includes a 32-MiB image allowance plus 16-MiB
working reserve; capacity refusal is explicit. Source copy can refuse after five
seconds when busy. Tests target writer progress, post-read sealed changes, invalid
unique health rows, historical worker separation and UI request races. Author qualification now passes 74 Rust checks, 26 Operations Node checks, strict all-target v2 Clippy and 13 semantic mutants with restored assertions. Evidence is in `.design/reviews/kan-v2-overview-correction-author/`; fresh re-review remains pending.
The final cold review returned APPROVE WITH FOLLOW-UPS for the overview, with O1 a required code correction, and APPROVE for the storage corrections. The raw report and independent probes are preserved unchanged in `.design/reviews/kan-v2-overview-opus/`. Fresh review of the corrected overview remains required.

## Authenticated overview browser follow-up

The merged source now has author-run browser evidence for unavailable, building,
completed, failed, cancelling, cancelled, capacity-limited and client-derived
superseded states. Old totals survive failed/cancelled/capacity-limited refreshes
with explicit labels. Light/dark and 390-pixel wrapping were inspected; lock clears
metadata. Evidence and exact fixture limitations are preserved in
`.design/reviews/kan-v2-overview-browser-followup/`. This was collected after the
7ab1afa independent-review export; it does not change that review's scope or verdict.

## Current cold-review disposition

The fresh combined review approved the overview correction at262cad3 and lifecycle
at7ab1afa with follow-ups; required writer exclusion is resolved. Full compatibility
execution passed310 checks on macOS. Sustained back-to-back writers can still
starve overview refresh, and practical overview capacity remains about64.5k
identities; refusal is visible. Backend deadline/revalidation/window regression
seams remain follow-ups.

A separate cold review approved the restart rendering fix at7126848 with
follow-ups. Its12 probes plus an author queue-repeat regression are now in CI;
49operations checks pass and11UI mutants fail named assertions. Evidence and
provenance are in `.design/reviews/kan-v2-overview-restart-opus/`. The production
fix has not changed after that review. The broader browser matrix was collected
before the restart fix; actual file download delivery remains unverified.

## Recovery and reconstruction checkpoint (2026-10-19)

Fresh actual Opus 5.5 session f4340dd8-27d1-4af5-9a11-982f98a676d0 reviewed
frozen 7b44429 (PR #297): migration pre-open correction APPROVE; inventory
corrections APPROVE WITH FOLLOW-UPS; recovery direction and pure decoder APPROVE
WITH FOLLOW-UPS. Inventory adapter lifetime/WAL and interruption mapping remain
required. Decoder strictness and explicit format decisions are being qualified
before consumers. No parent frontend or reconstruction AC is complete.

The recovery design now names the four residual design points: external-only
restart provenance; forensic recovery for non-BLOB/unrepresentable cells;
publication blocked by unrecoverable staged/orphan keys; and custody checks before
any SQLite open. These owner-visible limitations must survive into job/API/UI
behavior. DDL, wire fixtures, codec, writer, RPC and browser acceptance remain
separate work; full sessions/search/annotations/views/day/admin stay on the roadmap.
