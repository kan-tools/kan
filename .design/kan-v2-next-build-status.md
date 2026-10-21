# Kan v2 — feature-complete build, then review

## Active development flow — owner decision, 2026-10-19

The owner explicitly retains the full v2 scope and replaces checkpoint-by-checkpoint
review with continuous implementation/integration, followed by a thorough review
of the feature-complete product. This section is the single current completion
checklist and execution policy. Checkpoint tables below are historical evidence;
they do not prescribe another review loop or the current build order.

The product target remains `.design/kan-v2-server-first.md`,
`.design/kan-v2-buildout.md` and `.design/kan-v2-human-frontend.md`.
A minimal demo is useful verification, but does not replace feature completeness.

### Completion checklist

Mark a row complete only when its backend, shared API/CLI where applicable, human
workflow and relevant failure behavior work together. Existing component tests
and reviews are foundations, not automatic end-to-end completion.

| Work package | Completion means | Current position |
|---|---|---|
| Capture, storage and migration | Supported harness/provider traffic reaches the centralized encrypted ledger; spool/retry and visible recording gaps work; v1 imports reconcile against preserved originals; local and remote use the same server architecture | Implemented centralized encrypted capture/import, proxy/gateway forwarding, durable spool and exact retry, visible recording gaps, preserved-source v1 reconciliation, and admitted/copied proof archives. Indexed archive and current-control reads separate ordinary service I/O from explicit full audits. Managed root-path launch, live spool delivery and cold restore extensions are in remote qualification. The 11 MiB / 179-frame indexed workload passes; real 10/100 GiB measurements remain required and need an appropriate remote disk. |
| Library and sessions | Authorized cross-project browsing, readable complete supported conversations/tools/attachments/branches/compaction/gaps, exact source/provenance and working downloads; missing/corrupt evidence stays visible | Implemented cross-archive browsing, reconstructed supported conversations, explicit sessions/parents/branches/compaction, streaming gaps, attachments, exact provenance and native downloads. Existing API/browser checks pass. Current indexed managed CLI composition, current loss and live revocation are being requalified; final integrated acceptance remains. |
| Search and views | Authorized search/facets, stable references, honest index coverage, reproducible saved scope/trust views and relation inspection | Implemented encrypted persistent raw/reconstructed search, filters/facets, current source authorization, pinned saved views and portable references. View lists page beyond 200 records, survive restart and withhold revoked evidence. Source, annotation and import-trust filters have passing runtime coverage; final integrated acceptance remains. |
| Knowledge and annotations | Imported v1 claims and raw/derived evidence remain distinguishable; human/agent tags, annotations, relations and corrections use shared attributed append-only records with citations/history | Implemented signed attributed annotations/tags/relations, corrections/withdrawals, exact citations, publication/restoration and imported v1 identity/trust/fold views. Annotation pages cross 1,000 records with off-page history and current access checks. Shared API/CLI/MCP/UI knowledge-graph pagination is implemented; 119 Library UI checks pass and extended graph runtime qualification is pending. |
| Analysis and day integration | Explicit and tag-triggered background extraction/summary/assessment jobs, grants/quotas, retries/cancellation, recipe/model/input/output lineage and inspectable results | Implemented explicit and tag-triggered recipe jobs, summaries/day assessment, fixed input/destination grants, quotas, cancellation/retry, interrupted status, lineage and explicit result promotion. Lifecycle, publication and correction/withdrawal integration has passing runtime coverage. Requirement inspection found the adapter was Anthropic-only. An explicit TypeSafe System One adapter and fixed-route collector/gateway profile now support typed decisions with retained distributions and honest output bounds, shared preview/job APIs and human inspection/promotion. All 120 Library UI tests pass; protocol, two-hop credential separation, multiple-run retention and retired-provider history tests await remote qualification. Final integrated acceptance remains; no production traces or paid model calls were made. |
| Administration and operations | One human application exposes source/queue/gap health and authorized previewable jobs for rotation, backup/restore/recovery, migration, access, key lifecycle, settings and explicit erasure; interrupted jobs reconnect honestly | Implemented preview-bound owner jobs for backup/recovery/import, history-preserving rotation, policy and key lifecycle, independent custody, selected-capture/archive-prefix erasure, resumable derived/publication/queue/replica cleanup and separately authorized backup purge. Completed-selection consent, restart/intervening custody and stale approval passed at 2f91b45. Archive/control index maintenance jobs and managed activation are in qualification. Workspace dependency cleanup now falls back beyond 65,536 cached edges and streams selected annotation bodies; its new tests await CI. Execution deadlines remain explicit; no claim of constant-memory graph discovery or irrecoverability from old keys/backups. |
| Complete application | Coherent navigation across every area; accessible responsive light/dark/system UI; setup/restart/upgrade/backup/restore instructions and end-to-end synthetic qualification | Implemented one Library/Operations UI with responsive light/dark/system appearance, shared API/CLI/MCP, independently enrolled managed launches and documented upgrade/restore paths. Cold-host recovery composes archive, wrapped keys, workspace and references. Package assembly includes both frontends; CI file-list checks now pass. Final current-revision whole-application qualification, packaged-source compilation, scale evidence and the single fresh Opus 5.5 review remain. |

No silent reduction of the approved feature scope. Unsupported provider formats
must remain inspectable and labeled; expanding adapter support follows the agreed
contracts, not an unbounded claim to parse every provider. Day process features
remain required. Live installation, production keys, migration/cutover and main
merge retain their separate authorization boundaries; implementation and synthetic
qualification can finish without those operations.

### Build loop

1. Work continuously on the existing permanent integration tip
   `.worktrees/kan-v2-proof-library`, branch `feat/kan-v2-proof-library`.
   Preserve the existing draft stack and root checkout's unrelated changes.
   Do not create a branch, worktree or PR for each helper, test or review follow-up.
2. Finish the Library candidate's Rust/CLI/browser checks, then complete the work
   packages above in dependency order. Move directly from functioning integration
   to the next missing feature. A working demonstration is a checkpoint, not the
   finish line for the whole build.
3. Design only unresolved contracts needed by the next implementation. Reuse the
   accepted architecture and record concise decisions in its relevant document.
   Do not introduce a new process document or evidence ledger per small change.
4. Keep ordinary engineering validation during implementation: compile, run the
   affected tests, check real API/UI integration, and fix regressions. Preserve
   meaningful security, persistence, migration and provenance tests. Run broader
   checks when changes cross boundaries, and once across the integrated build.
   No routine full-suite repetitions, exhaustive mutation matrices, fresh external
   reviews or whole-change reversion demonstrations at every checkpoint.
5. Fix concrete correctness, data-loss, authorization and integration defects as
   they arise. A new validation pass must answer a named unresolved question;
   additional evidence volume alone is not progress. Nonblocking review suggestions
   do not automatically generate another build/review cycle.
6. Update this checklist at completed user workflows or material blockers. Report
   what a human can now do, what remains, and the next implementation target;
   avoid presenting test counts or review artifacts as the main accomplishment.

### Integrated completion and review

When all work packages are implemented, run a complete synthetic instance through
capture/import, browse/session/search, source/export, annotations/views, analysis,
admin/recovery and restart. Exercise loss, revocation, retry and incomplete coverage
along the relevant paths. Include realistic large records so the original capacity
pain is actually addressed. Record one concise capability/test map; fix failures.

Then freeze one integrated revision and run a thorough fresh actual Claude Code
Opus 5.5 review against the full product requirements. One review campaign may
organize its work by risk area, but every area judges the same integrated product.
It must cover architecture, trust/encryption, append-only provenance, recovery and
migration, feature completeness, shared API/CLI/UI behavior, failure handling,
resource bounds and browser usability. Reuse valid existing evidence and inspect
actual behavior; use targeted adversarial probes where they resolve a concrete risk.
No mandatory number of mutations, tests, reports or review rounds.

Triage findings by effect: fix broken required workflows and correctness/security/
data-integrity defects before acceptance; retain optional improvements in a backlog.
Re-review the material fixes and their affected boundaries, not the entire unchanged
system. A new independent full pass requires a material architecture change or
review evidence that the original pass missed its target. After the final targeted
regressions and whole-application checks pass, prepare the sequenced merge/release
plan using the preserved draft history. Do not merge/deploy merely because review
completed.

### Starting state and evidence reuse

- Recovery/pinned inventory author qualification at a2666df passed 138 integrations,
  strict v2 Clippy and formatting. The later fresh review at b01b62f was interrupted
  at the owner's request; it has no final verdict and is not a prerequisite to resume
  implementation. Its partial evidence is retained locally, not acceptance.
- Proof service/Reader author qualification at bdbf136 passed 82 integrations plus
  strict Clippy/formatting. The Library candidate is committed through c4e7f03;
  58 Library UI tests (111 total frontend tests) and six focused UI fault controls
  passed. Library Rust/CLI/browser qualification remains open.
- Existing completed reviews keep their exact scope and revision. Do not restart
  them merely to produce another report. The final integrated review evaluates
  composition and remaining uncertainty.
- Keep one shared Cargo target, four jobs and one heavy job at a time; obey the
  machine's disk threshold. No Mathlib builds, new worktree dependency caches or
  abandoned servers. Retain raw review output locally and publish only inspected
  concise results. Git-first process recording remains in effect under day#168 /
  kan#197; do not reconstruct excluded claims or invent witnesses.

### Integrated acceptance map

These are executable paths through the product, not completion checkmarks. Unless
qualified at a named revision above, their current outcome is still pending CI.
The proof Library cases below live in `tests/support/proof_library_tests.rs` and
run through `tests/evidence_inventory.rs`; they call real HTTP services and retain
encrypted synthetic evidence. Frontend unit checks alone do not close these rows.

| Human workflow / requirement boundary | Executable integration evidence |
|---|---|
| Capture without blocking inference; exact bytes and explicit gaps | `tests/evidence_capture.rs`: `binary_stream_above_ten_mib_has_exact_bodies_and_independent_frames`, `full_and_unavailable_capture_continue_with_visible_gap`; `tests/evidence_gateway.rs`: `two_hops_preserve_bytes_status_observers_and_exchange`, credential-separated provider profile cases |
| Managed deployment, spool delivery, restart, current loss | `actual_proof_service_and_library_cli_restart_with_missing_payload` runs the managed CLI, independent custody/policy and indexed admitted/copied readers; admitted mode delivers the actual encrypted spool through HTTP |
| Cross-archive sessions, search, pinned views, current grants | `session_content_preserves_archive_boundaries_membership_loss_and_revocation`, `search_reconstructs_chunked_messages_with_all_citations_and_rechecks_loss_and_access`, `saved_views_page_beyond_200_after_restart_and_recheck_current_access` |
| Attributed annotations, correction history, imported judgments, portable references | `annotations_preview_append_correction_preserve_cites_and_filter_revoked_sources`, `annotation_pages_cross_1000_keep_off_page_history_and_recheck_access`, `imported_current_claims_keep_signature_scope_authority_and_selected_trust_distinct`, `portable_references_rebind_for_another_reader_without_granting_access_or_hiding_loss` |
| Analysis and day assessment with immutable inputs/outputs | `analysis_retains_exact_lineage_quotas_retries_and_revoked_results`, `decision_adapters_retain_distinct_runs_and_read_history_after_provider_retirement`; TypeSafe responses are synthetic protocol fixtures, not a live accuracy/cost evaluation |
| Backup, cold recovery and legacy import without source mutation | `cold_host_restores_source_search_annotations_and_references_from_independent_backups`, `owner_import_pins_source_batches_exact_retry_and_preserves_originals`; `tests/evidence_import.rs`: `cli_resumes_large_malformed_snapshot_and_independent_decoder_recovers_exact_bytes` |
| Separate owner authority, access/key history, erasure and resumable cleanup | `owner_maintenance_uses_separate_authority_preview_exact_retry_and_new_outputs`, `owner_access_policy_previews_preserve_history_and_reject_reader_authority_and_stale_edits`, `owner_key_epochs_require_owner_preview_and_restore_wrapped_history_after_restart`, `owner_capture_erasure_revalidates_full_selection_and_resumes_offline_replica_after_restart`, `owner_complete_selection_resumes_batches_after_restart_and_intervening_custody` |
| Actual browser rendering, keyboard inspection, native downloads and lock | `scripts/check-library-browser.cjs` starts the real Rust synthetic fixture and Chromium, checks exact downloaded bytes, both themes at desktop/tablet/390px, missing/corrupt states, focus return, private-view clearing and no external resource loads. PR CI retains screenshots and the result. This new automation is pending execution; it supplements the earlier manual browser evidence and API/UI tests, not every administrative screen's visual acceptance. |
| Archive growth and bounded ordinary operations | `scripts/measure-v2-capacity.py`: true 10/100 GiB fixtures, fresh-process open/append/page/source distributions and RSS/I/O. The 10 GiB hosted job is running; 100 GiB requires the owner-selected remote disk. Neither the 11 MiB regression nor synthetic small smoke closes the scale criterion. |

Final independent review must assess the composition of these paths, the retained
failure evidence and human workflows outside the automated browser slice. It has
not started. No live capture, cutover, production migration or erasure is implied.

## Historical checkpoint records

## Current continuation checkpoint (2026-10-19)

The sections below retain the history of individual checkpoints. For the current
dependency order, use this table; a passing component review does not close the
full recovery or human-frontend acceptance criteria.

| Layer | Current evidence | Still required |
|---|---|---|
| Pure KANC2 decoder (#297) | Strict decoder and promoted independent regressions; latest independent scope-C review APPROVE | Pure assembly #303 passes local qualification; provider adapters, API and real session UI remain |
| Observation wire codec (#298) | Authenticated bounded envelopes and independent signed vectors; review APPROVE WITH FOLLOW-UPS | Semantic replay, physical format and publication checks |
| Streaming M1/O1/R1 (#299) | Reviewed framing; promoted boundary and deterministic cancellation tests; current CI green | Fresh review returned APPROVE WITH FOLLOW-UPS; UTF-8 test follow-through is in #300; digests alone confer no authority |
| Logical member (#300) | Fresh combined Opus scope-B review APPROVE for 5edb505; controls and whole-guard reversion reproduced | Physical consumers remain separate; replay constraint coverage is tracked in #301 |
| Observation replay (#301) | Frozen b52aa48 review APPROVE WITH FOLLOW-UPS; correction immediately verifies restored request signatures/bindings and adds 23 design-derived cases | Fresh combined review verifies writer-pass accounting and maximal-envelope labeling follow-through in #302; no physical publication authority |
| Pure occurrence assembly (#303) | Fresh actual Opus review APPROVE WITH FOLLOW-UPS at eb4f471; 13 integration checks plus cancellation unit and eight controls qualified | Four review-directed regressions and five semantic controls qualified; combined 84 integrations + four units pass. Provider interpretation, authorized API and human session browsing remain |
| Physical recovery and delivery | Read-only opener #302 correction received fresh Opus APPROVE WITH FOLLOW-UPS at eb4f471; physical empty-value follow-through passes 15 reader tests and strict lint | Creator/restorer/publisher, crash/reconnect jobs, RPC, spool proof integration and Library unavailable-evidence UI |

The Library's actual browser download remains unverified: IAB DOM access works,
but the latest synthetic download event timed out without a delivered file path.
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

## Integrated attempt discovery continuation

The proof Library can explicitly scan successive pinned inventory pages, group
verified capture records by archive/writer/observer/attempt and open their selected
Content or exact Source. Missing, corrupt and unrecognized records stay visible
and unassigned. No persistent plaintext index was added. Discovery windows retain
at most 500 descriptions; Content remains bounded to explicit 40-record selections.
Full linked sessions, large-attempt assembly and persistent authorized search remain.

Affected Rust Library/CLI integrations passed, including discovery continuation,
current payload loss, signed selection purpose and revocation. The 63 Library UI
tests and strict library Clippy pass. Real synthetic browser verification traversed
25 occurrences across two scan batches, changed archives, discovered a three-record
attempt and read its request Content without manual selection. Lock cleared the
view; no browser warnings/errors were observed. Fixture services and tab were
stopped. Independent review remains deferred until integrated feature completion.

## Attempt and explicit session integration

Large attempts have a dedicated API and bounded worker budget, avoiding the
40-record split in selected Content. Explicit incoming Kan session headers or
Claude Code membership headers now drive source-cited session navigation, parent
reading, branches and compaction claims. Conflicting claims remain visible and
neither branch nor compaction replaces earlier source. Continuous window scans
are stoppable; long derived text is paged. The collector carries Kan headers to
the gateway, which records and strips them before the provider.

Targeted Content/session/connection tests, the collector/gateway workflow and
strict all-target Clippy pass. The 66 Library UI tests pass. A real browser read
a parent through a session link, inspected the exact link source and cleared all
session state on lock; no warnings/errors were observed. The fixture and tab were
stopped. The encrypted 11 MiB / 179-record capacity regression passes with exact text and
177 payload-chunk citations, duplicate-selection refusal and current revocation.
The debug run took 498 seconds to prepare the archive and 107 seconds to read and
interpret it. The earlier 20-second bound failed; the dedicated attempt deadline
is 120 seconds. These timings are functional evidence, not performance acceptance.
Repeated full-archive audits during append and repeated metadata checks on reads
are concrete optimization work before release. The completed synthetic archive is
retained locally at `.local-state/large-attempt-fixture.sqlite` for reuse.

Cross-archive session views, fragmented HTTP metadata interpretation, persistent
authorized search/views, annotations, analysis/day and owner administration remain
required. No independent review is restarted at this checkpoint.

## Batched acquisition and cross-archive sessions

Proof Content and discovery now acquire bounded batches of up to eight records,
sharing one current metadata audit per batch while retaining individual source
checks and current authorization. The saved 11 MiB / 179-record encrypted fixture
passes with all 177 citations in 33.64 seconds, down from 106.91 seconds in the
previous debug run. Admission's 498-second setup remains unchanged. Neither this
read improvement nor any metadata audit confers write authority.

A tab-local cross-archive session workspace scans authorized archives round-robin,
with separate pins/cursors, explicit per-archive coverage, stop/continue and a
1,000-description window. It follows parent links across archive boundaries and
opens exact link evidence. Writer/observer boundaries and copied occurrences stay
distinct. Catalog refresh, snapshot refresh and lock discard derived workspace
state. This is not persistent search or complete automatic session normalization.

Affected proof service/reader/Library integrations, byte-bounded batch continuation,
legacy fallback, malformed replies, current loss/revocation and strict all-target
Clippy pass. The 70 Library UI tests pass. A real synthetic browser scan inspected 31 records
across two archives, displayed their shared explicit session, followed an admitted
child's parent into copied-archive Content ("Hello proof archive"), inspected the
exact 628-byte link source back in the admitted archive, and cleared all workspace
and source content on lock. No browser warnings/errors appeared; the tab closed
and the fixture stopped successfully.
Next work remains fragmented metadata, persistent authorized search/views,
annotations, analysis/day, owner administration and application integration;
write/read performance and actual browser file delivery remain release work.

## Fragmented metadata integration

Request metadata now reconstructs across selected capture records and discovery
pages. The human attempt/workspace controls resolve chunked session links under
fresh authorization; Content and session views retain every contributing byte
range. Incomplete, contradictory, malformed or over-limit documents yield visible
states without an invented link. The interpretation bound is 2 MiB per metadata
document; retained source does not inherit that limit.

The real proof API passes for admitted and copied archives, including discovery
on separate pages, exact citations, a removed middle fragment and revoked access.
Three reconstruction unit tests, 72 Library UI tests and strict all-target Clippy
pass. Browser verification resolved three fragments across scan pages, expanded
the session from one to two archives, exposed all three citations, opened exact
fragment bytes (298–65834) and cleared the derived data on lock. No console
warnings/errors occurred. The test tab and fixture stopped.

Persistent authorized search/indexing and reproducible saved views are the next
substantial implementation target. They must keep encrypted derived storage
separate from blind authoritative storage, report indexed versus ledger coverage,
and check current grants before results/counts/snippets. That implementation,
annotations, analysis/day, owner administration, performance and full application
qualification remain required; no full-v2 completion or final review is claimed.


## Current capacity evidence (2026-10-20)

The unchanged 11 MiB / 179-occurrence regression passed on the push CI capacity
job at 0e66ee3, retaining every chunk citation and current access check. Archive
preparation took 225.55 s and the read 59.44 s, versus 692.22 s / 57.06 s at d61df56
before bounded admission verification reuse. These use the same debug workload
and CI configuration on separate hosted runners. The roughly threefold preparation
improvement is useful evidence; it is not a production throughput guarantee.
No payload/chain audit was replaced with a cache hit. Current-byte changes and
source grants remain checked. Realistic sustained load and final integrated
qualification remain acceptance work.

Latest fully green integration baseline: `2f91b45` (PR CI 39502707104, migration
39502707118, perf 39502707116; companion capacity passed). Complete-selection
erasure, including restart/intervening custody and stale-consent handling, passed.
The indexed-storage work after that baseline is not yet runtime-qualified.

At `3697dd1`, MSRV/compiler, default workspace tests, migration, perf and the
separate indexed 11 MiB capture job passed. The broad v2 integration stage reached
83 passing inventory tests but failed one copied-index fixture while constructing
an invalid signed request, before its intended incomplete-copy assertion. The
fixture now supplies a valid predecessor; the queued managed ingest/restore,
maintenance and graph-pagination changes still need runtime qualification.

Package inspection also found nonportable filenames in historical review
artifacts. Cargo packaging now excludes `.design/reviews` while retaining the
independent `.design/tools` oracles, both frontends and v2 source. Local package
assembly (without compilation) succeeded at 3.2 MiB compressed. CI checks the file
list, and the release workflow now qualifies v2 features and compiles the actual
package before publication. The yanked `chacha20` 0.10.1 dependency is replaced by
its 0.10.2 patch; this and the packaging changes await remote qualification. No
release or registry publication has been performed.

Workspace cleanup no longer refuses a graph merely because its reverse adjacency
exceeds 65,536 edges. It falls back to repeated metadata passes with exact closure
and a 120-second work deadline; failure yields no partial selection. Selected
annotation bodies now stream individually into publication planning. Regressions
cover large unrelated graphs, erased-parent lineage, cycles, repeated passes and
failure before closure; remote qualification is pending. This is not a
constant-memory graph implementation or a guarantee for arbitrarily deep graphs.

At `0d67f28`, the real managed proof/Library CLI restart, indexed spool delivery,
cold-host restore, copied-index continuation and capacity smoke regressions passed.
The 11 MiB push job and migration matrix also passed. Broad qualification found
an obsolete owner-catalog count (two index jobs are now retained alongside the
erasure) and a 503 in the 1,003-annotation traversal after adding a short history
scan deadline. The count now selects the erasure by immutable job ID; history
scanning uses the existing 120-second long-read allowance and keeps the 8 MiB
related-metadata bound. API test failures now name the requested action. These
corrections and the queued adapter/graph work require requalification; this is not
a new full-green baseline or a claim that history scanning is constant-time.
