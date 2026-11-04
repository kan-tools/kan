# Feature: V1-style record and recall over v2, with bundled extraction

## Current refinement — owner decisions, 2026-11-04

The next design is
[semantic progressive disclosure and offline consolidation](kan-v2-semantic-disclosure-and-consolidation.md).
It records the owner's selections: all five built-in flows, explicit runs plus
opt-in post-finalization processing, and authored-first recall with a labelled
derived supplement. It grounds the semantic direction, witness-preserving
relations, normal reading/evidence fallback and replaceable decision workers in
the existing fold. A local decision-model setup is being investigated; an
official local Jev runtime has not been identified and no alternative installed.

Future Sonnet acceptance starts with fresh sessions and disposable state. Do not
resume the old readers. All old trials remain retained. At74922b7, scoped checks
and provider-offline readback passed, but the final resumed reader stopped with
a provider safeguard refusal before completing its source check. Certification
and independent review remain incomplete. Later historical checkpoint paragraphs
below describe their own revisions; they do not authorize another continuation.

## Summary

Restore the simple deliberate-recording and budgeted-recall workflow over v2's
shared service APIs. Capture, search and post-session extraction support authored
knowledge; retrieving a recorded decision must not require replaying a transcript.
Provide a bundled extraction/summary path whose output is a reviewable derived
report. Turning that report into an authored annotation remains an explicit act.

Owner decisions, 2026-11-02: preserve v1's familiar verbs and typed meanings where
possible; initial extraction output is a report with explicit annotation promotion.
These decisions follow the approved agent-usability build and the subsequent
product design review. This document refines its next implementation contract;
it is not a claim of implementation, runtime acceptance or Day compatibility.

No system binary replacement, live migration, production credential change,
merge, tag, publication, deployment or deletion is authorized here. No new paid
agent trial has started. A paid demo needs an explicitly selected model, provisioned
credential reference, input scope and spend limit before execution. Existing failed
pilots and all retained stores remain intact.

Process recording follows AGENTS.md's Git-first day#168 / kan#197 exception.
Live Day schema validation, claim recording, telos/bridge interrogation and claim
backfill remain pending. They are not empty or passing results. The skill's
suggested docs/CONVENTIONS.md is absent from this checkout; this file is not a
substitute for validation against the actual process schema.

## Initial product and evidence — historical context, 2026-11-02

- Released baseline is `8852067e6daf34348bf5e687c8c2ac19b3023e32` / beta.1.
  The private agent-usability build at
  `d937769623ae00ead740b2f6899003ca8b3da875` is qualified but unmerged. The
  installed laptop binary remains `kan 0.13.0-beta.1`.
- `src/cli/mod.rs` and `src/actions.rs` implement v1 recording, correction,
  structuring and recall with typed claims, explicit authors, citations, anchors
  and fold/trust semantics. Their JSON contracts are consumed by Day.
- `src/bin/kan-v2.rs` primarily exposes service, capture, Library and operational
  commands. Its Library request option and MCP share `src/evidence_library.rs`.
  There is no v1-style record/recall facade on the v2 executable today.
- `src/evidence_library/proof/knowledge.rs` offers annotation preview/save/list,
  corrections, withdrawals and relations. Its draft currently requires 1–8
  captured-evidence citations. Its authorization path also excludes declarations
  without citations. Merely relaxing validation would neither establish note
  scope nor safely implement uncited authored assertions.
- `src/evidence_workspace/annotations.rs` persists encrypted workspace records.
  Annotation publication is separately composed in
  `src/evidence_library/proof/outbox.rs`. A local save is not an archive receipt.
- `src/claim/mod.rs`, `src/claim/codec.rs`, `src/claim/view.rs` and
  `src/fold/claim_view_state.rs` already describe current/legacy typed semantics.
  `src/evidence_library/proof/imports/current.rs` projects imported typed claims
  under selected identity/control evidence. Tags on a generic note are not an
  equivalent implementation of these contracts.
- `src/evidence_library/proof/analysis.rs` already implements explicit bounded
  analysis previews, persisted jobs, retry lineage and source rechecks.
  `src/evidence_library/proof/analysis/adapters.rs` provides the generative
  Anthropic Messages adapter. Use the existing configured collector/gateway;
  provider credentials do not belong in CLI output or agent prompts.
- Current analysis input assembly is bounded to eight cited occurrences and a
  configured byte budget, and presents capture frames individually. A bundled
  session extraction must plan coherent selected input and report gaps instead
  of taking an arbitrary first eight records or silently losing long inputs.
- Both Linux and macOS qualification passed at d937769. The explicit continuation
  of the real Sonnet reader still failed the retrieval task despite every reply
  fitting 12 KiB. It stopped in the chronological prefix of one large captured
  request before the decision/source pins. The answer is retained; this is not a
  demonstrated storage failure. Captured Write inputs can contain authored text,
  while the normal renderer omits accumulated tool JSON. No independent review
  of this agent-usability feature has launched.
- Exact private evidence remains in
  `.local-state/agent-usability-20261101/pilot-evidence.json` and
  `.local-state/agent-usability-20261101/pilot-report.md`. Original results and the
  one continuation are retained separately. Do not rerun them as a new demo.

## Requirements

- REQ-1: Provide v1-style recording, structuring, correction and recall through a
  v2 CLI facade and equivalent typed MCP tools over one shared action contract.
  Preserve typed intent, author identity, subject/reference semantics and trust;
  do not replace decisions, status or relations with opaque tag conventions.
- REQ-2: Allow an authorized author to record a statement without prior transcript
  capture or an evidence citation. Authored scope and read/write authorization
  are explicit independently of citations. Uncited, cited and model-derived
  statements remain distinguishable. No missing governance/admission is invented.
- REQ-3: Return a stable record reference and explicit local/queued/acknowledged
  durability state. Ordinary recording does not require hand-built pins, preview
  JSON, separate manual publication calls or owner credentials. Existing explicit
  profile configuration fixes any automatic queue/delivery destination.
- REQ-4: Recall authored records directly by subject/reference and through a
  bounded context view, retaining correction history, contradictions, trust
  framing and omission disclosure. Supporting evidence can be expanded without
  requiring complete session reconstruction. Read-only tools cannot record.
- REQ-5: Existing v1 commands, signed records, CIDs, identity/trust and fold results
  remain unchanged. A compatibility matrix states which v2 behaviors and versioned
  JSON shapes match v1 and which require an explicit translation. Partial parity
  cannot be advertised as a compatible replacement for Day/v1.
- REQ-6: Separate operator configuration from normal use. One explicit private
  project/profile resolves the existing permitted source, destination, signer,
  reader workspace and credential references across its authorized worktrees.
  No inferred linked-worktree scope, global install or ambient key discovery.
- REQ-7: Bundle a versioned post-session extraction and summary recipe over exact
  selected evidence. Plan inputs using shared authenticated decoding, retaining
  original source references, ordering claims, missing/unsupported states and
  excluded ranges. Large input requires explicit bounded batches or refusal.
- REQ-8: A Sonnet API worker uses the existing configured inference adapter and
  gateway with separately supplied provider credentials, input allowlist, byte/
  token/job/spend limits and no arbitrary tools. Record actual returned model,
  recipe/prompt revision, exact input manifest, outputs and available usage.
  No automatic paid retry follows an interruption or provider failure.
- REQ-9: Extraction first produces a readable derived report with stable reference,
  citations, uncertainty, exclusions and run lineage. It is not an authored
  decision, accepted claim or instruction merely because a job succeeded.
  Explicit promotion retains run provenance and permits review/edit before save.
- REQ-10: Provide a supported demo runner using the same interfaces as ordinary
  users: explicit documentation versus independent post-session extraction over
  one frozen working-evidence set. Fresh readers receive no expected answer or
  filesystem/raw-offset workaround. Retain both successes and failures.
- REQ-11: Normal CLI/MCP output remains bounded and readable; continuations retain
  current authorization and exact source binding. Compact reusable references
  reduce repeated protocol objects without becoming durable read capabilities.
  Preserve document/tool input content needed for recall with explicit coverage.
- REQ-12: Keep existing Day/v1 and Git as the operational research workflow until
  the separately qualified adapter/cutover gate passes. The demo uses disposable
  stores and no dual writing of an authoritative live research record. Preserve
  original stores, capture gaps, backup evidence and failed experiments.

## Acceptance Criteria

- [ ] AC-1: A verb-by-verb fixture matrix compares observe/plan/decide/result,
  block/resolve, same/relate/mark, retract/reject and show/status/issues/context
  semantics with v1. Unsupported behavior refuses explicitly; a tag-only mapping
  cannot pass typed decision, status, identity or relation cases. (REQ-1, REQ-5)
- [ ] AC-2: Create an attributed statement in a disposable authorized scope with
  capture disabled and no citations; read it after restart. Cross-scope and
  reader-only writes fail. An empty citation set cannot bypass note-scope access.
  Scope admission/trust unknown states remain explicit. (REQ-2)
- [ ] AC-3: Record, return the stable reference, read back, enqueue/deliver, restart
  and retry without duplicate records or changed identity. Offline/failed delivery
  reports local durability and pending state; local save never claims archive
  acknowledgment or independent backup. (REQ-3)
- [ ] AC-4: Fresh CLI and typed-MCP readers retrieve the explicit decision, source
  revision/hash, reason and uncertainty by subject/context. Correction/retraction,
  conflicting-author and trust-exclusion controls pass. No transcript replay,
  invented source authority or missing-field reconstruction is needed. (REQ-4)
- [ ] AC-5: Existing v1 byte/signature/CID/JSON fixtures pass unchanged; compatibility
  results separately cover native v2 authored records and imported originals.
  No Day consumer is redirected, and full Day compatibility remains unclaimed
  until its separate contract tests pass. (REQ-5, REQ-12)
- [ ] AC-6: Two explicit worktrees share the selected private profile; an unrelated
  project is refused. Routine record/recall requires no owner configuration,
  global binary replacement or manual signed-token assembly. (REQ-6)
- [ ] AC-7: The real extraction planner handles multi-occurrence messages and
  decision-bearing tool inputs, reconstructs exact source-attributed inputs and
  reports partial/unsupported data. Over-budget plans refuse or expose selected
  batches and exclusions; no silent first-eight truncation. (REQ-7)
- [ ] AC-8: Fake-provider qualification covers provider errors, malformed/truncated
  output, current revocation, cancellation, interruption and exact-retry rules.
  One explicitly budgeted real Sonnet API run records actual model/recipe/input/
  output/usage; missing usage is labelled unavailable. No secrets appear in logs.
  (REQ-8)
- [ ] AC-9: Reading a report creates no annotation or trusted decision. Explicit
  promotion previews the author, text, subject and citations; save/readback retains
  run lineage and edits. Later correction retains original report and declaration.
  Prompts and captured instructions cannot enable promotion or tools. (REQ-9)
- [ ] AC-10: In the demo, both fresh readers recover the chosen decision, source
  revision/hash and unresolved boundary with resolving citations. Compare wrong
  or unsupported conclusions, omissions, retrieval calls/bytes, elapsed time and
  model usage. The extractor cannot read the explicit documentation arm's notes
  or later outputs; the evaluator's expected answers are inaccessible to both.
  Report each arm independently; exit 0 is not task success. (REQ-10)
- [ ] AC-11: Every normal output fits the declared bound; large Unicode messages
  and tool arguments remain recoverable, not silently omitted. Query/reference
  mismatch, current grant revocation and unavailable evidence controls pass.
  Fresh readers do not copy large selection sets per page as the normal path.
  (REQ-11)
- [ ] AC-12: Demo cleanup stops owned services and retains disposable stores,
  reports, gaps, failed attempts and credentials privately. Existing original
  pilot/recovery evidence is neither repeated nor relabelled current-runtime
  qualification. System binary and live Day/v1 stores remain unchanged. (REQ-12)

## Architecture

### Semantic compatibility before command aliases

Reuse the canonical claim codecs and deterministic view/fold implementation where
applicable, with an explicit service-backed action boundary. `src/actions.rs`
currently depends on a repository Workspace; simply invoking it through a hidden
kan-v1 subprocess would preserve the old storage/discovery problems rather than
provide the selected v2 interface. Separate pure command intent/read projection
from repository-specific I/O before choosing which action code to share.

The first engineering deliverable is an exact compatibility matrix with typed
examples and source references. It must settle how authored v2 records use the
existing claim codecs or a versioned annotation envelope without losing kind,
subject identity, correction/retraction or author/trust semantics. Existing
kan-annotation/1 publications remain readable; do not silently add fields that
old signed-envelope validators reinterpret. No second fold or competing source
of truth may be introduced as a shortcut.

Evidence citations and claim-to-claim citations have different types and meanings.
An authored statement needs an explicit scope even when it has no evidence cites.
The current requirement that every annotation cite a captured occurrence cannot
be removed until authorization, persistence, publication, restoration, erasure
and correction handling all cover that explicit scope. Keep source access checks
for citations that are supplied; do not erase provenance when sources disappear.

### Common record/recall surface

Proposed familiar CLI verbs are observe, plan, decide, result, block, resolve,
same, relate, mark, retract, reject, show, status, issues and context. They are
not available on the current v2 CLI. Equivalent action-specific MCP schemas call
the same shared action contract. Existing service/recovery commands retain their
meaning. Exact option spelling and versioned JSON are frozen with the compatibility
matrix, not guessed from examples in this draft.

Resolve profile configuration once at launch, with distinct read, annotation-write
and owner authority. A routine explicitly requested record operation may compose
its existing preview/save/readback internally and retain the receipt; this does
not require another human confirmation for every ordinary note. Sensitive owner
operations keep their separate plan/consent boundary. Delivery may continue in an
explicitly configured outbox, with honest local versus acknowledged states.

The human UI makes authored records and derived reports independently reachable.
Show an explicit statement without asking the reader to discover its source frames
first. Offer supporting evidence and full history as adjacent views. Context
assembly must label which entries are authored, model-derived, imported or captured,
and state its token budget, trust frame and exclusions. Search supplements exact
subject/reference reads rather than making those reads depend on an LLM.

### Bundled extraction and summary

Extend the existing analysis engine and adapters instead of introducing a second
scheduler or model-response store. A versioned recipe bundle produces a readable
report of decisions, results, open questions, source revisions and supporting
citations. The planner records the selected evidence frontier and decoded input
manifest before submitting bounded work. Source bytes are rechecked under current
authorization before dispatch; no cached plaintext bypasses revocation.

Reuse source-attributed decoded content when assembling model inputs. Avoid both
raw frame replay as the default prompt and silently discarding tool-input content
that contains authored documents. If several bounded batches are required, retain
per-batch manifests and connect the final report to all source runs. A synthesis
report cannot claim coverage of omitted, unavailable or never captured inputs.

Use the Anthropic Messages adapter with a separately configured Sonnet model via
the collector/gateway. "Offline" means post-session processing, not network-free
inference. Provider API keys remain in private operator-supplied files; they are
not inherited from Claude Code login or printed into configuration examples.
Prefer explicit on-demand submission for the first bundle. Existing optional tag
triggers remain opt-in; merely saving or reading this report cannot promote it.

A report is addressed and retrievable directly. Its content and references must
fit ordinary CLI/MCP pages without copying the provider's full raw response.
Original request/response and usage remain separately inspectable run evidence.
Explicit promotion uses the checked typed record-preview/record path in the authored annotation envelope, with derived-from
lineage; authorship of the promotion does not retroactively make the model output
independently verified.

### Controlled two-path demo

1. Create a new disposable public/synthetic toy project and working session under
   a bounded, explicitly approved model budget. Do not reuse production keys or
   repeat the retained original pilot, backup or large capacity fixtures.
2. Freeze the common working-evidence frontier and input manifest before producing
   either documentation result. Define the expected decision/source/uncertainty
   privately for evaluation; never give those answers to the fresh readers.
3. Explicit arm: prompt the working agent to deliberately record the documentation
   through the v2 record interface. Save/readback checks the real authored records.
4. Extraction arm: independently run the bundled post-session recipe over only the
   frozen working evidence. Exclude the explicit arm's documentation session,
   annotations and later generated reports from its permitted input.
5. Use separate fresh reader contexts with the same retrieval task and comparable
   budgets. One uses authored records, the other the derived report; either may
   expand exact supporting evidence through the ordinary typed read tools.
6. Evaluate each outcome and its coverage, quality, citations, retrieval effort,
   timing and usage. Do not turn a good summary into proof of author intent or
   independent review. Permit an explicit separate promotion demonstration only
   after report inspection. Retain refusals and failures as results.

## Resolved Questions

- Preserve v1's familiar verbs and typed meanings wherever possible; command-name
  parity without semantic parity is insufficient. Owner confirmed 2026-11-02.
- Bundled extraction initially produces a reviewable derived report; annotation
  promotion is explicit, not automatic. Owner confirmed 2026-11-02.
- Deliberate annotation and recall are a primary workflow, rather than requiring
  capture and later extraction to manufacture every useful research record.
- Keep the established Day/v1 research record and Git operationally unchanged
  until separately qualified compatibility and cutover; the demo is isolated.

## Open Questions

### Q1: Canonical authored-record and compatibility envelope — resolved for implementation
The bridge uses canonical, explicitly labelled kan-claim-v1 typed records carried
through v2, with the existing fold. It does not silently rename these records as
kan-claim-v2 or turn storage scope into governed identity. Native current-codec
records retain their original control-evidence requirements. A separate versioned
authored envelope preserves existing kan-annotation/1. See the concrete
[compatibility matrix](kan-v2-record-compatibility-matrix.md). This is an
implementation choice under the approved semantic-parity requirement, not a runtime
compatibility result or permission to replace Day's existing consumer.


### Q2: Prior demo execution — resolved historical choice; no fresh run authorized
The owner selected Sonnet5.5 through normal Claude Code sign-in. The comparative
trial ran using a test-only local bridge, not a direct provider API credential.
Its extraction succeeded once; later reader continuations remain failed/partial
acceptance, including the terminal provider refusal. The2026-11-04 refinement
requires fresh sessions and disposable state for any future test, preserving all
prior evidence. A new task/input/model/budget plan must be selected before that
execution; prior remaining allocation is not blanket approval. No secret value
belongs in the design or an agent prompt.

## Out of Scope

- Automatic annotation promotion or treating summaries as authoritative decisions.
- Running new paid jobs, changing credentials or live routes merely to draft this
  design; an actual demo has a concrete selected input/model/budget first.
- New plaintext retrieval stores, duplicate research ledgers, a second semantic
  fold, a provider-specific archive format or storage authorization from a citation.
- Retiring Day/v1, rewriting original claims/CIDs, migrating live research stores,
  upgrading the system binary, deploying services or publishing a release here.
- Repeating original failed inference/drills/capacity fixtures or deleting retained
  stores, snapshots, backups, keys, logs or volumes.


## Integrated implementation checkpoint — qualification pending

The approved build now has a shared typed record/preview/recall contract, a
private project profile and familiar CLI verbs, typed MCP author/read separation,
and browser authoring/recall. Canonical compatibility batches preserve typed
narratives, statuses, relations, retractions and rejections, with atomic append,
explicit retry operation, signed inner CIDs and separate publication state.
Ordinary v1 code/bytes are not rewritten. New authored envelopes are version 2;
ordinary annotation envelopes remain version 1. Sender custody must enroll the
uncited record collection independently of optional evidence citations.

Bundled extraction plans pin an explicit bounded interval and use shared decoded
streams, including tool arguments. Reports remain derived; report reads require
no provider configuration and promotion previews the edited authored operation.
The demo helper freezes input before the explicit-doc arm and retains create-new
operational receipts/readbacks. It does not itself launch agents or infer task
acceptance. Its retained controls cannot substitute for actual fresh readers.

The old capture-only author/reader trial and its one changed-code continuation
remain failures for agent acceptance, with successful backend recovery controls.
Neither is relabelled a pass by this implementation. The new two-arm exercise
uses new evidence and separately selected model/credential reference/spend; no
new paid inference or review has been launched at this checkpoint. All AC boxes
remain pending remote runtime qualification and the actual bounded exercise.

Explicit boundaries: default `me` is narrower than v1 `local`; explicit local and
DID/weight membership are available, role aliases refuse. Imported originals,
Git-computed ancestry and complete Day JSON/cutover are separate contracts. This
is not an upgrade of the installed system binary or the live research ledger.


### First runtime qualification findings — 2026-11-02

The first compiling revision exposed invalid decimal revision strings in new
canonical record envelopes: the unchanged v1 codec requires 13-character ATProto
TIDs. The correction reuses the original encoder for transaction-assigned append
order, checks its range, and verifies that every retained envelope matches that
order. Author-attested time remains separate. No invalid envelope was accepted by
the codec; failed operations and their diagnostics remain retained.

The extraction planner also stopped at the first newest-first inventory row.
It now scans through the inclusive lower bound, then orders the complete selected
interval chronologically. The actual provider integration test checks all three
frozen selections against the signed inventory and still refuses a missing row.

Existing install/migration-notice assertions that all familiar verbs were absent
are updated for the approved profile-scoped recording surface: v2 recognizes
`observe`, requires an explicit profile, and must leave a detected legacy store
untouched. Legacy-only `publish` remains refused by v2. These boundaries require
remote qualification; fixing source or passing formatting is not runtime proof.


### Real comparative trial finding — paginated report references

The Sonnet5.5 Claude Code extraction actually succeeded over seven frozen working
records, but its normal report read refused the 12 KiB budget. Input URI metadata
was repeated outside the paginated text field, so seven references could make
every page oversized. The correction paginates input references and text together
under one query/evidence-bound presentation cursor, preserving their stable input
numbers, all references, availability and complete text. Current authorization is
still rechecked for every page. The original successful job/result is retained;
qualification must read it without invoking extraction again. The fresh derived
reader and independent review remain pending until that changed code qualifies.


### Real fresh report-reader finding — compact input locators

The fresh Sonnet reader recovered the source revision/hash, decision, rationale
and uncertainty through two normal report pages, then changed one character while
copying a 1064-character capture URI for a supporting read. The altered reference
correctly failed verification; the reader disclosed that it had not checked the
underlying source. Preserve that original partial result. REQ-11's compact common
path now includes report-id/input-number locators through the existing typed
reference tool/shared action. These are not cached grants: every page rebinds all
report sources under current access before the ordinary reference/content read.
The report text, original frozen inputs and single provider result stay unchanged.
After remote qualification, continue only that same reader explicitly on the
changed interface within its original remaining spend allocation; do not rerun
authoring, extraction or a fresh inference unchanged.

### Operator readback finding — report references need frozen reconstruction context

Qualified compact handles resolved correctly, but input 4 of the actual report is
one body chunk: a single-occurrence read disclosed missing start/body ranges and
contained no readable items. No reader continuation was spent on that known gap.
The report handle must reconstruct its original bounded frozen input manifest
through the shared authenticated reader, then present complete decoded items whose
text or tool input intersects the focused input. States, original item attribution
and citations remain intact; enclosing items may cross input boundaries. This is
explicit selected context, not an expanded live search or completeness assertion.
Direct occurrence URIs retain their single-occurrence behavior. Rebinding all
manifest tokens to one fresh pin must preserve order, foreign-reader attribution,
current grants and source availability, without an Engine, cached plaintext or
another provider call. Regression checks must distinguish single-chunk partial
state from the same frozen context's readable source and preserve focus lineage.

### Terminal agent finding — readable input navigation

The same-session reader continuation correctly reported failure: it completed
metadata-only input5 and began6, but never opened a text-bearing input. Its actual
returns confirmed no readable bodies in those focused views; the input4 operator
control remained exact and readable. Preserve this failed acceptance result.
REQ-11 now requires an explicit focused readable-item count, a clear metadata-only
explanation and compact hops to readable inputs and each cited input. Derive these
only from the current shared decoded manifest; no new provider, cache, source
selection or authority. A zero-readable manifest remains explicitly unavailable.
The new testing tiers in the active SOP govern focused qualification and the
owner-authorized next bounded certification step; no broad matrix per UX patch.
