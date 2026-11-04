# Feature: Semantic progressive disclosure and offline consolidation

## Summary

Make ordinary Kan retrieval a semantic view over retained, attributed evidence,
assertions and derivations. Present the relevant statement first, its relational
grounds next, coherent supporting excerpts next, and full authorized evidence
inspection on demand. Offline consolidation adds reviewable interpretations; it
does not replace source objects, confer identity or silently author decisions.

This is the next design refinement of
[record/recall and extraction](kan-v2-record-recall-and-extraction.md) and
[agent documentation usability](kan-v2-agent-documentation-usability.md), under
the semantic invariants in `docs/SPEC.md` and the continuity contract in
`kan-v2-server-first.md`. It does not supersede the original feature scope or
claim that current runtime acceptance has passed.

Owner decisions, 2026-11-04: include all five flows described below; support
explicit runs and opt-in processing after session finalization; show authored
claims first followed by a labelled derived supplement. Future Sonnet acceptance
starts with fresh sessions and disposable working state, preserving every old
trial. The owner wants to investigate a local decision-model setup; no Jev
instance is currently running. The actual local model choice remains open.

Follow `AGENTS.md` and the Active development flow/testing tiers in
`kan-v2-next-build-status.md`. Design is Git-first while day#168 / kan#197 block
safe worktree-local process recording. No root-checkout process writes, invented
claim CIDs, inferred telos witnesses or new bridge declarations are made here.

## Current implementation and findings

At source revision `74922b7e6fea27f33c4c77da8f2e6277c3aef215`:

- `src/evidence_library/proof/records.rs` supplies canonical v1-compatibility
  authored records and recalls through the original fold. It is not full native
  governed-v2/Day identity, role or JSON compatibility. Its trust weights currently
  express membership, and Git-derived ancestry is not configured.
- `src/fold/identity.rs` retains directed identity witnesses but implements a
  component-level interpretation, not the higher witness structure named by the
  denotational target. `src/fold/relations.rs` retains attributed directed domain
  edges; enriched domain-relation composition is still a separate design.
- `src/evidence_library/proof/analysis.rs` has one bundled prose recipe,
  `documentation-summary` revision1. Configurable segment/extract/summarize/
  day-assessment purposes and tag triggers are execution hooks, not five complete
  opinionated consolidation flows. TypeSafe question shapes are implemented in
  `src/evidence_library/proof/analysis/adapters.rs`.
- `src/evidence_library/proof/reports.rs` paginates input references before report
  blocks. `src/evidence_library/mcp_pages.rs` places group/stream state before
  readable items and expands repeated citation metadata. Bounded output alone
  has not established useful first-page retrieval.
- The bounded same-session Sonnet continuation ended with a provider safeguard
  refusal, not an accepted source check. It used readable-input navigation but
  completed no source view. No cause for the provider classification is known.
  The original trial input included thinking-labelled items; ordinary
  documentation should instead use observable statements, artifacts and results.
- Tier1 passed167 unit tests and52 Library HTTP tests, with one ignored. A private
  macOS artifact and provider-offline source readback passed. Those controls are
  not agent acceptance or the final Tier2 candidate pass. Independent review has
  not launched; installed Kan and live Day/v1 remain unchanged.

The existing trials are historical diagnostic evidence. Their changing prompts,
resumed contexts and partial reads cannot be relabelled a clean fresh exercise.

## Requirements

- REQ-1: Preserve scoped subjects, immutable evidence/artifacts, attributed typed
  assertions, directed relation witnesses and recorded derivations as distinct
  structures. Content equality, occurrence identity, asserted identity and topic
  similarity are different judgments; consolidation cannot collapse them.
- REQ-2: Evaluate a semantic view under a named evidence frontier, query,
  admission/trust frame, normalization and relation-provider versions, and
  selected retained derivations. Apply identity before state under the same
  supported enrichment. Unsupported enrichment remains explicitly unsupported.
- REQ-3: Expose orientation, assertions/relations, source excerpts and evidence
  inspection as progressive disclosures of the same view context. Provide useful
  text promptly within12KiB normal payloads, compact reusable attribution and
  explicit coverage/omissions. No authoritative object is rewritten by rendering.
- REQ-4: Open source citations at a decoded item or excerpt inside an exact frozen
  selection, reconstructing necessary transport context internally. Preserve
  original item indices, source URIs, enclosing byte ranges, coarse flags and
  loss states; each expansion rechecks current access.
- REQ-5: Bundle five versioned flows: session brief; decision/open-question
  extraction; subject/project consolidation; handoff/context preparation; and
  relation suggestions. Each defines input selection, task instructions, typed
  output, citation validation, uncertainty, exclusions and execution bounds.
- REQ-6: Retain model outputs as attributed candidate assertions, proposed
  relations or narrative derivations. Never interpret a model probability as
  viewer trust, admission, identity, accepted status or logical entailment.
  Ordinary recall gives authored claims priority and a separately labelled
  derived supplement with its own budget and lineage.
- REQ-7: Support explicit runs and disabled-by-default, operator-opted-in
  finalization triggers. Freeze the selected session boundary before scheduling;
  require configured recipes, sources, models and quotas. Duplicate trigger
  delivery must not automatically submit duplicate inference. Scheduling never
  blocks capture, clears gaps or recursively processes its own outputs by default.
- REQ-8: Support replaceable bounded decision and generative workers through the
  existing analysis seam. Local model execution and a local proxy to a remote
  provider must be labelled differently. Record requested/returned identity,
  artifact/runtime revision where available, limits and usage-or-unavailable.
  Claude Code uses its normal sign-in without extracting login credentials.
- REQ-9: Consolidate across bounded frozen batches and, when explicitly selected,
  prior derivations with complete derivation lineage. A hierarchy of summaries
  cannot become the only route to original evidence or widen source access.
  Recompute/cache keys must bind every semantic input and current authorization
  remains a read-time check, never a cached grant.
- REQ-10: Ordinary documentation/consolidation inputs consist of user-visible
  statements, final outputs, artifacts and observed tool activity. Exclude
  internal model reasoning and non-user-visible control prompts from this
  projection, disclose selection exclusions, and preserve retained originals.
  Recorded reasons are explicit source statements, not reconstructed reasoning.
- REQ-11: A new Sonnet comparative acceptance exercise uses fresh sessions,
  disposable stores/worktrees and a newly approved bounded execution plan. Retain
  old trials; do not resume them, reuse their unused budget as blanket approval,
  seed reader answers or silently repeat extraction after failure.
- REQ-12: Keep the v1 compatibility boundary and proportional testing tiers.
  No second fold, live research dual-write, system upgrade, model download,
  provider invocation, large fixture repeat, migration or publication is implied
  by accepting this design. Final candidate qualification and independent review
  follow usable integrated evidence.

## Acceptance Criteria

- [ ] AC-1: Fixtures distinguish identical bytes in distinct occurrences, local
  subjects with matching labels in different collections, authored SameAs and
  model topic similarity. Consolidation preserves all objects and witness edges;
  retraction changes the interpreted view without rewriting them. (REQ-1)
- [ ] AC-2: Fixed evidence/assertions/retained model outputs and the same evaluation
  context yield the same deterministic view. A changed trust/admission/provider
  version invalidates the appropriate projection and retains conflicting states.
  Unimplemented weighted/higher identity semantics are disclosed. (REQ-2)
- [ ] AC-3: In a small representative fixture, first-page orientation contains
  relevant statement text; opening its citation returns nonempty supporting text
  without paging through transport metadata first. All pages remain<=12KiB with
  exact text/citation reassembly. Zero-readable, partial and indivisible oversized
  cases are explicit. Every disclosure carries the same view identity. (REQ-3)
- [ ] AC-4: A decoded excerpt crossing transport chunks resolves from its compact
  item locator, preserves original indices/ranges/coarse and loss states, and
  offers full authorized evidence inspection. Query mismatch, revocation, absent
  keys and erased evidence fail/disclose appropriately without fallback access.
  (REQ-4)
- [ ] AC-5: The five recipes have distinct versioned contracts and fixtures for
  explicit/inferred statements, unsupported conclusions, uncertainty, citation
  fidelity and excluded inputs. The handoff separates observed facts from
  suggested actions; relation suggestions cannot mutate the identity graph.
  (REQ-5, REQ-6)
- [ ] AC-6: A subject with authored and derived disagreement displays authored
  claims first and the disagreement in a labelled supplement. Budget pressure
  does not silently evict authored evidence in favor of derivations. Promotion
  previews an explicit authored operation retaining run/input lineage. (REQ-6)
- [ ] AC-7: Duplicate finalization events, restart, disabled triggers, exhausted
  quotas, missing sources and ambiguous provider completion retain explicit
  scheduling states without automatic duplicate calls. Only frozen pre-trigger
  inputs enter the job; later notes and output-derived triggers do not loop.
  (REQ-7)
- [ ] AC-8: Synthetic worker-contract tests cover Choice/Score/Noul and generative
  output, missing/malformed fields, bounds and unavailable backends. Local-only
  configuration cannot silently egress to hosted Jev or a cloud model alias.
  Actual local model quality/calibration is measured separately before relying
  on it to exclude material. Retained results need no live worker to read.
  (REQ-8)
- [ ] AC-9: A two-level consolidation retains intermediate runs and original
  source routes. Changing evidence/policy invalidates dependent projections;
  revocation blocks dependent content even with a cached report. Completeness is
  relative to the selected frontier; a newer assertion may create contestation
  instead of monotonically increasing certainty. (REQ-9)
- [ ] AC-10: An input fixture containing visible text, tool data, control prompts
  and thinking-labelled material sends only the permitted documentation
  projection to the worker, with excluded-kind disclosure. Original bytes remain
  intact, and no output claims to reconstruct private reasoning. (REQ-10)
- [ ] AC-11: A separately authorized fresh two-arm exercise records actual model,
  tools, clean session IDs, inputs, source reads/citations, elapsed time and usage.
  Freeze working evidence before explicit documentation; readers receive no
  expected answer or file/raw-offset workaround. Exit0 is insufficient. Cleanup
  stops owned services and retains failures, gaps and test stores. (REQ-11)
- [ ] AC-12: Targeted checks run under the selected Tier1 scope; one stable final
  Tier2 candidate and one independent integrated review use the current design
  and actual evidence. Compatibility limitations remain explicit, installed
  Day/v1/Git stores unchanged, and old scale/recovery trials unrepeated. (REQ-12)

## Architecture

### Denotational direction and effectful derivation

Use a typed evaluation context describing the source snapshot vector, scoped
target, admitted assertions, trust frame, normalizer/relation-provider versions,
selected derivations and query. Disclosure policy and budget are presentation
inputs. This is a conceptual contract, not a new URI grammar or a claim that all
these dimensions are implemented by the compatibility facade today.

The intended split is:

```text
Retained evidence + assertions + fixed derivation results
                 -> deterministic semantic evaluation under a context
                 -> brief / relational / excerpt / evidence-inspection views

Frozen selected evidence -> effectful model run -> retained derivation result
```

Do not describe an LLM summarizer as a lossless inverse, a proved functor or an
adjoint. Its judgment is a recorded effect. Later deterministic interpretations
can preserve its inputs and witnesses without treating its prose as a theorem.
More detail at a fixed frontier reveals grounds; new evidence or a changed trust
frame may legitimately change an answer from settled to contested.

Continue using `src/fold/mod.rs`, `src/fold/identity.rs`,
`src/fold/state.rs` and `src/fold/relations.rs` as semantic references. Reuse
`src/evidence_library/proof/records.rs` for deliberate authoring/promotion;
do not add a parallel interpretation of canonical claim kinds.

### Reading and relation structures

The semantic response has a concise body and compact witness references rather
than repeated transport records. A response-scoped citation dictionary retains
the original URI, source identity, item/region mapping, ranges and coarse flags.
An excerpt locator names a decoded item within a frozen selection and is not a
capability. Exact wire names require versioned schema/conformance updates.

Use the existing reconstruction and current-grant checks beneath
`src/evidence_library/proof/reports.rs` and
`src/evidence_library/mcp_pages.rs`. A normal first page prioritizes text; concise
coverage/availability accompanies it. Full per-stream diagnostics, large manifests
and original transport objects belong to explicit inspection pages. Reordering
must not erase unavailable observations or present a partial selection as whole.

Typed relation candidates name scoped endpoints, relation kind, supporting
references, model/run identity and explicit-versus-inferred basis. Topic grouping
and approximate retrieval do not assert SameAs. Accepting a proposed relation
requires the existing deliberate authored operation; derived graph views can
show candidates separately under an explicit derivation policy.

### Opinionated recipe pack

Each recipe is a bundle of selector, instructions, output schema, renderer,
validation and execution limits. These are proposed contracts, not new bundled
code already present in `src/evidence_library/proof/analysis.rs`.

| Flow | Required result and prompt stance |
|---|---|
| Session brief | State observed work, explicit decisions, results and open questions; distinguish a denied/unrun test from a failed or passed test. |
| Decision/open-question extraction | Return individually source-linked candidates with actor attribution, proposed/accepted/unclear stance and explicit/inferred basis. Extract recorded reasons only. |
| Subject/project consolidation | Combine selected authored records and derivations under one frontier; preserve correction paths, competing assertions and missing evidence. Matching labels alone cannot merge subjects. |
| Handoff/context preparation | Prepare budgeted orientation with source pins, active decisions, unresolved boundaries and separately labelled suggested next actions; captured instructions never become authority. |
| Relation suggestions | Evaluate supplied endpoint/span candidates for typed relations, including no-link/unknown outcomes. Preserve alternatives and grounds; do not mint identity or retract claims. |

Candidate outputs retain kind, text, scoped subject references, source/item
references, attributed speaker where supported, explicit/inferred basis, run and
recipe revision, and uncertainty/availability. A captured speaker need not be the
cryptographic signer. Model confidence is optional model output with its own
meaning, never a substitute for trust or admission. Prose is rendered from these
outputs alongside retained full model responses, not parsed back into authority.

A small session may need one generative call, not one call per display. Use
deterministic parsing/validation and reuse retained results for several renderings.
Large consolidation uses explicit bounded batches with complete lineage;
recursively summarizing summaries does not justify discarding original inputs.

### Local decision worker and generative worker

Generate candidate spans structurally; a bounded decision worker can label
decision-bearing spans, assess boundaries, rank supplied excerpts or propose
relations. Keep unknown/none outcomes. Initially its advice affects ordering and
visible suggestions, not silent evidence exclusion. Preserve actual distributions
and measure errors on the intended workload before choosing thresholds.

The existing `typesafe-system-one` adapter provides a compatibility seam for
Choice/Score/Noul. A local server using that protocol is not necessarily the Jev
model. TypeSafe's public quick start and model documentation describe hosted API
access; an official downloadable Jev runtime was not identified on2026-11-04.
Do not install an SDK or local gateway and label remote inference local.

Ollama documents local System One execution for independent models such as
Together AI's experimental Tev1. The proposed first candidate is Tev1 0.8B for
bounded setup/contract checks;4B is an alternative with a larger footprint.
Schema compatibility does not establish Jev-equivalent accuracy or calibration.
The next local setup plan is concrete below and awaits the owner's model choice.

Claude Code is the preferred local-controller path for the next Sonnet exercise,
using its existing normal sign-in. The current Messages-to-Claude-Code bridge is
test-only. A product worker needs explicit lifecycle, model, tool and cost/usage
contracts, using the existing analysis-job engine rather than a new scheduler.
No login token is extracted and no direct-provider API qualification is inferred.

### Explicit and opt-in finalization execution

Session finalization emits a scheduling opportunity, not a task-success or
capture-completeness claim. A disabled-by-default project policy selects recipes,
input categories, finalized frontier, worker/model, byte/time/job limits and
spend bounds where relevant. Enabling it is distinct from merely recording a
note or reading a report. Existing tag triggers remain explicit configured intent.

A trigger key binds session/attempt identity, frozen frontier, recipe/config
digest and execution principal. Persist accepted scheduling intent before worker
submission; retain interrupted/ambiguous attempts rather than automatically
resending them. No exactly-once provider-execution claim is made. Outputs do not
trigger themselves by default. Capture remains independent and fail-open.

Ordinary recall reserves its authored-record budget first, then appends a clearly
labelled derived supplement with run/frontier/recipe provenance and its own
omissions. It never changes authored status or trust membership because a model
report is more recent or rhetorically confident.

## Local setup plan

Read-only preflight on2026-11-04 found arm64,24GiB physical RAM and about22GiB
free disk. No common Ollama CLI was found on PATH in the prior inspection; that
does not establish that every possible application/runtime location is empty.
No model or runtime has been installed, downloaded or started in this pass.

After the model/runtime choice:

1. Verify the exact runtime release, model artifact, license and macOS support
   from primary sources; check disk again before any GB-scale write. Keep runtime
   and model files in explicit task-owned paths; no Kan system binary changes.
2. Install only the selected runtime/model. Initial setup writes are bounded and
   serial; do not start a login/background service, download a model family or
   change other agents' runtimes. Record actual sizes and artifact hashes.
3. Bind an owned server to an explicit loopback endpoint with a task-owned model
   directory, one loaded model, short context and one request at a time. Disable
   cloud fallback. Local loopback is not an upstream API credential.
4. Test one bounded synthetic request covering Choice, Score and Noul plus an
   unknown/none case. Validate actual fields against Kan's adapter. Distinguish
   a protocol pass from useful classification or calibrated confidence.
5. Exercise the existing analysis seam with disposable synthetic evidence only
   after scoped integration is prepared; preserve model/run identity and make
   retained output readable after worker shutdown. Stop/unload only owned work.

Ollama's documented request/context constraints and backend-specific model
artifacts must be checked against the actual pinned runtime; do not assume the
largest advertised context fits the laptop or a small request's precision.

Primary setup references checked2026-11-04:

- [TypeSafe quick start](https://docs.typesafe.ai/introduction/quickstart)
- [TypeSafe models](https://docs.typesafe.ai/models)
- [Ollama System One](https://docs.ollama.com/api/systemone)
- [Ollama Tev1 0.8B listing](https://ollama.com/library/tev1:0.8b)
- [Ollama macOS setup](https://docs.ollama.com/macos)

## Resolved Questions

- Include session brief, decision/open-question extraction, subject/project
  consolidation, handoff/context preparation and relation suggestions as bundled
  first-class flows. Owner selected all five on2026-11-04.
- Provide explicit runs plus opt-in processing after session finalization;
  automatic execution requires separately configured limits and authority.
- Ordinary recall presents authored claims first, followed by an explicitly
  labelled, unpromoted derived supplement.
- Semantic progressive disclosure has full authorized evidence fallback and
  preserves witness structure rather than replacing it with summaries.
- Future Sonnet tests start clean; old failed sessions and evidence remain
  retained and are not resumed or silently reused as fresh acceptance.
- No Jev instance currently exists. Investigate a local decision-worker setup
  and distinguish the actual model from API compatibility or a remote gateway.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Actual local decision-model starting point

Official local Jev weights/runtime were not found. The owner has been offered a
concrete choice: independent Tev1 0.8B locally through Ollama for a small initial
check, Tev1 4B with a larger footprint, or hosted Jev with separately configured
credentials/egress/spend. No substitution or installation has been performed.
An exact runtime/model artifact is selected and verified before local setup.
<!-- /OPEN -->

## Out of Scope

- Claiming full higher categorical semantics or inventing an enrichment algebra
  merely to name the aspiration; unsupported dimensions remain explicit.
- Automatic SameAs, deletion/compaction of original evidence, automatic trusted
  promotion, a new semantic fold, or opaque model-based authorization.
- Launching new paid Sonnet/review calls before a fresh bounded execution plan;
  reproducing the previous refusal through repeated old-session retries.
- Live migration, credential changes, system Kan upgrade, main merge, release,
  deployment, erasure, or repeating old large storage/recovery exercises.

## Validation and process recording

The acting worktree has no local Kan workspace. The prior `day doctor` read
refused to redirect to the main checkout under day#168 / kan#197; a worktree bulk
read reporting no subjects is not a complete process/telos inventory. This
refinement serves the previously recorded raw-data-and-projections direction and
the owner's explicit semantic target without declaring new witness criteria.

`day design check .design/kan-v2-semantic-disclosure-and-consolidation.md` was
attempted in this worktree on2026-11-04. It refused before schema validation:

```text
error: day is running in a Git worktree whose checkout has no kan workspace, while the main checkout at `/Users/m/code/kan-tools/kan` does.

kan currently discovers its log from the process working directory, so an empty read here does not establish that this repository has no teloi, atoms, or practice. day will not redirect the read: that could anchor a write to the main checkout's HEAD instead of this worktree. Run from the main checkout, or wait for kan's explicit shared-workspace mechanism (day#168 / kan#197).
```

This is unavailable live validation, not a schema pass or evidence of absent
process claims. Claim/bridge recording and live graph next-step reads remain
unavailable under the same worktree guard. Do not substitute manual counting for
the validator or redirect writes into the main checkout. Backfill remains pending
under the standing Git-first exception. The owner-selected recipes, triggering
and display policy are resolved; the actual local model choice remains open.
