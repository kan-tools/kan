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
trial. The owner selected Tev1 4B Q4_K_M for an isolated local decision worker.
Its initial protocol/setup checks have passed; workload quality and Kan recipe
integration remain unqualified. Tev1 is a separate model, not local Jev.

Follow `AGENTS.md` and the Active development flow/testing tiers in
`kan-v2-next-build-status.md`. Design is Git-first while day#168 / kan#197 block
safe worktree-local process recording. No root-checkout process writes, invented
claim CIDs, inferred telos witnesses or new bridge declarations are made here.

## Current implementation and findings

Current Nov10 disposition: `32e2f6c` passed full candidate CI, then the actual
cold integrated review returned **BLOCK**. The owner approved correcting all
F1–F9 without reducing these requirements. Correction `7c9a11e` compiled and
passed lint, 182 units, 57 HTTP tests and the native capture fixture, but Tier1
failed on workspace fixture setup, an incorrect rejection-status expectation,
obsolete child-source navigation and test-only writer placement in both surface
configurations. The focused test-support/navigation correction remains pending
remote verification; assertions and product behavior are unchanged. Preserve the
failed run, qualified baseline, blocked report and fresh `7b79269` source/runtime
trial independently. A partial test pass is not candidate qualification.
The observed harness-wrapper leakage invalidates the earlier input-exclusion
acceptance, even though the observed retrieval results remain retained.

The integrated correction uses visible projection revision2 to exclude whole
recognized harness-control wrappers while preserving literal user mentions and
original fallback. It refuses a complete authored fold when currently withheld
or erased correction dependencies could change state. Finalization claims an
event independently of the capture lock and admits worker deadlines only within
the total drain/cleanup budget. Five revision2 recipe contracts retain distinct
flow structure, including typed handoff pins and grounded relation alternatives
or no-link outcomes. Multi-batch consolidation freezes one frontier, chains
labelled parent interpretations and rechecks their complete bounded dependencies;
promotion retains ancestor witnesses rather than silently reducing lineage.
Origin report/project evaluations remain distinct from current authenticated read
views. Real v1 actions/read results, actual populated MCP examples, operation
retries after HEAD movement and conservative fixture/rename routing are new
regression targets. These are pending qualification, not proof of calibration or
automatic acceptance of model interpretations.

Historical starting point at source revision
`74922b7e6fea27f33c4c77da8f2e6277c3aef215`:

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

Implementation pass,2026-11-04, with scoped runtime inspection2026-11-05:

- `src/evidence_library/proof/analysis/recipes.rs` implements five versioned typed
  candidate contracts and a visible-evidence projection. Original item ids and
  source ranges survive exclusion of thinking/control wrappers. Shape and witness
  validation cannot certify truth or calibrate confidence.
- Existing jobs carry explicit worker identity, optional private local token-file
  references and bounded prior-derivation lineage. Capture-only mode requires
  parent originals in the selected interval. The Nov9 implementation adds an
  explicit bounded authored subject/prefix/relation selector with its own frozen
  frontier and current dependency access. It is not an unbounded project crawler;
  its new runtime qualification remains pending.
- Reports lead with structured statements and exact decoded-item locators.
  Typed content-page version2 leads with useful text/tool data and uses a
  page-local citation dictionary. Original indices/ranges, loss states and the
  separate full-evidence API remain. Recall binds an explicit compatibility
  evaluation context and appends explicitly selected derived supplements after
  authored rows under a separate budget.
- `scripts/kan-finalized.py` supplies an opt-in metadata-only finalization queue
  and bounded explicit drain, using existing analysis jobs. Hooks never execute
  inference. Signed attempt discovery freezes inputs; duplicate scheduling and
  ambiguous outcomes never automatically reissue the request. No daemon, new
  credential, plaintext source cache or production configuration is installed.
- `docs/V2-CONSOLIDATION.md` records interfaces and boundaries. The new actual
  HTTP regression covers all five flows, excluded inputs, source routes,
  two-level lineage, duplicate finalization, authored priority, offline report
  reading and revocation. At22295f4, actual Tier1 passed170 Rust units and53
  Library HTTP tests (one ignored), plus compilation, lint and180 Node tests.
  Capture lifecycle and macOS runtime were scope-skipped, not qualified by this
  run. The private exact-head Mac artifact was verified but not installed.

Local-worker readback correction,2026-11-05:

- The one synthetic Kan-to-Tev job at22295f4 reached a bound server while it was
  loading and retained HTTP503 `Loading model`. No classification result was
  produced, and no automatic resubmission occurred. All owned services stopped;
  the system binary and global Ollama state were unchanged. Port readiness was
  an operator-harness mistake; subsequent explicit starts must wait for a
  successful runtime health response. This is not a workload quality result.
- Source inspection also found that normal reports rendered prose/structured
  consolidation but omitted successful System One answers. The report read path
  now retains each exact question/rubric and complete answer/distribution in
  bounded `decision-assessment` blocks. Confidence is not calibrated truth or
  authored acceptance. No result or execution format changes; no Engine/provider
  is needed to render a saved result. Pure Unicode/paging and actual fake-provider
  HTTP controls cover all three answer types, provider-offline reading, retained
  model/usage identity, no extra requests and current revocation.
  These controls passed scoped Tier1 at4b8caa9. The corrected one-job real local
  runtime integration then passed, with worker-offline ordinary report readback;
  it did not establish classification quality.

Own-project task evaluation,2026-11-05:

- The authorized Terra subagent labeled48 genuine whole annotation bodies;
  a blind12-case parent audit initially matched full label triplets on8/12.
  Disagreements and uncertainties were reviewed before predictions; labels are
  provisional model-assisted references, not human gold. Text/revision matched
  digest-verified CAR blocks; claim identity came from a derived index without
  independent signature or current-MST verification. Private sources remain
  outside Git; original annotation kind was not provided to the classifier.
- All48 local requests succeeded in314s on the pinned M4 worker. A namespace
  alias group split defect was caught by the scorer before prediction inspection;
  both affected cases were quarantined, retaining all original frozen artifacts.
  Primary analysis uses23 calibration and23 held-out examples. Future runs must
  execute the offline preflight before starting a worker, not after inference.
- Held-out accuracy was stance11/23, adoption12/22 and reason strength11/22.
  Calibration-only temperatures did not improve all held-out probability scores.
  Two top-class-probability>=0.9 stance predictions mislabeled merged-work reports
  as adopted decisions. Median latency6.43s/p958.03s; no isolated memory benchmark.
  This pilot supports no source filtering or acceptance inference. Keep existing
  authored kinds and fold judgments deterministic; classification from untyped
  text remains optional and requires better evidence before production use.

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
- REQ-13: Measure the selected local decision worker on a small, frozen corpus
  of genuine own-project annotation excerpts with source pins. Separate grouped
  calibration and held-out cases; labels remain blind to worker output. Preserve
  ambiguous labels, failures, full distributions, latency and runtime identity.
  Model-assisted labels are provisional references, not human gold or truth.
- REQ-14: Report task discrimination and probability reliability separately.
  Any fitted calibration parameters use only the calibration split; held-out
  results cannot tune prompts, thresholds or calibration. No evaluation score
  changes admission, authorship, source visibility or product defaults.

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
- [ ] AC-13: At most48 source-verified real excerpts have stable identities,
  subject/near-duplicate-disjoint splits and a frozen rubric. The authorized
  Terra labeler sees no predictions; a deterministic12-case independent audit
  and review of uncertainties retain disagreements before labels freeze. Private
  text, label/provenance and model-input manifests remain separate. (REQ-13)
- [ ] AC-14: A bounded single pass records missing/failed requests, per-head
  accuracy/confusion, Brier/log loss, reliability-bin counts, selective risk and
  latency. Any temperature fit uses only calibration cases; tests detect split
  leakage, missing predictions and native-confidence misuse. Report baseline
  comparisons and grouped uncertainty; no broad calibration or production
  filtering claim follows from this enriched small corpus. (REQ-13, REQ-14)

## Integrated worker and authored-selection implementation — 2026-11-09

Owner approval extends the existing build with three connected paths, without a
second scheduler, fold or authoritative store:

- `statement-assessment/1` uses exact visible-unit UTF-8 occurrence spans and
  categorical prescription/adoption/reason questions. It retains original full
  visible units, verbatim context windows and source fallback. A missing reason
  prevents reason-link inference structurally. Display mappings do not establish
  truth, present effectiveness, authored acceptance or probability calibration.
- A supported `claude-code` worker uses the installed CLI's normal sign-in,
  tool-free safe mode, a fresh job-bound session, bounded pipes, time/budget
  limits and owned process-group cleanup. Actual init, model, session, tools,
  completion and usage are retained. One invocation is not a promise about the
  CLI's internal provider requests. Read-only report paths instantiate no worker.
- An explicit bounded project selector runs the canonical fold over authorized
  authored records, selects whole subject classes and live relation neighbors,
  and retains correction history, signed claims, identity witnesses, trust and
  frontier. Explicit prior derivations keep their original dependency sources.
  Claim witnesses route to typed CID recall; capture witnesses keep exact decoded
  item routes. Appended claims invalidate an unsubmitted preview but do not rewrite
  a completed report's frozen interpretation. Publication and erasure follow
  typed frozen annotation dependencies, never model text or coincident labels.

The existing encrypted analysis job/input/result wildcard surfaces retain these
contracts; result classifications remain derived. Their surface declarations and
conformance evidence are updated with the implementation. No storage format,
claim codec, grant, canonical fold semantics or system installation changes.

Initial scoped Tier1 at `156c301` compiled all targets/features and passed176
unit tests. Actual HTTP integration passed55 tests with two failures: the worker
kept stdin open while waiting for an EOF-reading child, and a new project test
used a model relation spelling instead of the established typed enum. Lint also
rejected an unused public re-export. The original outcomes and complete logs are
retained; the final gate correctly failed despite masked action conclusions.

The integrated follow-up explicitly closes stdin, exposes the public span type,
uses the canonical relation enum, avoids duplicating bounded CLI output beyond
workspace framing, and completes authored-only supplement/promotion/full-source
report paths. Frozen frontier identity includes canonical record order. New
regressions preserve exact large outputs, signed inputs, identity context and
promotion citations. Changed-head runtime confirmation is pending. No local Rust
execution or fresh paid inference has qualified these changes. Development Q4 ablations
are motivation, not held-out product accuracy. Next come exact-head operator
checks and a newly named fresh acceptance exercise, then one final Tier2 and
scoped independent review. Historical failed trials remain historical evidence.

## Architecture

### First-pass local-worker task evaluation — owner request,2026-11-05

Use the existing `evidence-triage` questions from the verified current binary:
recorded stance (adopted/proposal/none/unknown), presence of explicit adoption
(Noul), and recorded reason strength (Score0–2). These labels concern what the
visible excerpt records, not whether a statement is true, a task succeeded, or
the viewer accepts it. Annotation kind is a sampling aid, never model input or
a substitute for reading the excerpt. A proposal is not adoption; ambiguous
binary/ordinal labels remain null and their coverage is reported.

Select up to48 whole short text bodies or exact bounded excerpts from Kan's own
retained annotations, with immutable claim/log source identities. Keep original
texts/provenance private outside Git. Enrich the sample across original annotation
types, at most two per logical subject; this is a task pilot, not a prevalence
estimate. Related subjects and exact/near-duplicate excerpts cannot cross the
24-case calibration /24-case held-out split. Freeze source, corpus, rubric,
recipe/request and label hashes before worker execution. The single authorized
Terra subagent labels independently of predictions; the parent independently
audits12 deterministic cases and all uncertainties before resolving a frozen
reference set. Record unresolved disagreements rather than forcing certainty.

The evaluator sends at most48 requests in one15-minute owned local runtime,
one slot/four CPU threads with the pinned Tev1 4B Q4_K_M artifact. It uses the
existing System One question/state envelope and visible-unit text, with genuine
evaluation source locators rather than invented proof tokens. This measures the
worker task; it is not another48 archive/backup fixtures or a substitute for the
separate qualified Kan integration. No proxy/cloud fallback or automatic retry;
requests, errors, skipped cases, token usage where returned and cold/warm latency
are retained. Stop the owned worker afterward. No paid Sonnet call is implied.

`scripts/tev-evaluate.py` performs offline scoring only. Report per-head class
counts, confusion/accuracy/macroF1, unscaled multiclass Brier (sum of squared
class errors), negative log likelihood, three reliability bins with counts,
fixed confidence risk/coverage points and grouped-bootstrap accuracy intervals.
Compare uniform and calibration-split class-prior baselines. Native `confidence`
is not presumed to mean probability of correctness; use the actual full
distribution. Ordinal expected-score error is separate from classification.
Failed/missing predictions count against end-to-end accuracy and coverage, never
silently disappear from the metric denominator.

Optionally fit one scalar temperature per head on calibration cases only, over
a fixed bounded grid, when there are at least12 usable examples and two classes
with at least three each. Preserve raw results and report held-out adjusted
results even when worse; do not choose settings using held-out outcomes. Brier
and log loss combine reliability and discrimination, so neither alone certifies
calibration. Use reliability counts and broad grouped uncertainty to state what
this small model-assisted corpus cannot establish. This follows the distinction
in [scikit-learn's calibration guidance](https://scikit-learn.org/stable/modules/calibration.html)
and the single-parameter method in [Guo et al.](https://proceedings.mlr.press/v70/guo17a.html).
No threshold is promoted to a product exclusion rule by this experiment.

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
validation and execution limits. The initial typed pack is now implemented
beside `src/evidence_library/proof/analysis.rs`; full runtime and fresh-agent
qualification remain pending. Shared pinned capture intervals and the Nov9
explicit bounded authored-graph selector supply the inputs. No autonomous graph
crawler or implicit selection of recent model reports is claimed.

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
Together AI's experimental Tev1. The owner selected Tev1 4B Q4_K_M after comparing
the published accuracy, runtime and weight footprints of the available options.
Schema compatibility does not establish Jev-equivalent accuracy or calibration.
The isolated setup and its bounded checks are recorded below.

Claude Code is the preferred local-controller path for the next Sonnet exercise,
using its existing normal sign-in. Historical Messages-to-Claude-Code bridge
evidence remains test-only. The Nov9 supported worker implements explicit
lifecycle, model, tool and cost/usage contracts in the existing analysis-job
engine; runtime and fresh acceptance checks are still required.
No login token is extracted and no direct-provider API qualification is inferred.

The fresh Nov9 exercise at `5b46a29` verified native EOF, timeout, cancellation
and output-limit controls, and one exact-witness Q4 operator request. The new
author actually ran eight toy tests; its authored reader recovered the exact
claim and pins with recorded-versus-verified limits. The first native Sonnet
session brief completed through normal sign-in but failed structured validation:
its otherwise valid JSON object was enclosed in a `json` Markdown fence. The
original failed job and raw response remain unchanged; the other model phases
were stopped. A private receipt-number collision also obscured the terminal
result until read-only recovery; no extraction was repeated.

The corrective parser accepts only one complete JSON object, bare or inside one
entire `json`-labelled fence. It never searches surrounding prose or repairs
JSON, fields or evidence ids. Existing schema and exact witness validation remain
mandatory, with original response bytes retained. The orchestration helper picks
the next numeric receipt before execution, preserving gaps and prior logs.
These corrections require remote scoped runtime checks; they do not turn the
retained failed exercise into acceptance or authorize an automatic paid retry.

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

Initial read-only preflight on2026-11-04 found arm64,24GiB physical RAM and about
22GiB free disk. Subsequent setup preflight measured20.52GiB free. No common
Ollama CLI or application was found, and global Ollama state was absent. The
following plan governed the isolated setup; production integration remains a
separate step.

Setup constraints:

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

### Actual isolated setup, 2026-11-04

The owner's concurrence resolved the choice to `tev1:4b-q4_K_M`. Task-owned
runtime, model, receipts, licenses and synthetic results are retained under
`.local-state/local-decision-20261104`; `README.md`, `worker-config.json` and
`setup-evidence.json` are the operator entry points. This configuration is not a
new supported Kan production schema.

- Official Ollama0.40.14 Darwin archive SHA256:
  `f3bf9a528e908da0da5a2b3a4ad3252a369d62186501dc4880261e8d9023bff5`.
  Its bundled native llama-server0.8.0-dev, commit39febd2ad, is invoked directly.
  Inspection found that `ollama serve` initializes a global identity key;
  invoking the native server avoids that global state. No system installation,
  login service or global Ollama identity was created.
- Model manifest SHA256:
  `608e3a13eec386ad34b657b1dcefe89e98c489f0cd6a3287ac2bb613db2f93da`.
  The2,783,448,672-byte GGUF SHA256 is
  `58b59b64c8f3b9386005fbbbb90ed2e8fefc8f8ca80fb09862974fde9371c6af`.
  Sizes and hashes were verified; only the selected model was downloaded.
- The explicit loopback endpoint is `http://127.0.0.1:11436/v1/systemone`, with a
  task-local bearer-file reference, offline loading, context2048, one slot and
  four CPU threads. Explicit Apple M4 Metal execution offloaded34/34 layers.
  The model GPU buffer report was2572.86MiB; individual buffer reports are not
  additive peak unified-memory measurements. Foreground startup is bounded to
  600seconds and starts no inference by itself.
- Three synthetic cases each exercised Choice, Score and Noul. All responses
  satisfied the adapter's field/probability checks;7/9 expected labels matched.
  Two proposal-case disagreements exposed an overlapping rubric and a near-tied
  topic choice. These results do not certify quality or confidence calibration.
  Three-question requests took1.32–1.49seconds; initial readiness took5.03seconds.
  A separate explicit-Metal diagnostic took1.34seconds, with warm caches; it is
  not an independent quality sample or a cold-load measurement.
- Owned servers were stopped, port11436 closed, global Ollama state remained
  absent and system Kan matched its retained baseline. Free disk was17.13GiB
  after setup. No provider call, actual Kan analysis job or fresh Sonnet
  acceptance run was performed as part of these local checks.

Next, prepare the scoped recipe integration and a small labelled workload with
unambiguous rubrics before using model scores to choose thresholds. Existing
analysis jobs remain the execution seam; a protocol-compatible local worker
does not establish that production integration is already implemented.

Primary setup references checked2026-11-04:

- [TypeSafe quick start](https://docs.typesafe.ai/introduction/quickstart)
- [TypeSafe models](https://docs.typesafe.ai/models)
- [Ollama System One](https://docs.ollama.com/api/systemone)
- [Ollama Tev1 0.8B listing](https://ollama.com/library/tev1:0.8b)
- [Selected Tev1 4B Q4_K_M](https://ollama.com/library/tev1:4b-q4_K_M)
- [Pinned Ollama runtime release](https://github.com/ollama/ollama/releases/tag/v0.40.14)
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
- The owner selected independent Tev1 4B Q4_K_M locally. The isolated native
  runtime setup and protocol checks above are complete; quality/calibration and
  Kan recipe integration remain separate qualification work.

## Open Questions

<!-- OPEN: Q2 -->
### Q2: Fresh acceptance exercise and bounds

Select a concrete fresh working task, observable input categories, model/tool
allowlists and total execution budget for the next Sonnet exercise after the
semantic retrieval and recipe changes are ready. Retained old-session budgets
and local setup results do not authorize an unspecified new paid trial.
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
and display policy, and the local model choice, are resolved. The fresh
acceptance execution plan remains open.
