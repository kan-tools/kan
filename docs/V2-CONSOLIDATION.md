# Semantic disclosure and bounded consolidation

Kan preserves authored claims, source evidence and model derivations as distinct
objects. The canonical v1 compatibility fold still supplies authored state and
identity; model scores never become trust weights, grants or identity witnesses.
Higher/weighted identity semantics and computed Git ancestry remain unsupported.

## Built-in flows

`kan recipes` lists the exact versioned generative contracts, without opening a
workspace or worker. `kan recipes --decision` lists the separate bounded decision
contract for an explicitly configured local worker.

| Recipe, revision1 | Output stance |
|---|---|
| `session-brief` | Observed work, decisions, outcomes and open questions; denied/unrun differs from failed/passed. |
| `decisions-and-questions` | Individually attributed decision/question candidates; proposed, accepted and unclear remain distinct. |
| `project-consolidation` | Selected project statements and explicitly supplied prior consolidations, preserving conflict/correction grounds. |
| `handoff-context` | Orientation and unresolved boundaries; suggested actions remain suggested/proposed. |
| `relation-suggestions` | Directed, scoped candidate relations, including no-link/unknown; never a graph mutation. |

These return `kan-consolidation/1`: candidates with kind, text, explicit/inferred/
suggested basis, stance, optional speaker, scoped subject suggestions, optional
directed relation, supplied evidence-unit ids and uncertainty, plus limitations.
Schema/locator validation is mechanical; truth and calibration are not certified
by a successful parse. Invalid/missing evidence ids fail the job while retaining
the exact provider response. No recipe automatically authors or promotes a claim.

The default CLI recipe is `session-brief`. The original prose-only
`documentation-summary` revision1 remains available explicitly for old plans and
retained reports; it does not acquire the new typed-output/projection contract.
Custom recipe lists retain their existing explicit meaning.

```sh
kan extract --profile /private/project.json --from 10 --through 15 \
  --recipe decisions-and-questions
# Save the preview as a private absolute plan file, then deliberately submit:
kan extract --profile /private/project.json --plan /private/frozen.json --run
kan report REPORT_ID --profile /private/project.json
```

All five flows require coherent decoding. Their `kan-visible-evidence/1` input
contains user/assistant text, observed tool names/inputs/results and original
item/range attribution. Thinking, system/control/context wrappers, duplicate raw
events and whole parsed documents are excluded and counted. Unattributed response
channel text remains explicitly unattributed; it is not speaker authentication.
Loss/availability states remain visible. Original encrypted inputs are retained;
the projection is neither deletion nor complete-capture certification.

`--derived-report PARENT` explicitly includes a prior validated consolidation as
context. Every original parent input must also occur in the selected interval;
the eight-input bound never silently widens. The new result retains parent-job
lineage and must ground its new candidates in its own supplied visible units.
Read-time checks cover all dependency sources and retained ancestors; provider
configuration is unnecessary for reading. Long ranges/large ancestry refuse
explicitly. This initial bounded hierarchy is not an unbounded project crawler
or automatic consolidation of every authored subject in a repository.

## Progressive disclosure

Reports present statement text before their full source manifests. Statements
carry compact `reference_request.report` locators, including an exact decoded
`excerpt` (group/direction/original item/part). Opening one reconstructs only the
frozen original manifest under current access, then presents that item, preserving
cross-chunk source ranges and loss diagnostics. Portable occurrence URIs still
resolve one occurrence; full selected evidence/audit remains independently
available through the existing shared API.

Typed decoded pages now use `kan-mcp-content-page/2`. Text/tool data comes first;
structural diagnostics follow. Each entry's `citation_refs` resolves in that
page's `citation_dictionary`. Dictionary values retain source, original URI,
enclosing byte ranges, coarse attribution and applicable report hops. Dictionary
ids are page-local, not capabilities or persistent object ids. Follow `next`
with identical arguments; never reuse a dictionary from another page. Every page
remains at most12KiB. An indivisible oversized witness refuses explicitly.

`view_id` binds decoded query, reconstruction, citation lineage and coverage.
Recall separately exposes a compatibility evaluation id over the scoped claim
frontier, trust frame, normalizer/relation versions, selected derivations and
query. Presentation budget is not semantic identity. Unsupported enrichment
remains explicit; this is not a claimed implementation of higher categorical
identity or a proof that model generation preserves denotation.

`kan show project/name --derived-report REPORT --derived-budget 256 --profile ...`
appends a labelled model-derived supplement after all authored rows. Subject
filtering requires matching explicitly scoped candidate subjects. Its separate
token budget cannot evict authored claims. Omitted candidates are counted. With
no selected reports, recall remains authored-only. This provides an explicit
selection policy rather than silently treating recent model prose as relevant.

## Local decision worker

The existing `typesafe-system-one` adapter accepts Choice, Score and Noul.
`kan recipes --decision` supplies `evidence-triage`, which preserves unknown/none
and full returned distributions. It uses the same visible-evidence projection.
These scores advise ordering/review only; no threshold silently excludes sources.
Tev1 is a different model from hosted Jev, despite protocol compatibility.

Ordinary `kan report` and `kan_v2_report` expose each retained question/rubric
and its complete Choice, Score or Noul answer as JSON text fragments in
`decision-assessment` blocks, keyed by `question_id`. Full distributions and
unknown/none alternatives survive; they are not reduced to a winning label.
Follow `next` to complete the report. Model identity, input references, usage
availability and current dependency access follow the same report contract as
generative output. Reading needs no worker configuration and performs no model
call. These assessments remain unpromoted model interpretations, not calibrated
truth or authored acceptance.

Example analysis configuration (substitute existing private paths and source):

```json
{
  "adapter": "typesafe-system-one",
  "worker": {
    "kind": "local-decision",
    "runtime_revision": "explicit pinned runtime revision",
    "model_sha256": "58b59b64c8f3b9386005fbbbb90ed2e8fefc8f8ca80fb09862974fde9371c6af"
  },
  "endpoint": "http://127.0.0.1:11436/v1/systemone",
  "token_file": "/private/local-server.key",
  "model": "tev1:4b-q4_K_M",
  "sources": ["proof:explicit-source-id"],
  "recipes": [],
  "max_input_bytes": 4096,
  "max_output_tokens": 128,
  "max_jobs": 1
}
```

Replace the empty `recipes` array with the exact output of `kan recipes
--decision`; an empty array refuses rather than selecting an implicit model flow.
The token file contains only disposable local-server authentication, not an
Anthropic API key. Configure exactly one of `token_file` or the legacy inline
`token`. The client uses literal loopback HTTP, no proxy or redirect, rejects
cloud-style model aliases in local-decision mode and requires exact returned
model identity. Runtime/artifact identity is operator-attested configuration,
not remote attestation that an arbitrary local proxy never egresses. The owned
runtime must separately use offline loading and explicit lifecycle bounds.

Tev1 4B Q4_K_M on gilgamesh has passed isolated API/Metal setup checks;7/9 small
synthetic labels matched, with two proposal/rubric disagreements. That is not
Kan workload accuracy or calibration. No daemon or production profile was
installed. Actual new-binary integration and workload evaluation are separate.
The first Kan-to-Tev probe received HTTP503 `Loading model`: the operator checked
the listening socket before the model was ready. Its failed job is retained;
there was no classification result or automatic resubmission. A future explicit
run must require the runtime's successful health response before submission;
an open port alone is insufficient readiness.

The corrected one-job Kan integration at `4b8caa9` succeeded: a health-gated
local request completed, then ordinary report reading reproduced all retained
questions and distributions with the model stopped and provider configuration
unavailable. It used one synthetic excerpt, so it establishes the execution and
readback path, not classification quality or calibration.

### Small real-annotation evaluation

The offline scorer `scripts/tev-evaluate.py` reads an explicit private corpus,
reference labels and previously retained responses; it never starts a worker:

```sh
python3 scripts/tev-evaluate.py --validate-only --cases /private/cases.jsonl \
  --labels /private/reference-labels.jsonl --output /private/preflight.json
# Only after preflight succeeds, run the separately bounded worker experiment.
python3 scripts/tev-evaluate.py --cases /private/cases.jsonl \
  --labels /private/reference-labels.jsonl \
  --responses /private/responses.jsonl --output /private/evaluation.json
```

Cases contain `id`, `group`, `split` (`calibration` or `heldout`) and exact visible
`text`. Labels contain `id`, `stance` (adopted/proposal/none/unknown), `decision`
(0/1/null) and `support` (0/1/2/null). Response rows retain `id`, `status`, typed
`answers` and elapsed seconds. Failures and absent responses remain failures in
accuracy/coverage; ambiguous reference heads remain counted but unscored. Text
and source/claim metadata should stay in private files, not Git fixtures.

Subject groups, exact duplicates and near-duplicate text cannot cross splits.
The scorer reports raw and calibration-only temperature-adjusted held-out
results, class-prior/uniform baselines, reliability counts, grouped uncertainty
and latency. It uses actual probabilities, not the worker's unrelated native
confidence scalar. Brier/log loss combine discrimination and reliability, so
they do not alone establish calibration. Model-assisted references, selection
bias and small per-class counts must accompany results. No fitted temperature
or threshold automatically changes product retrieval or excludes evidence.

The2026-11-05 own-project pilot submitted48 genuine annotation excerpts; every
local request succeeded. A namespace-alias split defect was caught before
prediction inspection; the entire two-example group was quarantined, leaving
23 calibration and23 held-out examples. Original inputs/results remain retained.
This is why preflight must run before future worker execution. Source text and
revision were matched in digest-verified CAR blocks; claim identity came from
the derived index, without independent signature or current-MST verification.

Terra supplied blind provisional labels. An independent12-case parent audit
matched all three labels on8/12; disagreements and uncertainties were reviewed
before predictions, with five binary/ordinal references left ambiguous. Held-out
accuracy against the resulting references was stance11/23 (48%), explicit
adoption12/22 (55%), and reason strength11/22 (50%). Group-bootstrap95% accuracy
ranges were broad:25–70%,32–74%, and30–70%, respectively. Calibration-only
temperature scaling did not improve every held-out probability score. Neither
of the two stance predictions above0.9 top-class probability matched its
reference: merged-work reports were mistaken for adopted decisions.

Median request latency was6.43s and p958.03s on the pinned M4 configuration;
48 sequential requests took314s including readiness. No isolated peak-memory
benchmark was performed. These enriched, model-assisted references are not human
gold, and this held-out set is now spent for tuning. Keep this worker opt-in;
no result supports hiding evidence or inferring acceptance. Already typed authored
claims should keep their explicit kinds and fold semantics, rather than being
reclassified by Tev.

## Finalization queue

Project capture accepts an optional `consolidation` policy:

```json
{"profile":"/private/project.json","recipes":["session-brief"],"max_jobs":2}
```

Absence disables queueing. The analysis configuration must separately opt in
using `finalization_recipes:["session-brief"]` and bound input/output/lifetime jobs.
Only acknowledged, gap-free SessionEnd or explicit KanFinalSnapshot captures of
at most eight records enqueue metadata. This does not certify complete capture or
task success. Stop/compaction snapshots, notes and derivations do not trigger it.

Hooks only queue; they never launch a model or background process. An explicit
`python3 scripts/kan-project.py --config /private/capture.json process-finalized`
drains at most one queued event under a 120-second total processing deadline,
shared across discovery, preview and submission commands. This is also a bounded
entry point for an
operator-managed after-session runner; no scheduler or login service is installed.
Signed discovery must find the exact attempt's complete ordinal set within the
scan budget and one contiguous inventory interval. Interleaved/missing/oversized
attempts refuse rather than including unrelated evidence. A private `--pin-file`
freezes the discovery frontier before any model submission.

The engine derives finalization job identity from session/attempt, exact source
metadata/bytes, recipe/worker/model/request. Duplicate delivery with a fresh pin
nonce does not dispatch again. Accepted job intent precedes worker submission;
restart, interruption or ambiguous outcome stays visible and is not retried by
the finalization path. Quotas reserve all configured recipe jobs in an event.
Capture queue failure does not rewrite capture health or block its fail-open
contract. Explicit retry/replanning remains a separate operator decision.

Private operational artifacts under capture runtime `consolidation/` are:
queue `*.json` intents; create-new per-event run receipts/frozen plans; command
stdout/stderr diagnostics. They contain metadata/retained model readbacks, not a
new source-plaintext cache or grant store. Preserve failed/ambiguous receipts.
They are catalogued in `tests/fixtures/read-write-surface.tsv` and covered by
`tests/test_kan_finalized.py`. Actual analysis inputs/results stay in the existing
encrypted workspace and its original custody/erasure mechanisms.

Fresh Sonnet acceptance still requires a new concrete task/tool/input/budget
plan and clean sessions/stores. Old resumed trials remain historical failures;
no local setup check or successful job exit substitutes for agent acceptance.
