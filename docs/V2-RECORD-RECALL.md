# Record, recall and derived reports

Experimental implementation on the agent-usability branch. These additions are
not in the published beta. Qualification and the comparative agent exercise are
pending. Keep Day/v1 and Git as the working research record.

V1 starts with deliberately authored claims in a repository. V2 also captures
observed evidence and runs optional analysis. The common authored loop remains
small: **record a typed statement, recall its subject, expand a source only when
needed**. Capture, authored records and generated reports have separate meanings.

| Task | V1 | V2 facade |
|---|---|---|
| Record | `kan-v1 decide TEXT --subject NAME` | `kan decide TEXT --subject NAME --profile /private/project.json` |
| Block / resolve | Narrative plus paired status | Same canonical body pair, one atomic encrypted batch |
| Structure | `same`, `relate SUBJECT KIND TARGET`, `mark` | Same typed relation/status bodies within the selected collection |
| Correct | `retract CID`, `reject CID` | Same author checks and reference fold; original records remain |
| Retrieve | `show`, `status`, `issues`, `context --budget N` | Direct authored-record views with bounded continuations |
| Summarize | External workflow | Bundled extraction plan, explicit provider run, derived report |
| Use a summary as a decision | Deliberate authoring | Review/edit, then explicit promotion retaining report/input lineage |

## Configuration is an operator step

A private JSON profile uses existing credentials and an existing authorized proof
service. It does not create keys, find a shared-root repository, migrate a store,
start services or change the installed binary. Each path is absolute; the file
and credentials must be private. Name each durable worktree explicitly using its
canonical path. Linked worktrees are not inferred. An invocation outside these
roots refuses before opening keys/workspace. Subdirectories of a selected root
are included.

```json
{
  "version": 1,
  "allowed_worktrees": ["/private/demo/author", "/private/demo/reader"],
  "source": "copy the exact proof scope.id from the configured Library catalog",
  "reader_config": "/private/demo/reader-sources.json",
  "signing_key": "/private/demo/existing-author.key",
  "workspace": "/private/demo/reader-workspace.sqlite",
  "workspace_key": "/private/demo/existing-workspace-recipient.key",
  "git_root": "/private/demo/author",
  "annotation_outbox": null,
  "analysis_config": "/private/demo/analysis.json",
  "workspace_erasure_history": []
}
```

The reader-source array is the existing proof-reader configuration described in
[V2-LIBRARY.md](V2-LIBRARY.md). The author signs inner records and the encrypted
workspace. Service issuers, capture writers, inference credentials and owner
credentials remain separate. A managed workspace must explicitly enroll its
existing independent erasure histories. An uncited note still needs collection
access; independent sender custody is required before delivering it.

`git_root` is optional and never discovered. When configured, CLI writes attach
that repository's current commit; `--file path:start-end` adds a literal file
anchor on narrative actions. This does not configure Git-derived ancestry in the
fold. Without it, no Git anchor is invented and `--file` refuses.

## The ordinary loop

```sh
kan decide 'Keep Day/v1 until its adapter and migration pass.' \
  --subject project/continuity --profile /private/project.json
kan block project/continuity 'The compatibility gate is still open.' \
  --profile /private/project.json
kan show project/continuity --profile /private/project.json
kan status --all --profile /private/project.json
kan context --budget 1024 --profile /private/project.json
kan relate project/continuity depends-on project/migration \
  --profile /private/project.json
```

An explicit statement needs no captured session or evidence citation. `--cite`
means a canonical claim CID. Typed MCP requests may additionally supply existing
signed evidence citations and literal artifacts; returned source URIs expand
through the normal typed reference tool under current access.

Receipts distinguish canonical inner claim CIDs, the outer authored declaration,
operation nonce/time and local/publication state. Append order is encoded with the original 13-character ATProto TID encoder in each canonical envelope; it is separate from the author-attested time. Local encrypted save is not an
archive acknowledgment, independent backup, complete capture or accepted review.
An operator-configured outbox automatically queues the record at that fixed
bound destination; delivery uses the existing explicit drainer. Queue failure
retains the local record and reports the failed queue check. No destination is
inferred from an agent request.

The CLI prints its operation nonce/time before attempting a write. Preserve that
object for an uncertain exact retry, using `--operation '{"nonce":"...",
"recorded_at":...}'` with unchanged intent. Reusing it with changed text, source,
artifacts, evidence or derived lineage refuses. A new deliberate act uses a new
operation, even when the text/time match. Retraction and rejection are additive;
retracting a retraction restores the earlier claim under the existing fold.

Normal structured results are at most 12 KiB. `show/status/issues/context` expose
`entries` and `next`; pass `next` as `--cursor` with unchanged arguments. Context
also reports token-budget omissions. A page boundary is separate from an omission.
Current access and the evidence/view binding are checked again on each page.
An indivisible item that cannot fit refuses explicitly; it is never silently
truncated or represented by an empty successful page.

## Compatibility is explicit

The initial bridge transports **canonical kan-claim-v1 compatibility records**
inside v2, using the original CID/signature codec and deterministic fold.
Original imported v1 claims keep the existing import APIs and original bytes;
this facade does not silently reclassify them as locally authored records or add
its collection anchor/operation artifact to an original claim. It does
not manufacture native governed ScopeIds, did:kan control history or scope
admission. The collection anchor is a content-addressed Blob descriptor, not a
fabricated Git genesis. Claim identity differs from its outer evidence occurrence.

New typed declarations use `kan-annotation/2`; ordinary `kan-annotation/1` remains
unchanged. Publication/restore validate the original inner signatures, collection
binding and author. Restoring another author's records does not automatically
trust that author. The default is **me**, narrower than v1's default **local**.
`--trust me`, explicit static did:key identities/weights and explicit `local` are supported. Here local
means authenticated retained collection authors, including explicitly restored
ones. Role aliases refuse until the separate identity/Day adapter exists. As in
the existing fold, nonzero weights currently express membership, not a qualified
weighted-composition algorithm. Responses disclose this boundary.

SameAs witnesses, conflicting statuses, correction history, literal artifacts,
claim cites and source/report lineage remain visible. Matching subject strings
across collections do not merge them. JSON is versioned v2 output and explicitly
**not Day JSON compatible**. Identity setup, GitTree publication and whole-store
migration keep their separate contracts. See the [compatibility map](../.design/kan-v2-record-compatibility-matrix.md).

## MCP

Run `kan mcp --profile /private/project.json` for a configured reader. Add
`--writes` only for an author; add `--analysis` only when exposing the configured
extraction planner/provider. Neither flag grants owner authority.

| Tool | Purpose |
|---|---|
| `kan_v2_record` | Deliberately author one typed atomic batch; write authority required |
| `kan_v2_recall` | Read an authored subject/CID, status, issues or token-budgeted context |
| `kan_v2_extract_plan` | Preview the exact pinned interval/model/recipe/bounds without a provider request |
| `kan_v2_extract` | Explicitly submit that copied plan digest, selection and nonce |
| `kan_v2_report` | Read bounded derived text/lineage without a provider call or promotion |

Existing typed catalog/help/discover/content/session/reference and advanced audit
APIs remain. Normal decoded views retain bounded tool-input JSON as well as text;
large Write inputs are not hidden behind a whole-event/raw-hex fallback. Tool
input is observed data, not evidence that the tool executed successfully. Fragments
retain exact enclosing source ranges and their coarse-attribution flag.

## Bundled extraction and report review

The `documentation-summary` recipe, revision 1, uses the existing configured
Anthropic Messages inference adapter through a loopback gateway. The gateway owns
its separately configured upstream API credential and model allowlist. Kan does
not read a shell API key or silently select a provider/model. Omitting `recipes`
from the analysis configuration selects this bundled recipe; an explicit list
keeps its existing meaning. The configured input bytes, output-token request,
lifetime job quota and single-new-job provider call remain explicit. These are
execution bounds, not a verified dollar bill; select the actual model, source
allowlist, credential reference and spend envelope before a paid exercise.

```sh
kan extract --profile /private/project.json --from 1 --through 3
# Retain the returned plan in an absolute private file; no provider was called.
kan extract --profile /private/project.json --plan /private/plan.json --run
kan report REPORT_ID --profile /private/project.json
kan promote REPORT_ID --subject project/continuity --as-verb decide \
  --text 'My reviewed, edited conclusion, with its unresolved boundary.' \
  --profile /private/project.json
# This previews author/text/subject/kinds/evidence and an exact operation.
# After review, repeat the intended statement with --save; copy --operation
# from the preview when preserving that exact authored operation.
```

The interval is inclusive and pinned. At most eight explicitly selected
occurrences are accepted; a larger interval refuses before a provider call rather
than secretly taking its first eight entries. Coordinates above the exact
JavaScript integer range refuse on this facade. Use the advanced signed-reader
interfaces for other coordinates. A source selection may itself be partial:
shared assembly/decoding preserves missing, unsupported and stream-coverage
states. There is no claim that three frames constitute an entire conversation.

The prompt contains coherent decoded selected streams, source attribution and
citation sets, including decision-bearing tool input. Duplicate whole-event JSON
is omitted from this presentation, while original inputs/request/response remain
in encrypted analysis lineage. A changed source/selection/model/recipe makes the
copied digest fail. A retained interrupted/failed job is not automatically retried.

A report ID identifies a run, not an accepted decision. Readback does not require
provider configuration and calls no model. It reports requested/returned models,
recipe, inputs/source URIs, availability, usage or its absence, and coverage.
Report input references and text fragments both paginate under the normal 12 KiB budget. `inputs_count` and `blocks_count` name the total manifest and fragment counts; each page carries only its visible `inputs` and `blocks`. Follow `next` with unchanged report ID to retain both completely. Input numbers in the generated text refer to the stable selected manifest. An indivisible over-budget reference refuses explicitly.

Report inputs also return a compact `reference_request`, such as `{"report":{"id":"...","input":4}}`. Pass it directly to `kan_v2_reference`, then follow its cursor with the same handle. This avoids copying a long portable URI. The report id/input number is a locator, not a read capability: every use rechecks the report sources through the existing authenticated readers, requires no provider configuration and makes no model call. Exact portable URIs remain supported.

Report text/citations need review. Explicit promotion inherits original input
citations and the retained result CID; edits and later corrections do not replace
the original report. A captured instruction cannot grant tools or promotion.

## Comparative demo and retained operational artifacts

`scripts/kan-record-demo.py` orchestrates the normal CLI interfaces and retains
operator evidence outside the authorized agent worktrees. It does not start
services, launch inference agents, create credentials or assess semantic success.
Use the [maintained capture integration](V2-PROJECT-CAPTURE.md) for actual harness
sessions. Derive transcript paths from their exported events, never directory
encoding guesses. Check capture health, queue, acknowledged delivery, historical
gaps and explicit backfill separately; queue zero is not complete capture.

1. Select a disposable public/synthetic working exercise and exact qualified
   private binary. Configure both explicit worktrees and the fixed provider
   model/credential reference/limits. Keep evaluator answers outside agent scope.
2. Capture the working session once, finalize/drain it, then freeze the agreed
   working interval **before** writing explicit documentation:
   `python3 scripts/kan-record-demo.py --binary /private/kan --profile /private/project.json --output /private/operator-evidence freeze --from 1 --through 3`.
3. In the explicit arm, prompt the real documentation author to record the
   decision, source pin, reason and uncertainty through `kan_v2_record`. Retain its
   actual initialization/model/tools/hooks/result. A fresh reader uses only typed
   recall/reference tools, no current-document Read/Bash or expected answers.
4. The offline arm submits the original frozen plan using the runner's `extract`
   phase. It cannot include later authored notes/doc sessions: input is the fixed
   captured interval, not the reader workspace. Give a separate fresh reader only
   the derived report address and typed report/reference tools. Keep usage/model
   and original failures, and do not infer acceptance from exit zero.
5. Runner `readback --arm explicit --subject NAME` or `readback --arm derived`
   retains ordinary paginated API controls for the operator. These controls are
   not an agent-success substitute or a saved-file workaround for the readers.
   Compare both actual reader results against the private evaluator: unsupported
   conclusions, recovered facts/pins/uncertainty/citations, calls/bytes/time/usage.
6. Stop every service the exercise started. Retain test keys, reports, failed
   attempts, capture gaps and backups privately. This runner performs no erasure,
   credential changes, system install or live research cutover.

`plan.json` and `frozen.json` bind the source selection and binary/profile hashes.
`extraction-start.json` prevents duplicate automatic submission even after a
failure/unknown outcome. `extraction-terminal.json`, `command-*.json` and each
`*-readback.json` retain exact receipts/diagnostics/control pages. Files are
create-new, private and fsynced; they are operational evidence, not a second
research ledger. Changing a frozen plan/profile/binary refuses. A failed exercise
requires inspection and an explicit changed plan; never erase its evidence to
make an unchanged retry look new. Native source/workspace backup and restoration
remain their existing independent interfaces; this runner does not claim a new
backup-recovery qualification.
