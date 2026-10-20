# Feature: Kan Studio — the complete human frontend

> Development flow update (owner decision, 2026-10-19): complete the full v2
> feature set with continuous integration, then conduct one thorough integrated
> Opus 5.5 review campaign. The active checklist and policy are in
> [kan-v2-next-build-status.md](kan-v2-next-build-status.md). This supersedes older
> per-checkpoint review/reversion instructions below, without reducing product scope.

## Summary
Build a full human client for Kan: a rich, navigable library of retained work, messages, evidence, annotations and interpretations, with process assessment and administration in the same coherent application. Operations is one area, not the product boundary. Use the user's selected technical-studio direction: clean light surfaces, dense data and vivid accents.

This design supersedes the initial operations-only choice following the user's explicit clarification. It preserves `.design/kan-v2-server-first.md`: centralized cross-project evidence, blind storage, separately authorized readers, provenance-preserving projections, explicit missing evidence and eventual day integration. The companion `.design/kan-v2-operations-polish.md` covers every operations review follow-up. This design does not claim the full frontend or its missing backend contracts are implemented.

## Requirements
- REQ-1: Provide coherent navigation across Library, Sessions, Knowledge, Saved views, Analysis, Operations, Storage/recovery, Migration and Access/settings. A complete frontend includes readable evidence and useful human workflows, not just admin metrics.
- REQ-2: Browse and search authorized retained data across projects, scopes, hosts, observers, time, type and tags, with bounded pagination and stable deep links. Project grouping never implies scope access. Show selection, source/index frontier, exclusions and incomplete coverage.
- REQ-3: Read reconstructed sessions with user/assistant/tool events, attachments, branches, compaction and gaps; inspect the exact captured source alongside each normalized rendering. Unsupported payloads remain downloadable/inspectable subject to grants and size limits, not silently omitted.
- REQ-4: Distinguish raw observed evidence, human annotations, imported v1 claims and model-produced interpretations. Inspect origin, observer, claimed speaker, signature validity, scope admission, consumer trust and citations separately. Every derived summary can lead back to exact source spans and the run that produced it.
- REQ-5: Create explicit attributed annotations, tags, relations and saved views through the shared signed/encrypted API. Edits append new records and preserve prior history; retraction does not destroy a subject. Preview scope, target and effect before committing a user action.
- REQ-6: Make views first-class, with selectable authorized scopes, snapshot/frontier, trust/enrichment frame, filters and grouping. Offer table, session and relation views with textual equivalents. Contradictory witnesses remain accessible; no similarity/cluster result silently creates identity.
- REQ-7: Expose background extraction and day-style assessment as inspectable jobs/runs: input selection, recipe/prompt/schema, model identity, trigger, progress, attempts, outputs, cost when available and exact evidence lineage. Explicit user actions can schedule work under grants/quotas; viewing content cannot execute instructions found in it.
- REQ-8: Include the complete operational/admin surface: capture sources, spool/ledger health, retained gaps, journal rotation, backup checkpoints, restore verification, migration inventory/plans/progress, scope memberships, reader/writer grants, key epochs and instance configuration. Owners must be able to execute supported administrative tasks from the full frontend through separately authorized plan/job APIs, including rotation; permanent CLI-only instructions do not satisfy full-frontend completion. Read capability, mutation capability and missing backend support are explicit.
- REQ-9: Keep blind storage separate from the plaintext reader/index and optional annotation signer. A browser session gets only authorized data and operations; neither an operations token nor an ordinary reader session gains archive-admin or signing authority implicitly. Secret key material never enters view URLs, diagnostics or ordinary browser persistence.
- REQ-10: Treat captured content as untrusted. Render text/Markdown/code without executable HTML, script, external resource loading or active attachments; expose safe source views and explicit downloads. Search, snippets, facets, counts, exports and derived results obey scope authorization without existence leaks.
- REQ-11: Deliver accessible, responsive, polished human interaction: keyboard navigation, visible focus, usable long documents/tables, error/loading/empty/locked states, inspector focus management, reduced motion and text-labeled status. Avoid invented data visualizations or dead navigation masquerading as implemented functionality.
- REQ-12: Track end-to-end feature completeness through a capability matrix and reviewed vertical slices. Preserve CLI/MCP/API semantics and canonical identity/URI rules; every new writer extends persistence conformance. No phase is called a complete frontend until its human workflows work against real APIs.

## Acceptance Criteria
- [ ] AC-1: From the real Library, find a retained session across two authorized projects, narrow by observer/time/tag, paginate at a pinned snapshot, open a stable link and return to the same list state. An unauthorized third scope contributes no snippets, facet counts or inferred existence. Missing/stale indexes produce incomplete coverage, not empty success. (REQ-1, REQ-2, REQ-9, REQ-10)
- [ ] AC-2: A fixture session containing tool output, an attachment, branches, compaction, cancellation and an unknown payload type renders every available event or a typed unavailable state. Source inspection/export reproduces exact selected retained bytes; normalized speaker labels never imply a signature that does not exist. (REQ-3, REQ-4)
- [ ] AC-3: Follow a summary to its extraction run, input manifest and cited byte/span references; compare two conflicting interpretations without overwriting either. Inspect imported v1 origin and all four read judgments. Broken, withheld and erased references retain distinct authorized states. (REQ-4, REQ-7)
- [ ] AC-4: Annotate a selected source span, preview scope/author/effect, submit with an idempotency key, lose the response and retry without duplicate attribution. Edit/retract while preserving history and provenance. The same operation through CLI and UI yields equivalent signed/encrypted records. (REQ-5, REQ-9, REQ-12)
- [ ] AC-5: Save a view with a pinned input/trust frame; reopening it produces the same membership and judgments despite arrival-order changes. Changing trust or scope produces a visibly different view. Relation inspection retains witnesses and contradictory paths; accessible list/table views expose the same relationships. (REQ-6)
- [ ] AC-6: Schedule an authorized analysis over an explicit selection, inspect its plan, interrupt/retry, and retain every attempt plus unknown provider outcomes. A changed recipe creates a new run; a captured prompt-injection string cannot grant access or schedule work. Unsupported costs/versions are unknown, not zero or invented. (REQ-7, REQ-9, REQ-10)
- [ ] AC-7: Exercise the operations state matrix and all rotation/recovery controls in the companion design. From the human UI inspect a backup checkpoint, a restore verification report, a migration plan with per-source failures and the final-delta/cutover preconditions. Mutation actions require their own capability and a concrete preview. Execute an owner-authorized synthetic rotation through the admin API, observe progress/reconnect, and compare its effects to the CLI protocol; a read-only operations token must be denied. Synthetic fixtures only until deployment is separately authorized. (REQ-8)
- [ ] AC-8: Revoke reader access and verify subsequent reads, indexes, snippets, attachments and exports cannot disclose the revoked scope. Lock clears rendered content and client query caches; responses are no-store. Verify CSRF/origin/session boundaries on mutations and prevent admin or signer privilege through a read-only session. Revocation makes no promise to recall plaintext already copied by a user. (REQ-9, REQ-10)
- [ ] AC-9: Browser tests at desktop, tablet and 390px cover all implemented navigation, filters, keyboard interactions, long identifiers, large paginated lists, inspector open/close, failed fetch, empty/partial results and lock. No body-level horizontal overflow; raw tables may scroll within labeled regions. No external asset requests or executable captured content. (REQ-11)
- [ ] AC-10: Each screen's capability matrix names real API contracts, tests and exact reviewed commits. A UI-only mock or CLI primitive is not marked integrated. Fresh actual Claude Code Opus 5.5 reviews substantive builds/fix rounds; finding fixes include whole-production-fix reversion evidence. (REQ-12)

## Architecture

### Human information architecture

| Area | Human task | Detail/secondary views |
|---|---|---|
| Library | Find anything retained or derived within authorized inputs | Global search, facets, result type, source preview, coverage, export selection |
| Sessions | Read the history of work | Transcript, event timeline, branches, tool calls, attachments, raw source and provenance |
| Knowledge | Inspect and add what has been asserted | Claims/annotations, tags, subjects, relations, disputes, four judgments, correction history |
| Saved views | Return to a meaningful perspective | Scope/trust/frame editor, pinned or live frontier, table/session/relation rendering |
| Analysis | Understand and request interpretation | Recipes, jobs, attempts, outputs, input manifests, prompt/schema/model lineage, assessments |
| Operations | Understand whether collection and delivery are working | Sources, reporter freshness, queues, retries, gaps, journal capacity and rotation guidance |
| Storage & recovery | Know what is retained and recoverable | Partitions/generations, checkpoints, export plans, backup coverage, restore verification, erasure plans |
| Migration | Bring old stores into the aggregate service | Discovery, inventory, destination mapping, plan preview, enqueue/delivery/reconciliation, final delta |
| Access & settings | Control who can do what | Scope membership, capabilities, reader grants, key epoch metadata, instance metadata profile, client connections |

The primary navigation separates exploration, interpretation and administration, but the same evidence inspector and stable links work across them. A project is a filter/association, not a mandatory storage container. A session may span projects; unrelated personal work remains findable without inventing a repository. Full application scope includes all rows; delivery sequencing does not quietly remove any of them.

### What exists and what needs building

The operations service in `src/evidence_dashboard.rs` remains separate from the new authorized Library in `src/evidence_library.rs`. The Library composes real snapshot/page/read service operations and exact source/provenance inspection. Neither service yet supplies normalized transcripts, semantic search, full claim views or administrative execution. The full application still requires those integrations.

| Capability | Existing foundation | Missing integration/contract |
|---|---|---|
| Raw inventory/retrieval | `src/evidence_service.rs` signed Snapshot/Page/Read operations; `src/evidence_reader.rs` authorized pins/ranges; `web/library/` real paging and source/provenance UI in #286 | Per-record unavailable evidence, semantic normalization, stable resource links, merged cross-scope results and complete browser/export qualification |
| Decryption | `src/evidence_crypto.rs`; explicit CLI `DecryptRequest`; imported-source restore; separate reader signing principal, explicit scope keys and bounded in-memory Library reads | Key/grant epoch lifecycle, encrypted search projections and deployment/custody qualification |
| Session reconstruction | Capture observations in `src/evidence_capture.rs` and `src/evidence_gateway.rs` | Versioned provider/harness adapters, branching/compaction/attachment coverage and source maps |
| Search/facets | v1 query/fold references; parent architecture's reader-bound index design | Incremental authorized encrypted index, pinned frontiers, coverage diagnostics, ACL-aware search and invalidation |
| Claims/annotations | `src/claim/view.rs`, `src/fold/`, identity and CLI/MCP semantics | v2 read adapter and separately authorized annotation signer; no semantic writes through blind storage |
| Views/relations | `src/fold/identity.rs`, `src/fold/state.rs`, `src/fold/relations.rs`, `src/uri.rs` | Explicit view recipes, input/trust frames, saved-view authority and browser rendering |
| Analysis/day | Architectural run/assessment model in `.design/kan-v2-server-first.md` | Scheduler/worker APIs, immutable run records and assessment integration; not present in current dashboard |
| Operations | `src/evidence_operations.rs`, `src/evidence_dashboard.rs`, `web/operations/`; capacity and preserved-history collection in #283–#285 | Concrete surviving review tests, deduplicated collection overview (#287), shared app integration and separate admin plan/job execution |
| Migration/restore | `src/evidence_import.rs`, `src/evidence_restore.rs`, `src/migration_preflight.rs`, `src/bin/kan-v2.rs` | Capability-scoped job adapters and plan/status UI; local filesystem picker belongs to the selected agent host |
| Backup/access/retention | Ledger backup/verify and service grants; reviewed design boundaries | Administrative plans/jobs, recovery key/grant lifecycle, revocation/erasure protocol and readable audit |

The table records foundations, not shipped end-to-end support. Canonical capture/resource URI additions must follow RFC 2's extension process; a prototype route or `demo:` identifier is not a production URI definition.

### Reader and application boundary

Keep three authorities separate: blind ledger/storage, authorized plaintext reader/index, and privileged administrative or annotation-signing operations. They may be co-hosted on the home server, but use separate principals, credentials and granted capabilities. The inference gateway does not gain historical archive-reading powers because a human UI exists.

The browser talks to an authenticated application API. This adapter composes existing operations and reader contracts; it does not scrape CLI prose or shell arbitrary browser-supplied commands. Typed request plans expose exact targets, scope, snapshot, estimated work and side effects before authorized mutations. Durable job IDs support progress and reconnects. Sensitive actions such as access grants, exports, erasure, restore destinations and final cutover have distinct capabilities and confirmations bound to the reviewed plan; ordinary read navigation remains frictionless.

Reader indexes and normalized caches are disposable projections pinned to evidence membership, processing frontier, normalization version and trust frame. Encrypt persistent plaintext-derived indexes under reader custody, including temporary/WAL/backup paths; storage credentials must not read them. Separate budgets prevent interactive search or indexing from starving capture. Cancellation stops the read/job attempt within its contract, not the underlying capture service.

The deployment location of the reader is the one open product decision below. Both local and separately authorized home-server reader deployments use the same logical API. This design does not introduce browser-managed archive keys by default.

### Shared resource and state model

Use typed resources for evidence occurrences, byte/span selections, reconstructed sessions, claims/annotations, saved-view definitions, model runs, operational observations, migration plans and administrative jobs. A list result carries authorized scope selection, evidence snapshot vector, index frontier, coverage/exclusions, continuation cursor and interpretation version. Distinguish missing, unavailable, unsupported, access-limited, corrupt and empty-at-snapshot without leaking inaccessible existence.

A reusable inspector provides Content, Source and Provenance views. Content is a normalized presentation. Source displays exact authorized retained bytes or their explicit bounded byte range. Provenance identifies the observer, claimed speaker, ingestion/import origin, signature/admission/trust judgments, causal links and citations. A summary is visibly an interpretation, with a source/run link; it never substitutes for unavailable raw evidence.

Display corpus counts only over the declared authorized/query coverage. Search indexes can lag the raw ledger; show that lag near results and offer bounded exact inventory inspection where permitted. Do not market search results as "everything" when coverage is partial. The product ambition is full access to the user's retained knowledge, while every particular query remains honest about its bounds.

### Interaction and visual language

Use an ink/white/cool-gray palette with electric blue for primary interactions and active navigation. Compact groups, thin rules, small consistent radii and generous hierarchy around primary content replace the original pastel card grid. System sans and tabular monospace numerals avoid a remote font dependency. Keep reading panes comfortable even where metadata lists are dense.

The Library offers a resizable-style master/detail composition: scoped search and filters, a readable result list with provenance/type labels, and an inspector that can expand to a focused reader. Sessions make messages primary, with raw/provenance a deliberate adjacent view. Knowledge uses tables/lists and inspectable relationships; a graph is an optional lens, with a complete keyboard-accessible textual alternative. Analysis makes inputs and outputs legible, not merely progress badges.

Operations retains the companion design's separation between current observations and historical gaps. Administration uses the same visual language and inspector patterns as browsing. Preview/demo screens label synthetic data persistently. Production navigation exposes implemented capabilities and clear availability states; prototypes may demonstrate the full target with a visible implementation map. No fake live charts, activity animation or invented cost/throughput values.

### Delivery sequence and definition of complete

1. Close the operations follow-ups in the companion design, preserving the #279 checkpoint.
2. Establish the reader/API/authentication boundary and app shell; integrate real bounded inventory and source/provenance inspection.
3. Add session reconstruction, cross-project search/facets and coverage-aware deep links.
4. Integrate annotations, knowledge/relations and saved trust-aware views with their existing semantic contracts.
5. Integrate migration, storage/recovery and access management through reviewed plan/job APIs.
6. Add analysis/day runs and assessments when their backend contracts are implemented; preserve source/run lineage throughout.
7. Run end-to-end role/scope, recovery, accessibility, large-data and real-browser qualification across all areas.

Each slice can ship useful functionality, but only completion of the matrix and its end-to-end criteria earns "full frontend". The synthetic prototype is visual/interaction design evidence, not slice completion. Fresh Opus 5.5 review remains standard for each substantive build/fix point. Main merges, live deployments, production credentials and cutover require their existing explicit authorization boundaries.

## Resolved Questions
- Q1: The user explicitly wants the complete human frontend, including rich browsing and all administration/operations; this supersedes the earlier operations-only selection.
- Q2: Technical studio styling: clean light surfaces, dense data and vivid accent color.
- Q3: Health-journal rotation is owner-triggered and preserves history, as specified in the companion design.

## Open Questions
<!-- OPEN: Q4 -->
### Q4: First authorized reader deployment
The browser requires a plaintext reader and searchable projections, separately privileged from blind storage. The user has been asked to choose a separately authorized home-server service, a local-computer reader, or support for both with deployment selection deferred. The recommended first deployment is the separate home-server reader, matching the user's service-first infrastructure goal. No key placement is assumed until this is answered; synthetic design work does not depend on it.
<!-- /OPEN -->

## Out of Scope
- Claiming a working full frontend from synthetic screens or the existing operations endpoint alone.
- Replacing Kan's evidence/identity model, bypassing grant boundaries, silently expiring retained data or rewriting old claims.
- Public internet deployment, production key provisioning, live data import, service installation or cutover during this design pass.
- Sending external messages or granting workflows new powers from captured content.

## Process record
Design work is retained in the permanent `.worktrees/kan-v2-operations-polish` checkout. Only `.design/` artifacts change in this pass. The main bulk kan read still withholds two claims; process composition is explicitly partial. Claim/bridge backfill remains pending under the standing Git-first workaround. `telos/raw-data-and-projections` is the existing target and deliberately declares no maintenance witnesses; none are fabricated. The process graph reports generative-build after design. Runtime acceptance criteria remain unchecked.

## Appearance preference

The owner requested System/Light/Dark on 2026-10-18. System is the default and
follows live platform changes. An explicit light/dark choice is retained in the
browser origin under `localStorage["kan.theme"]`; selecting System removes it.
Only this enumerated appearance preference may be written by `web/theme.js`,
which is its narrow browser-side persistence owner (not a Rust filesystem
capability). Failed browser storage falls back to tab memory. Tokens, message
content, keys and search results never use this surface. The same controller
serves the production dashboard and the generated offline design artifact.

## Build checkpoint — operations generations and next reader slice

The shared appearance controller and worker-history correction are in draft #281;
bounded coalescing is in #282; sharded admission/reversion tooling is in #283.
Capacity, preserved-history collection commands, recent-list search and metadata
inspection are in draft #284 (production 67e3414, review record 771341e). Fresh
Opus 5.5 review approved with follow-ups. The child admission-audit correction
addresses those findings plus WAL-header refusal; its review remains pending. They still do not provide
raw message browsing. The collection-wide deduplicated overview remains required.

`.design/kan-v2-reader-library.md` makes the next real Library API boundary concrete:
signed snapshot inventory, authorized bounded source/provenance inspection, and
no persistent plaintext index. It is a build plan, not a capability claim. The
existing reader-placement question remains open; portable code and synthetic
fixtures do not select production key placement.


### Current build checkpoint

The real Library is stacked in #286 through a8cbf21; its initial fresh Opus review
approved with follow-ups, and the corrections have their own review pending.
System/Light/Dark follows platform settings by default. Inventory, byte ranges,
source/provenance, lock clearing and a visible API-driven capability matrix are
implemented. These do not close this document's composite acceptance criteria.
The next operations projection contract is #287. See
`.design/kan-v2-followup-status.md` for concrete remaining work and preserved
review gaps; this table must not turn “foundation exists” into “workflow complete”.

### Persistent reader search and pinned views (integration, 2026-10-20)

The Library accepts an optional dedicated encrypted workspace database and recipient
key, outside repositories. Its signer is the configured reader. Index pages and
saved view declarations are signed with a separate workspace domain and encrypted
in bounded HPKE chunks; no plaintext SQLite index or browser cache is created.
A reader signature, exact source/pin/cursor binding and projection version are
required on a cached page. Database identifiers expose kind, sizes and opaque
hashes under the default rich-metadata policy. This is a reader-owned projection
service, not a new authority for the blind evidence service.

`index-page` builds eight occurrences at a time, `search-page` queries that exact
page, and `save-view`/`views` preserve explicit source snapshots, text and conjunctive
writer/kind filters. The shared JSON request also runs through `kan-v2 library
--request`. Raw text search is ASCII case-insensitive with exact UTF-8 byte citations;
non-ASCII text matches exactly. Capture headers and complete UTF-8 bodies are
separate spans. Binary spans and phrases crossing capture chunks are explicitly
outside this projection's coverage; normalized-session search remains a later layer.
Every search rechecks present remote authorization and rereads matches before
returning snippets. Facets are labeled as indexed. Saved views pin membership and
trust framing, not enduring access or current payload availability. Listing a view
requires present access to all its sources; unavailable scopes reveal no titles.

The database is owner-only, rollback-journal mode, capped at 256 MiB; a value is
bounded to 12 MiB and view declarations to 256 KiB, with at most 200 views. Capacity
exhaustion is an explicit failure without silent expiry or overwrite. View saves
are content-addressed and idempotent; changed declarations retain prior versions.
Index pages are disposable immutable projections and can be rebuilt into a new
workspace. Normal open refuses hot journals. Explicit CLI or owner recovery copies
a stopped database and its rollback journal into a new file, lets SQLite recover
only that copy, then authenticates every retained entry. Originals and failed
outputs remain. Maintenance and scheduler locks use separate owner-private inodes;
older processes without these locks must also be stopped. WAL workspaces,
malformed journals and super-journal references are refused. A separately functioning
owner journal can recover a reader workspace; a damaged owner journal uses the CLI.
A recovered file is never activated automatically. Entry authentication does not
prove completeness against an independent checkpoint. Back up the workspace and its key separately: deleting
it loses view declarations. Source erasure must also clear affected projections in
the eventual owner erasure plan; normal search does not serve cached deleted bytes.

### Explicit annotations on verified evidence (integration)

The reader workspace also stores signed, encrypted owner annotations. This is an
explicit new record type, distinct from observed raw bytes, imported v1 claims and
machine-generated outputs. `annotation-preview` verifies the exact supplied source
selection tokens and reports current availability and the configured signing author;
`annotation-save` rechecks the citations and requires the preview's content digest.
The CLI and UI share these operations. Drafts contain subject, text, tags and up to
eight whole-occurrence citations. Tags are deterministic sorted sets. `supersedes`
adds a correction edge to an earlier annotation by the same author and subject,
inheriting every earlier evidence citation. It never mutates or hides the original.
Saves are content-addressed and idempotent; the annotation list displays all history
and permits exact subject/tag filtering. All cited sources must remain authorized
for the annotation to be displayed. Missing payloads remain citable as explicitly
unavailable evidence. The private workspace has a 1,000 annotation declaration
budget, with explicit capacity failure and no automatic expiry. Other relation
kinds, imported-v1 claim rendering and tag-triggered analysis remain separate work.

### Annotation withdrawal

`withdraws` appends a reason against one earlier annotation by the same author
and subject. It is mutually exclusive with correction, carries no new tags or
relations, inherits all original citations and analysis lineage, and schedules no
automatic analysis. A withdrawal cannot target another withdrawal. The original
record, subject, relation edges and published copies remain evidence; lists and
relation views label the author's withdrawal rather than erase history. Retraction
of a correction does not implicitly retract its parent or reinstate another record.
A new declaration can express a later position. Restored links affect display only
when the original and linked record are both authorized and their authors and
subjects match. Missing parents remain unresolved. Search over annotation history
continues to include withdrawn records and reports that history scope explicitly.

### Live proof-archive ingress

`serve-admitted` connects the existing durable spool protocol to the profile-2
admission API. It accepts only authenticated scoped append requests, returns the
existing signed durable commit reply after atomic source/receipt/attestation
commit, and leaves all reads to the proof-aware read service. No append-to-read
fallback or automatic legacy conversion is introduced. This supplies the live
capture-to-proof-Library route; full-archive admission audit performance remains
unchanged. Reader-workspace annotations are currently local authored records;
publication of those declarations to the blind ledger is still required before
calling the knowledge work package complete.

### Annotation publication through the shared spool

An optional operator-selected annotation outbox binds an existing spool, a fixed
loopback/tunnel service endpoint, a recipient key and the workspace signing author.
The UI first reads a destination preview, then explicitly queues the selected
immutable declaration. Its confirmation digest binds scope, issuer, recipient,
endpoint, spool path and writer; every use rechecks the spool's current binding.
The plaintext frame is canonical JSON `{format: "kan-annotation/1", declaration}`,
encrypted and signed by the existing delivery layer. The inner author is the
workspace signer and the outer retained writer; no plaintext enters the blind
service. A deterministic operation ID makes retries reuse the exact queued bytes.
The UI distinguishes local-only, queued and acknowledged publication; a lost reply
is resolved by inspecting the spool, never by resealing or replaying inference.
One bounded delivery action advances the configured queue; the existing drainer
can run it independently. Cross-reader citation resolution, reconstruction of
workspace projections from published declarations and imported v1 claim rendering
remain required; this publication adapter alone does not close Knowledge.

### Conversation reading across archives

`proof-session` composes the existing verified attempt interpreter for up to eight
explicit attempts / 1024 occurrences / 96 MiB rendered content per request. Every
archive is checked again before returning any content. Missing payloads remain
visible; membership metadata is labeled claimed, conflicting or unconfirmed.
The response keeps each original pin, occurrence and byte citation. Selection
order is a presentation order, not an invented chronology. Supplied request
history is collapsed separately from responses; archive copies, branch and
compaction claims are never collapsed into a single fabricated conversation.
The frontend offers consecutive eight-attempt windows and retains exact source
navigation. Larger selections remain browsable individually. This is shared
CLI/API/UI presentation over the raw ledger, with no new persistent authority.

### Background analysis execution contract

An optional private instance configuration enables named, versioned recipes
(including day assessment), a fixed local inference-gateway endpoint/model, an
explicit source allowlist, byte/output/job quotas and at most one active job.
The reader preview rereads exact authorized citations and hashes the complete
provider request plus recipe and destination. Submission must repeat that digest
and a retry-stable nonce. A changed source or configuration invalidates preview.
No model output creates an annotation, changes a grant or invokes a tool.

Encrypted signed workspace records retain the job declaration, exact input bytes,
provider request, observed response and append-only lifecycle events. A running
job with no live worker after restart is interrupted, never silently resumed.
Explicit retry is a new linked job with fresh source checks; cancellation records
intent before aborting the worker. Inspection rechecks every input source grant.
The server runs asynchronously; the shared request supports waiting for completion
for one-shot CLI use. Tag scheduling must use this same declaration/runner and
limits, not an independent privileged execution path.

Tag triggers are optional instance declarations (`tag`, `recipe`), limited to
eight. Matching recipes, revision, model and destination are part of the signed
annotation preview and declaration. Appending queues those jobs through the same
preview-bound runner; deterministic nonces prevent duplicate inference on save
or scheduling retries. An encrypted append-only receipt records scheduled job IDs
or scheduling failure. Explicit retry retains the earlier receipt and refuses a
changed trigger plan. At most sixteen jobs are queued/live and one dispatches at
a time. The worker rereads every input and compares its hash immediately before
sending; revoked, erased or changed inputs fail before dispatch. A restarted
scheduler marks previously queued/running work interrupted rather than replaying.

A user may draft an annotation from a model result, edit it, preview it and append
it. `derived_from` references the original jobs. The server requires their retained
results, inherits their evidence citations, and carries both through corrections.
Promotion is therefore an explicit authored interpretation with inspectable model
provenance, never an automatic conversion of model text into an original claim.

### Attributed subjects, relations and day declarations

Annotations may declare up to sixteen typed relations using kan's existing
`RelationKind` vocabulary. The subject graph is a pure authorized view of those
signed annotations: outgoing direction, author, source citations and correction
history remain visible. It does not merge identities or discard an earlier
assertion when a correction appears. Subject counts and edges include only
currently authorized declarations, and a referenced target never implies access
to its evidence.

The day view selects `telos/`, `atom/`, `bridge/` and `thread/` subjects. Explicit
fenced day JSON is shown as declared data beside the original text, including
malformed-declaration notices. A human can follow relations, inspect a subject's
history, and send its cited evidence through the configured day-assessment recipe.
Imported native v1 files and individually signed claims now have their own source-cited browser. Applying repository membership and the richer native trust/fold queries remains a separate requirement.

### Owner maintenance boundary

Owner jobs have a separate bearer credential and encrypted signed journal from
the evidence reader and operations observer. Private instance configuration names
allowed archive/collection targets and output directories; browser requests may
select names and operation enums, never arbitrary paths, commands or key material.
A preview binds target configuration, operation, retry parent and nonce; submit
must repeat its digest. Backup/recovery outputs use new nonce-named files and are
never overwritten or activated. Retried jobs retain earlier results and outputs.

Backup, derived-data recovery and retained-history rotation call their existing
owner APIs directly. One maintenance job runs at a time. Once a synchronous
maintenance operation starts it is allowed to reach its existing safe boundary;
closing the browser does not pretend to cancel or roll it back. Restart reports
unfinished journal entries as interrupted. Credentials and source keys never
appear in the browser. Provisioning this API does not grant authority to reader
or model-generated actions. Migration now uses a fixed source/spool/recipient target
and a preview-pinned source inventory; jobs queue bounded encrypted batches with
exact retries and linked continuation. Import recovery uses a fixed plan, key,
archive binding and output root, previews its plaintext effect, and records the
new output/report location. Proof metadata audit and restoration share a pinned
transaction. Access changes, key lifecycle, reconciliation/cutover and explicit
erasure require further owner contracts and remain build work.

### Reconstructed search

The raw encrypted index remains page-addressed. Search responses additionally
expose authorized capture membership so the browser can reconstruct explicit
attempts after completing the selected archive scan. The shared `search-attempt`
API uses the existing Content assembler/interpreter, current access checks and
limits. It searches supported message text across capture chunks, retaining all
enclosing source ranges and reporting unavailable streams. Message boundaries
are preserved; separate SSE delta items are not implicitly concatenated. No
normalized text is written to blind storage. Browser work windows bound retained
members and interpretation calls, and cancellation keeps completed results only.

### Portable provenance and annotation recovery

Portable references bind archive identity, sequence and manifest/attestation/receipt
identities. Resolution obtains a fresh authorized snapshot and verifies membership
through the existing proof service; it never imports another reader's authority.
Signed historical citation tokens can likewise be rebound through current service
verification. Their original pin is retained as source data, not treated as a new
reader capability. Analysis previews bind immutable record metadata and original
citations, excluding newly minted local continuation signatures.

Explicit annotation recovery reads a publication under current grants, verifies
its writer and original declaration hash, and previews installation in the encrypted
workspace. One immutable annotation value retains the original declaration plus
its recovery origin, making attribution and disclosure dependencies atomic.
Recovered records require current access to the publication and all cited archives.
No trigger or publication is invoked. Exact retries preserve prior entries;
foreign-authored records cannot be republished under the restoring reader's name.

### Imported repository membership and native v1 views

The imported-file reader now pairs a CAR only with its sibling `HEAD` from the
same verified import plan. It verifies both file hashes, the entire CAR scan,
HEAD's commit, static did:key commit signatures, and bounded ordered MST
reachability before marking records current members. It never chooses a newer
commit or the CAR header root when HEAD is unavailable. Historical/unreferenced
blocks retain their individual signature display and exact byte citations.
Other commit identity methods explicitly require resolution; graph reachability
alone is not identity authentication, scope admission or user trust.

The shared `proof-import` API accepts `view.trust` as exact v1 author identities
(including agent qualifiers) and `view.subjects_after` for pagination. No authors
are included implicitly. The existing pure v1 identity, retraction, rejection
and state folds interpret verified reachable `tools.kan.claim` / `dev.kan.claim`
records; author exclusion counts, SameAs witnesses, live status claims and
contested states remain inspectable. Every folded claim links back to its CAR
block and retained source ranges. Local subjects stay inside this imported
repository; no cross-import identity merge is inferred. Current identity-governed
and unsupported codecs remain visible outside this legacy fold. Git ancestry is
not reconstructed from an import that did not include that evidence.

Presentation bounds are 4,096 reachable records, 8,192 tree nodes, depth 32,
128 authors, and 100 subject groups / 2 MiB per fold page. Larger or incomplete
views report their limit and keep the raw file browser available. These are
query limits, not ingestion or retention caps. No persistent derived authority
or mutation surface is added.

### Live access policy administration

Proof ingest and proof-read servers may opt into one owner-pinned signed policy
journal, in place of a static grants file. The policy has the exact archive,
scope and issuer binding, explicit full grant set, ordered revision, previous
record digest and nonce. Append and inventory are independent capabilities;
policy membership supplies no decryption key, provider-forwarding privilege or
administrative authority. Owner previews bind the prior tip and complete next
grant set. Applying a stale preview fails; retrying the exact signed declaration
is idempotent. Prior policies remain immutable and readable.

The same private journal directory can be mounted in separate local services.
Every request reads and verifies current policy under a shared lease held through
its authorization/operation; policy changes take the exclusive lease. An
unreadable, inconsistent or incomplete policy fails closed. A revoked reader's
next operation cannot reuse an earlier snapshot as authority. In-flight work that
acquired the earlier policy completes before the change commits. Reader API
credentials cannot use owner controls. Existing static-grant mode remains explicit
and does not acquire a fictitious live-update guarantee.

The default policy metadata is signed plaintext (principals, capabilities and
change times), consistent with the personal instance's rich-metadata profile;
raw evidence remains encrypted. Deployment must keep the policy directory private
and back it up with the archive and an independently held current policy digest.
An optional minimum policy digest detects rollback before that checkpoint.
Signatures alone cannot detect a whole-directory rollback to an otherwise valid
prefix when no external checkpoint survives. Key custody/rotation and payload
erasure are separate contracts, not effects of grant removal.

### Encryption epochs and independent recovery (2026-10-20 implementation contract)

The owner chooses a pinned key-history directory, exact proof binding, signing
identity and separate X25519 recovery public key. Epoch changes are immutable,
owner-signed, previous-digest-linked records. Each new random recipient private
key is HPKE-wrapped to the recovery recipient with a separate wrapping-domain
context bound to the full archive/profile/scope/issuer identity; neither
blind storage, capture nor browser responses receive unwrapped private keys.
An owner preview shows the new public recipient, previous checkpoint and effect;
apply uses an exact digest and compare-and-swap. Old epochs remain retained.
This is rotation, not erasure, and cannot recall previously distributed keys.

Epoch-aware capture verifies the current history once per new attempt and holds
that public recipient through completion. In-flight and spooled requests never
get re-encrypted on retry. A runtime history failure produces the normal visible
recording gap while inference continues. Proof readers explicitly configure the
wrapped history and a separately held recovery credential, reload epochs when
reading, and continue to check current storage grants. Existing single-key scopes
remain supported; historical explicit keys provide a migration path. A missing
matching epoch is `key-unavailable`, retaining provenance and ciphertext
availability separately from missing/corrupt source material. Import validation
binds to the actual recipient of the selected frames, not whichever epoch is new.

The human owner surface shares inspect, preview/apply rotation, wrapped package
export and preview/restore with the owner CLI/API. Packages include the complete
signed wrapped-key chain and tip, never the recovery private credential. Restore
accepts only an identical existing prefix in a separately configured initialized
private directory and never activates service configurations. A separately kept
minimum digest detects rollback; absent such a witness, valid-prefix truncation
cannot be detected. The current format admits at most 64 epochs / 128 KiB of key
history, with explicit capacity failure and no automatic deletion. Increasing
that format limit is separate from evidence retention/capture capacity.

Archive ciphertext, access-policy history, encrypted reader/owner workspaces and
independent credentials are separate backup dependencies. A key-package export
alone is not a complete instance backup. Recovery credential rotation, delegated
per-reader wrapping, selective payload erasure and the full clean-host drill
remain separately required; this first epoch format does not claim them.


### Imported current-codec claims and control evidence

Repository membership continues to come only from the exact selected HEAD/MST.
The current-codec view separately invokes the existing identity, governance,
capability, mixed-claim and status-fold implementations. Humans explicitly select
public control files across authorized imported snapshots, then select trusted
current principals independently from legacy composite authors. Control references
are reader-verified source selections; their exact byte ranges and current access
are rechecked when used. Lock clears the browser's control selection.

Every displayed current claim separates cryptographic validity, exact identity
state, scope admission and view trust. Missing authority never becomes admission
because a signature verifies. Genesis/recovery checkpoints and methods without
capability-invocation purpose cannot exercise scope reach. Unsupported selected
control evidence makes authority unresolved. Inception-only did:kan authority is
limited to the existing native verifier; unsupported later governance is not
inferred. A delegated claim requires the named head to delegate to that principal,
and the native path evaluator handles coverage, revocation and time requirements.
Author-recorded time is never used as trusted time.

Resolver conclusions are relative to the explicitly selected evidence set, not
a promise of globally complete/current control history. No implicit network
resolution, Git ancestry, legacy subject remapping or cross-repository identity
collapse occurs. Unknown/retired identity versions remain raw inspectable evidence
if the current native verifier cannot authenticate them. These limitations are
shown beside the human trust selectors and control provenance.

### Recovery replacement and explicit epoch sharing

The owner previews an exact current history tip, destination X25519 public key,
and ordered epoch record IDs. Replacement requires every current epoch; sharing
requires an explicit nonempty subset. The preview returns metadata only. Apply
holds a source-history lease, checks the exact preview and tip, unlocks only the
selected epochs, and returns an owner-signed recovery package wrapped to the new
recipient. Each resulting record retains a signed origin reference to the old
record, history tip, recovery recipient and transfer purpose. Original histories
and their independent backup packages remain retained as provenance.

The recipient restores into a separately initialized private directory using the
existing API/CLI/UI. It must independently pin the archive, owner, new recipient
and returned checkpoint; a package does not choose those trust anchors. No live
reader or gateway config changes automatically. For replacement, stop capture,
export/restore/verify the new complete history, update both configurations and
rotate to a fresh epoch before resuming. An intervening rotation invalidates the
preview. Old credentials still decrypt previously wrapped epochs and backups;
replacement protects future epochs only after activation and a fresh rotation.
Shared packages confer decryption custody of selected epochs, not storage grants,
owner signing authority or future epoch keys. Keys already distributed cannot be
recalled. Retain the returned wrapped package independently from its private key.

### Search by attributed annotations

Raw and reconstructed search accept conjunctive `annotation_subject` and
`annotation_tag` filters. The human Search form and saved filters expose both.
They select occurrences through the current authorized annotation history,
including retained corrections; they do not treat captured text as a tag, collapse
subjects or infer project membership. Every matching annotation must retain access
to every cited source and publication origin. Its signed citation coordinate is
matched to an already verified result; normalized messages match when at least
one contributing occurrence is cited. This coordinate check confers no read grant.

Filtering runs after current source verification and uses a bounded worker for
citation checks. Full attempt membership remains available for reconstruction;
tags must not truncate message chunks. Corpus facets, unavailable-source counts
and reconstruction coverage stay separately labeled as unfiltered. Saved views
retain the explicit filter and raw snapshot, while annotation membership is
reevaluated against currently visible history and is not a historical trust pin.

### Saved imported evidence and trust frames

A saved import view records the exact archive binding/pin, selected occurrences,
import plan/file, legacy author set, current principal set and selected control
citations. Save verifies the selected import and controls with current grants;
reopening reruns those same inputs rather than adopting the tab's newer control
selection or newer archive records. Every referenced source must still be currently
authorized before its saved name or inputs are listed. Loss remains explicit on
reopen. Trust changes produce a new content-addressed declaration, retaining the
old view. The encrypted workspace's existing view bounds apply (200 declarations,
256 KiB each). Saving a view does not make its relative authority globally current.

### Native file delivery

The browser's Blob/data-URL export path failed an isolated control while an HTTP
attachment produced the exact downloaded bytes. Source export therefore uses an
origin-checked native `POST /api/library/download`, with one `text/plain` form
field containing JSON `{token, request}`. The credential remains in the request
body, never a URL or cookie. Only existing source-range queries are accepted; the
server repeats current grant, signature, membership and availability checks and
returns bounded bytes as an attachment. The UI performs its ordinary source check
first to show normal failure states. A race-time failure on the native POST shows
the server's refusal and emits no attachment. Missing Origin and foreign Origin
are refused, even with a valid token. CSP permits forms only to the same origin.

`POST /api/owner/download` separately requires the owner credential and a bounded,
typed wrapped recovery package previously exported by the UI. It only delivers
that package as a file, without restoring, activating, unwrapping or granting
custody. Both forms are removed and cleared immediately after submission; responses
remain no-store. These routes add no persistent cache or ticket authority.

### Agent MCP adapter

`kan-v2 library --mcp` runs the existing configured Reader/API over stdio instead
of HTTP. `kan_v2_read` is the default tool; it accepts the same typed JSON requests
and refuses mutations. `--mcp-writes` explicitly advertises `kan_v2_write` for
annotations, indexing, saved views and analysis actions. `--mcp-owner` separately
requires owner configuration and advertises `kan_v2_owner`; supplying owner config
alone does not expose that authority to MCP. Read/write classification is exhaustive
across the request enum, including retry/cancel/restore variants. Existing previews,
idempotency, grants and bounded work remain authoritative. No new persistence path,
automatic policy action, credential creation or extra server is introduced.

Results retain the API's JSON as structured MCP content. Adapter failures preserve
access-limited, missing, corrupt, conflict, unavailable, busy and content-limit
states; none becomes an empty collection. Input lines are bounded before JSON
parsing; four concurrent tool executions share the Reader's own worker limits.
Stdio startup/shutdown creates no listener and writes no diagnostics to stdout.

### Owner erasure contract — accepted 2026-10-20, implementation pending

The owner accepted logical-capture selection, managed removal and enforced
no-resurrection on restore, with backup purge reported independently. The
authoritative policy is §10 of `kan-v2-server-first.md`; stronger cryptographic
irrecoverability from historical backups/keys is outside this guarantee.

The owner workflow must resolve a capture or explicit bulk selection into an exact
preview of raw records, chunks/attachments, affected derived material and managed
destinations. Ordinary browsing never acquires erasure authority. Partial discovery
or incomplete dependency enumeration must remain visible in the preview. After
explicit authorization, a durable signed record fences access and replay while a
restartable cleanup job reports each destination. An “erased by owner” source row
retains minimal provenance; it does not mean the subject/assertion was retracted.
Backups outside the active service remain visibly pending or outside Kan's control,
and must not be counted as purged without evidence.

Current storage verification requires every retained payload and its signed
request; simply deleting an object would make the archive fail its audit. The
implementation must introduce authenticated erased-evidence handling across
verification, availability, admission/retry, copying/backup/recovery and derived
workspaces together. A missing object without valid erasure authority remains
damage. Cold restore must apply independently retained current erasure history
before activation; replaying only the older checkpoint's history is insufficient.
These are outstanding implementation/qualification requirements, not shipped
behavior or authorization to erase existing data.

### Storage erasure implementation in progress

The proof storage API now prepares exact signed erasure plans at a pinned archive
frontier and commits authorization plus payload removal atomically. The optional
`erasures` table holds canonical issuer-signed records, chained independently from
the immutable admission proofs. Erased object rows retain only a one-byte marker
so immutable slot bindings and content identities survive; that marker is never
returned as evidence. Verifiers accept it only with valid signed erasure authority
and matching retained metadata. A missing marker, forged record, altered source
coordinate or restored payload under an erasure marker remains corruption.

The inventory, wire reader, Library Source, Content, discovery and search propagate
an explicit `erased` state. Native downloads and analysis input acquisition refuse
it. Exact signed-request replay is fenced before staging. Backup and derived-index
rebuild preserve the signed history. Reconciliation of an older archive requires
an independently supplied history and explicit expected tip, rejecting forks and
rollback; erased objects absent from the old checkpoint remain fenced. A restored
prefix behind that history cannot admit new records until its missing metadata is
recovered. SQLite reclamation is a separate operation and never a guarantee about
filesystem snapshots or backup copies.

A bounded complete-archive scan resolves a closed capture by archive, writer,
observer and attempt, using caller-supplied historical decryption keys. It refuses
active captures, unknown capture framing, missing keys and exhausted bounds.
Observed recording gaps are disclosed. The current limits are 100,000 inspected
occurrences, 256 MiB signed-request scan bytes, 120 seconds, 4,096 selected objects,
1 MiB per signed erasure record, and 16 MiB / 1,024 records / 32,768 distinct objects
of erasure history. These are explicit capacity refusals, not incomplete success.

This is a storage primitive, not the complete owner workflow. Independently durable
history publication before acknowledgement, current-history service enrollment,
spool/replica/derived-workspace cleanup and publication fencing, owner job/API/CLI/UI
preview/apply/status, and managed restore activation gating remain required. Do not
present the low-level API as completed managed erasure. Qualification is pending
remote CI; local Library checks cover the erased source state and disabled export.

Derived read safeguards now recheck each cited occurrence's current erasure state
using verified metadata, without needing its plaintext or historical key. Notes
and analysis jobs with erased inputs return only minimal `erased-source` IDs;
annotation bodies, graph edges, result text and publication controls are withheld.
Those markers explicitly say coordinated physical cleanup is pending. Annotation
restoration, new previews, publication preparation and analysis result access also
refuse erased inputs. A worker rechecks inputs after inference and discards the
provider response if access or availability changed. Already dispatched provider
inputs cannot be recalled. These read/publication checks do not substitute for
workspace/outbox purge or fencing a publication already queued; those remain part
of the coordinated owner workflow. Whole-list metadata checks have a 20-second
bound and fail visibly rather than returning partial data as complete.

Remote all-target compilation passed at 3ad781e; the default test gate found three
surface-registration omissions (rule registration, independently enumerated values,
and mutation-facade digest). Those inventories are corrected with the existing
facade-call controls retained. Runtime storage/reader qualification is still pending.

Independent owner custody now has a separate append-only signed history, with an
explicit empty genesis and an owner key distinct from the storage issuer. Each
subsequent owner record authorizes one exact issuer-signed storage erasure plan.
Storage issuer attestations alone do not prove human authorization. The UI therefore
says “Payload erased”; the coordinated owner workflow must establish the stronger
claim. Custody is published before storage reconciliation: an interrupted transition
leaves enrolled reads and ingestion blocked, rather than serving stale content.

Both services can enroll using an owner-pinned history configuration. They hold a
shared custody lease throughout each operation and require exact agreement between
current owner-authorized and local storage history. Owner publication takes an
exclusive lease. Startup and ongoing requests refuse missing custody, lagging
restores or extra issuer-only erasures. A current owner checkpoint can reconcile an
older archive before it is enrolled. Genesis and history must live outside the
archive backup lifecycle; an independently retained minimum checkpoint detects
rollback below that checkpoint, but cannot detect rollback of both custody and
its pin together. This trusts the configured owner-controlled custody service/file
system as the current source; it is not a cryptographic freshness oracle.

Enrollment remains explicit for existing experimental configurations. Starting a
legacy service without `--erasure-history` does not acquire these managed restore
guarantees. The full owner coordinator must enroll every managed read/ingest/restore
path and keep custody current before it reports managed erasure complete. Coordinated
spool, outbox, workspace, replica and backup cleanup and owner job/UI still remain.

Workspace cleanup now has an exact bounded owner-side plan and atomic ciphertext
removal plus encrypted, signed per-entry tombstones. A plan may fence an absent
analysis output so a delayed completion cannot recreate it. It pins the workspace
identity, owner authorization record ID, selected kinds/IDs and existing ciphertext
digests. Stale previews fail atomically; exact retries scrub the same identities
again. Minimal tombstones contain plan/authorization IDs and entry coordinates,
never removed content. Reads and writes check them; recovery refuses reintroduced
payload rows. Ordinary workspace writes cannot mint erasure records.

This cleanup requires an exclusive maintenance handle with all workspace users
stopped. First erasure changes the workspace profile to 2; earlier binaries refuse
it, preventing an old writer from silently bypassing the new fences after restart.
The unchanged encrypted entry schema preserves tombstones through recovery. SQLite
secure deletion clears removed managed cells; page reclamation and old backup purge
remain separate. The plan is bounded to 4,096 selected keys and 64 MiB of inspected
ciphertexts. This is the physical cleanup primitive: the owner coordinator still
must resolve the complete capture/derivative/outbox/replica dependency set, bind its
independently signed authorization and reconcile old workspace backups before use.
