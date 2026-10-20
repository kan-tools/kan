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
workspace. Existing hot journals are refused until explicit recovery (owner recovery
workflow remains required). Back up the workspace and its key separately: deleting
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
