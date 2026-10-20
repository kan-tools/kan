# Evidence Library

The experimental Library serves real, authorized evidence inventory and exact
source ranges. It is the first browsing slice of Kan Studio. It is not yet the
complete frontend: persistent search, cross-archive session views, annotations, saved
views, analysis, administrative jobs and an integrated Operations area remain
required build items. No example or synthetic success is served by this app.

Build with `v2-crypto`. Give the reader a dedicated signing identity with only
`inventory: true, append: false` at each selected service. Keep it separate from
the storage-service signer, capture writers, the inference gateway, and admin
principals. Configure an existing scope decryption key explicitly; the Library
never creates or discovers keys. Location is portable; no production deployment
default is selected by this implementation.

## Proof archives, attempts and explicit sessions

A proof source config uses `"protocol": "kan-proof-reader/1"`, `"profile":
"admitted"` or `"copied"`, and an explicit `"archive"` (64 lowercase hex), in
addition to the scope, issuer and private-key fields below. Its endpoint ends
in `/v2/read`. The array may mix proof and legacy sources, up to 16 entries;
archives sharing a scope remain separate. The `serve-proof` service opens
metadata even when retained payloads are unavailable. Proof inventory displays
per-record missing/corrupt status; the legacy limitations below do not apply to
proof inventory.

Use **Discover attempts** for one page or **Scan this window** to continue up to
1,000 occurrence descriptions. **Stop scan** retains completed batches. At the
window boundary, another scan continues with older inventory and replaces the
previous window. Refreshing the snapshot, changing archives or locking clears
these in-memory descriptions. Finishing the inventory is not proof of complete
traffic capture; missing/corrupt evidence cannot be assigned to an attempt.

**Read attempt** reads all records of that attempt in the scanned window together,
including requests spread over more than 40 records. This rechecks current access
and retained source and refuses mixed writer/observer/attempt identities. Source
citations still refer to exact decrypted bytes. Long text and parsed bodies use
paged display; text pages are display positions, not source byte coordinates.
Incomplete streams and unknown terminal outcomes remain explicit. The existing
**Read Content** action still supports arbitrary selections up to 40 records.

Explicit session headers in recorded incoming request metadata produce a session
view with source-cited link claims and per-attempt reading. `x-kan-session` is a
64-character lowercase hex ID; optional `x-kan-parent-attempt` names a parent
attempt, and `x-kan-transition` is `continue`, `branch` or `compaction`. A session
without a parent has a `start` claim. An existing `x-claude-code-session-id` header
is supported separately as membership only: it makes no parent/order claim.
The two namespaces are not merged. Ambiguous/invalid or conflicting claims remain
visible. All grouping includes the configured archive, verified writer and
observer; matching text or timestamps never constructs session identity.

These headers are opt-in calling conventions, not a claim that every installed
harness emits them. Large fragmented HTTP metadata currently remains raw evidence
without session interpretation. Requests with no explicit links remain independent.
Session views cover the scanned window, not an unseen whole-archive index. Branches
and compaction preserve earlier source instead of rewriting history.

Proof API additions share the existing authenticated loopback presentation API:

| Action / endpoint | Bound |
|---|---|
| `proof-discover` at `/api/library` | 1–20 records; 8 MiB input; 20 seconds |
| `proof-content` at `/api/library/proof-content` | 40 selected records; 64 KiB request; 8 MiB input; 4 MiB output |
| `proof-attempt` at `/api/library/proof-attempt` | 1,024 selected records; 2 MiB request; 40 MiB input; 96 MiB output |

Selected Content has a 20-second deadline; attempts have 120 seconds and exclusively hold both
Content worker permits to bound aggregate memory. Limits fail visibly without
partial Content or changes to retained evidence. The connection and grant checks
below still apply. This is bounded in-memory reconstruction, not unlimited
streaming or a persistent plaintext index.

## Sessions across archives

Use **Scan authorized archives** to discover explicit session relationships across
configured proof sources. The scan visits archives in turn using their individual
pinned snapshots. Each archive reports its inspected count, current window and
whether its inventory end was reached. Stop preserves completed batches; continue
resumes their independent cursors. The window holds at most 1,000 records; a new
window discards previous descriptions while preserving continuation. Clear starts
again at those snapshots. Refresh snapshot or Retry sources clears session results.

Session groups require the same verified writer, observer, session-header scheme
and explicit session ID. Matching archive copies remain separate observations.
Parent links show every matching archive; **Read parent in …** opens the selected
archive's attempt, and **Link source …** opens the exact claim. Each read rechecks
current access. Lock clears the entire workspace. An absent parent means it was
not found in this window; a finished inventory never proves complete traffic.
These views do not persist an index or merge claims into authoritative identity.

## Chunked metadata and session links

Large captured HTTP headers can occupy several records and discovery pages. In
an attempt or the cross-archive workspace, choose **Resolve chunked session links**
after scanning the relevant window. Resolution rereads the selected attempt under
current access, reconstructs complete request metadata, and adds its explicit
session relationship with a source link for every fragment. Reading Content also
shows reconstructed metadata and exact source ranges.

Only complete, consistent documents yield links. Missing fragments, conflicting
ordinals or extents, malformed metadata and documents over the 2 MiB interpretation
limit show incomplete/invalid/limited states. Their raw records remain inspectable.
Duplicate occurrences retain all citations. This is an explicit window operation;
a missing link may mean that necessary fragments have not been scanned. Refresh,
window replacement and lock discard derived links along with their input window.

## Batched proof acquisition

Attempt Content and discovery negotiate optional `read-batch` support. A batch
selects at most eight records and returns an ordered prefix with at most 4 MiB of
retained signed-request bytes. One current full metadata audit covers the batch;
records, writer signatures, encryption bindings and fresh payloads are checked
individually. Every batch authorizes current access, and derived views perform a
final grant check. No audit result or plaintext is cached across requests.

New readers retain the single-read fallback for older proof services. Upgrade the
Library/reader before the service: older readers that insist on the original exact
capability list do not accept the added capability. The existing single-read wire
operation and snapshot/token formats are unchanged.

The saved synthetic 11 MiB / 179-record debug fixture read in 33.64 seconds with
batching, compared with 106.91 seconds before, with all 177 payload citations.
This is a development measurement, not a latency guarantee. Admission performance
and further read optimization remain necessary; this change does not remove
admission's repeated full payload audits.

## Legacy source configuration and behavior

Use an owner-only JSON file containing 1–16 distinct entries:

```json
[
  {
    "scope": "<64 lowercase hex characters>",
    "endpoint": "https://your-service.example/v1/rpc",
    "issuer": "did:key:<storage-service signer>",
    "private_key_file": "/absolute/path/to/existing-32-byte-recipient-key"
  }
]
```

The config, existing signer, raw 32-byte recipient keys and a distinct access
token file are owner-only. Remote endpoints require HTTPS; HTTP is accepted
only on literal loopback. The browser-facing listener requires literal loopback;
remote use goes through an authenticated tunnel.

```sh
kan-v2 library --config /absolute/path/reader.json \
  --signing-key /absolute/path/reader.identity \
  --token-file /absolute/path/reader.token \
  --listen 127.0.0.1:7284
```

Only the address is printed. Open that address and enter the reader access token.
The client stores tokens, pins and displayed content in tab memory only. System,
Light and Dark use the shared appearance controller; only that enumerated
preference is persisted. Lock or page exit clears the client state. This is not
a promise to scrub OS swap, browser internals or previously requested downloads.

The catalog queries current grants before exposing authorized scope pins. Switch
scopes to inspect each scope's own snapshot. Refresh snapshot explicitly to include
newer commits. Inventory pages list committed sequence, manifest and receipt
identities. Signature, service admission and trust in content are separate;
a signing key does not prove the speaker claimed inside captured bytes.

Source reads first recheck membership at the pinned snapshot, then verify the
signed retained request and manifest before scope-bound decryption. Unknown
formats remain inspectable. UTF-8 is shown only if the selected bytes decode
exactly; other ranges show hex. Offsets are half-open byte ranges. The first UI
reads 64 KiB at a time and does not accumulate previous ranges. Download exports
only that range as a `.bin` file after another authorization check, not the full
object or a transcript. No source HTML, external images or attachment scripts
are executed.

Every valid source/page/export read contacts the service before returning data,
so an effective remote grant revocation denies the next read. Malformed and
out-of-range requests can be refused locally without contacting it. To replace local reader keys, scope
selection or browser token, restart the explicitly configured reader; it has no
hidden config watcher or administrative mutation API. Service grant rollout
remains governed by that service's own restart/configuration contract.

Bounds: 40 inventory records per API page, 256 KiB per API source range, 16 KiB
request body, four executing browser connections plus eight queued connections,
a 6-second queue deadline, 5-second header deadline, 3-second body deadline and 150-second overall
connection deadline including queue time. Additional connections are refused;
this is bounded burst handling, not immunity to a hostile local process. A range currently decrypts one bounded
service object in memory. It is not streaming decryption. The current service can fail an entire inventory
page containing a missing or damaged object. Authorization errors lock the view;
other read failures clear the inspector and remain visibly unavailable, allowing
retry or selection of another scope. No failed page is presented as empty success.

Validation and review are recorded with the implementation checkpoint; do not
interpret this runbook as proof that uncompleted acceptance criteria passed.

## Unavailable evidence and safe display

Authorization failures lock and clear the Library. A missing response (404),
verification/server failure, or transport failure clears the source inspector
but keeps other already-authorized browsing controls available. An unavailable
page displays no rows or counts from its failed response. Refresh the snapshot
or select another scope to recover. This does not bypass verification or skip
unreadable rows silently.

The current storage Page RPC verifies referenced objects as it reads records.
A damaged or missing object can therefore make its containing page unavailable;
this first reader does not yet return per-occurrence unavailable-evidence rows.
The service reports absent retained bytes as corruption, so physical absence and
corruption are not independently distinguished by the Library. That remaining
backend contract is required for full browsing coverage.

Directional formatting controls default to hex, like control bytes. An explicit
UTF-8 toggle shows the exact original text; it does not sanitize or rewrite the
source. Byte ranges remain the unambiguous comparison/export representation.

The reader refuses a signing principal equal to any configured storage issuer.
A verified signed access-denial result omits the scope without identifying it.
Unreachable, malformed or unverifiable sources instead produce `coverage: partial`
alongside any successfully authorized scope pins. Failed scope identifiers,
endpoints and counts are not returned in the response body. Response timing can
reveal how many groups contain stalled checks; this profile does not hide timing.
Even if no scope succeeds, partial is
visibly distinct from a completed check with no currently authorized scopes.
The persistent coverage notice survives page/source navigation. **Retry sources**
clears old pins, rows and plaintext before rechecking grants; lock also clears
coverage. A failure while retrying leaves coverage unknown and retry available.

Each upstream signed read has a five-second deadline. Catalog checks run in
groups of at most four (sixteen configured scopes maximum): up to twenty seconds.
A source range requires two calls, up to ten seconds. Queue + header + body +
maximum catalog budget is thirty-four seconds inside the 150-second
connection limit. Scheduling/CPU overhead can still exhaust the whole deadline;
a slow healthy service is temporarily unavailable, never declared absent.
Cancellation drops the in-flight checks. Excess connections remain refused.
The visible capability matrix is populated from the authenticated API; unknown
capabilities are labeled client-unsupported, never presented as working controls.

## Persistent text search and saved views

The optional reader workspace stores encrypted, signed index pages and explicit
saved-view declarations outside code repositories. Provision a **dedicated**
32-byte recipient private key as an owner-only file, and select a private directory
(mode 0700) for the database. Supply both options when starting the Library:

```sh
kan-v2 library --config /absolute/path/reader.json \
  --signing-key /absolute/path/reader.identity \
  --token-file /absolute/path/reader.token \
  --workspace /absolute/path/private/reader-workspace.sqlite \
  --workspace-key /absolute/path/private/workspace.key
```

Use **Index & search** to search across current authorized proof archives or just
the selected archive. Each bounded window indexes and searches at most 25 pages
of eight occurrences. Stop preserves completed pages; Continue resumes pinned
coverage. Only 1,000 hits stay in a browser result window; continuing starts a new
window when full. Search is ASCII case-insensitive; other Unicode matches exactly.
The current projection searches headers and UTF-8 bodies separately, so binary
spans and phrases crossing capture chunks are explicitly excluded. Facets describe
the index at build time; matching source bytes and current access are rechecked
before returning snippets. Follow **Open exact source** to the original byte range.

Save a named view to retain the source snapshots, query, filters and trust framing.
The same declaration is idempotent; a changed declaration preserves the old view.
Load saved views after restart, then **Run pinned view** to reuse those snapshots.
A view is shown only while every source is authorized. New capture is excluded
until you explicitly search a newer snapshot. Captured text remains untrusted.

CLI callers can execute the same JSON API request from a private file, without
starting an HTTP server or supplying a UI token:

```sh
kan-v2 library --config /absolute/path/reader.json \
  --signing-key /absolute/path/reader.identity \
  --workspace /absolute/path/private/reader-workspace.sqlite \
  --workspace-key /absolute/path/private/workspace.key \
  --request /absolute/path/private/library-request.json
```

Requests are `catalog`, `index-page` (`target: {source, pin}`, `cursor`),
`search-page` (same fields plus `filter: {text, writer, kind}`), `save-view`
(`name`, `targets`, `filter`) and `views`. Use catalog/source identifiers and pins
verbatim. Null writer/kind mean no corresponding filter. CLI request files currently
have the private-file reader's 64 KiB bound; HTTP requests allow 256 KiB.

Back up this database and its recipient key separately. Index pages are disposable,
but deleting the workspace also removes saved views. Nothing expires automatically.
The database has a 256 MiB capacity bound and supports 200 view declarations; a
full workspace reports failure instead of deleting history. Keep old workspaces
when moving to a new one. Hot journals are refused at startup pending explicit
owner recovery; do not delete them to force startup. Source erasure must include
affected derived workspaces in the owner erasure plan.

## Notes, tags and correction history

With an encrypted workspace configured, open a proof occurrence and choose
**Annotate**. Enter a subject, note and comma-separated tags, then **Preview
annotation** to inspect the signing author, evidence citations and their current
availability. **Append annotation** rechecks the preview and appends a signed,
encrypted declaration. It does not change the captured bytes. Editing or cancelling
the form invalidates the preview. The configured reader identity signs these notes;
a claimed human name inside the text is not another authenticated author.

**Load annotations** supports exact subject and tag filters. Inspect cited evidence
or append a correction from any entry. Corrections preserve earlier entries and
inherit their evidence citations. Notes whose cited scopes are no longer authorized
are hidden; missing payloads retain explicitly unavailable evidence references.
The workspace supports 1,000 annotations with no automatic expiry. Include the
workspace in backups to retain this authored history.

The shared requests are `annotation-preview` with a `draft`, `annotation-save` with
the checked `draft` and its `preview` digest, and `annotations` with optional
`subject` and `tag`. A draft contains `subject`, `text`, `tags`, `cites` and nullable
`supersedes`. Each citation contains an exact `source`, `pin` and `selection` from
the proof reader. Saving the same declaration again returns the original entry.
`recorded_at` is the reader server's observation time, not a source event timestamp.

## Writing captures into a proof archive

An existing profile-2 archive can now receive the same signed, encrypted append
requests used by the durable spool. Select it explicitly with the same admitted
binding file used by the proof reader:

```sh
kan-v2 serve-admitted /absolute/path/archive \
  --binding /absolute/path/admitted-binding.json \
  --signing-key /absolute/path/archive-owner.identity \
  --grants /absolute/path/ingest-grants.json \
  --listen 127.0.0.1:7282
```

Point the existing queue drainer at `http://127.0.0.1:7282/v1/rpc`. The wire
request and signed durable commit reply remain compatible with queued requests;
each admitted record also gains an atomic issuer attestation in the archive.
Exact retries return the original committed record. Wrong principals, scope,
audience or append permissions are refused before storage mutation. Reads remain
on `serve-proof` at `/v2/read`, with separately configured inventory grants.
This command opens only an existing explicitly selected admitted archive; it does
not convert a legacy archive, initialize one implicitly or enable network exposure
beyond loopback. Use the existing authenticated transport/tunnel arrangement for
remote access. Grant changes currently require owner restart/reconfiguration.

## Operations in the same application

To mount the existing operations console under `/operations/`, add
`--operations-journal /absolute/path/operations.sqlite` (or a preserved-generation
collection directory) and `--operations-token-file /absolute/path/operations.token`
to `kan-v2 library`. The Library navigation then exposes **Operations**. Its
separate credential is required on operations APIs; a Library token does not gain
operations access, and the operations token does not gain evidence access.
History/overview refresh and cancellation use the existing operations manager.
Both surfaces share the light/dark/system appearance setting. This mount exposes
operational observations only; owner mutation jobs remain a separate capability
and are not implied by either read token.

## Publish annotations to the encrypted ledger

Create a dedicated spool with the existing `spool-init` command, using the Library
signing identity as writer and the chosen destination scope/issuer. Give this writer
append permission at the destination service. Configure an owner-only JSON file:

```json
{
  "spool": "/absolute/path/private/annotation-spool.sqlite",
  "endpoint": "http://127.0.0.1:7282/v1/rpc",
  "recipient": "<64 lowercase hex characters for the destination public key>"
}
```

Add `--annotation-outbox /absolute/path/private/annotation-outbox.json` alongside
the workspace options. No declaration publishes automatically. In its annotation
entry, choose **Check ledger publication**, inspect the fixed scope, issuer and
recipient, then **Queue encrypted annotation**. **Deliver one queued record**
advances this dedicated queue; it may deliver an earlier pending annotation first.
Use the existing independent spool drainer for continuous delivery. Acknowledged
means the signed durable commit reply was accepted, not independent backup or
complete capture. Restart/retry keeps original queued bytes. Changing the spool's
binding invalidates the configured destination instead of silently redirecting it.

API equivalents: `annotation-delivery` (`id`), `annotation-queue` (`id`,
`destination`, the returned confirmation digest), and `annotation-drain`
(`destination`). The server chooses all filesystem paths and network destinations
from operator configuration. Published records use `kan-annotation/1` encrypted
plaintext frames and preserve the authored declaration and all citations. Keep the
workspace backup as well: automatic rebuilding from published annotations and
cross-reader citation resolution are not implemented yet.

After scanning authorized archives, use **Read conversation** on an explicit
session group. Responses and tool activity appear beside gaps and membership
claims; expand supplied request history when needed. Original archive copies
remain separate. Citation buttons reopen the exact archive and snapshot. Each
window covers at most eight selected attempts and 1024 occurrences; the next
window is an explicit action. Complete traffic capture and chronological order
are not inferred from session headers.

The same workflow is available through `--request`: `proof-session` accepts an
`identity` (`writer`, `observer`, `scheme`, `session`), `attempts` (each with
`source`, `pin`, `selections`) and the same `format` as `proof-attempt`. HTTP uses
`POST /api/library/proof-session` with the reader bearer credential. Current
revocation denies the entire response; a missing payload remains an unavailable
observation in its original attempt.

## Background extraction and day assessment

`--analysis-config PRIVATE_JSON` enables analysis alongside the encrypted reader
workspace. The file selects a fixed loopback inference gateway, model, source
allowlist, versioned recipes and quotas. Its token is never returned to the
browser. Example (replace every illustrative value before use):

```json
{
  "endpoint": "http://127.0.0.1:7285/v1/messages",
  "token": "your-private-collector-token-at-least-32-bytes",
  "model": "your-configured-provider-model",
  "sources": ["exact-proof-source-id-from-catalog"],
  "recipes": [{
    "id": "day-assess", "revision": "1", "purpose": "day-assessment",
    "instructions": "Assess the selected telos, atom, bridge and execution evidence. Cite input numbers. Separate observed progress, uncertainty, tensions and suggested next work."
  }],
  "max_input_bytes": 131072,
  "max_output_tokens": 2048,
  "max_jobs": 100
}
```

Supported purposes are `segment`, `extract`, `summarize`, and `day-assessment`.
This uses the configured collector/gateway's Anthropic Messages interface. It
never chooses a provider, buys credits or obtains production credentials.

Inspect a source and choose **Analyze**. Preview shows the exact recipe revision,
model, destination and input budget. **Start background job** submits it; **Refresh
jobs** reconnects to persisted status. Inspect a job to read derived output and
its exact input/request/response lineage. Results never publish claims or execute
tools. Cancel records intent before stopping the worker; a request already sent
to the provider may still be billed. Retry previews a new linked job using fresh
source checks. The same preview/nonce submission is idempotent and does not resend.

The shared actions are `analysis-preview`, `analysis-submit`, `analysis-jobs` and
`analysis-job` (with optional `cancel: true`). A submission repeats its draft,
preview digest and nonce. Use `wait: true` in one-shot `library --request` calls so
the runtime stays alive until the worker stops; the server UI uses `wait: false`.
An interrupted process leaves an interrupted job; restart does not silently
resend it. At most one scheduler owns a workspace, and one job runs at a time.
The lifetime job quota requires an explicit configuration increase; stored records
have no automatic expiry. Current source revocation hides jobs and their results.

To schedule from annotation tags, add an optional `triggers` array to the private
analysis configuration, for example:

```json
"triggers": [{"tag": "assess-day", "recipe": "day-assess"}]
```

The annotation preview shows every matching recipe revision and destination.
Append records the annotation and queues matching analyses. **Inspect tag-triggered
jobs** exposes scheduling receipts and **Retry failed scheduling** retries the
same declared plan. Quota, missing input or permission failures remain visible;
repeating an accepted trigger does not create another inference request. A changed
configuration requires a new reviewed annotation, rather than silently changing
the old trigger intent. The bounded queue holds up to sixteen jobs, with one
inference request active. Inputs are reread immediately before dispatch, so queued
work cannot send a cached copy after source loss or revocation.

**Draft annotation from this result** opens an editable human annotation. The job
reference and all its source citations follow it into the preview and any later
corrections. The full result stays inspectable if a draft is excerpted to the note
length limit. Merely inspecting a model response does not publish it.

## Subjects, relations and day

**Browse subjects & relations** lists visible authored subjects and their retained
history. Select **Day** to focus on teloi, atoms, bridges and threads. Following a
relation shows its target's available history; absent or unauthorized declarations
are not invented. Relation assertions retain their author and correction links.
`SameAs` is shown as an assertion and does not silently merge subjects.

Add relations in an annotation draft with the relation selector and target subject.
They appear in the preview before append. Corrections retain prior declarations
in the history. Process declarations in fenced `day-atom`, `day-bridge` or
`day-telos` JSON blocks are inspectable as data; they are never executed by the
browser. **Assess cited evidence** selects original citations for a recipe preview.

The shared `knowledge-graph` action accepts optional `subject` and `day` fields;
its result includes authorized subjects, relation assertions, selected declaration
history and coverage. Imported v1 claims are not counted as authored v2 annotations.

## Owner maintenance

`library --owner-config PRIVATE_JSON` mounts `/api/owner` with an independent owner
credential and encrypted job journal. Reader and owner tokens must differ. Use a
separate owner signing identity and a separate workspace recipient key. Example:

```json
{
  "journal": "/private/kan-owner/jobs.sqlite",
  "signing_key": "/private/kan-owner/signing.key",
  "recipient_key": "/private/kan-owner/workspace.x25519",
  "authority": {
    "token": "independent-private-owner-token-at-least-32-bytes",
    "max_jobs": 100,
    "targets": [{
      "kind": "archive", "id": "personal-ledger",
      "root": "/private/kan/archive",
      "output": "/private/kan/backups",
      "binding": {
        "profile": "admitted", "archive": "OWNER_ARCHIVE_HEX",
        "scope": "OWNER_SCOPE_HEX", "issuer": "OWNER_ISSUER_DID"
      }
    }, {
      "kind": "operations", "id": "capture-health",
      "collection": "/private/kan/operations"
    }]
  }
}
```

Replace all illustrative values and provision private directories/keys first.
`binding: null` explicitly selects a legacy archive; `profile: copied` selects a
copied proof archive. Profiles are never inferred from a database's contents.

Open owner controls with the separate token, select a configured target and
preview `backup`, `recover`, or `rotate`. The preview shows paths, profile,
effects and the new nonce-named destination. Run requires its exact digest.
Backup/recovery preserves the source and any failed output; no service switches
to the result. Rotation preserves sealed history and refuses live-writer
contention. Once a job starts, it reaches its existing safe boundary: closing the
browser does not cancel or roll back writes. Refresh or reconnect to inspect the
persisted result. Restart labels a job without a terminal result interrupted.

Repeated submission of the same preview returns the original job without another
write. **Preview new attempt** links a new job and new destination while retaining
the prior outcome. One owner job runs at a time. These are local verified copies;
`independent_backup: false` remains explicit until a separate-host drill proves it.

The same typed API is available through `kan-v2 owner --config PRIVATE_JSON
--request PRIVATE_REQUEST_JSON`. Actions are `catalog`, `preview`, `submit` and
`job`. For one-shot execution, submit with `wait: true`. Browser requests select
configured IDs and operations; they cannot supply filesystem paths or commands.

This maintenance API currently covers backup, derived recovery and operations
rotation. Import/cutover, live access changes, key lifecycle, erasure and hot
workspace-journal recovery remain separate implementation work.

### Imported v1 snapshots

Discovery recognizes `KANI/1` frames and groups them by verified writer and plan.
“Browse imported files and claims” reconstructs the selected inventory, checks its
plan commitment, scope, writer and recipient, and verifies each selected frame's
original operation and audience. File reads require every committed part and the
whole-file hash. Missing parts remain visible; originals are never opened or
rewritten. The same action is available through `library --request` as
`proof-import` (`source`, `pin`, `selections`, `plan`, optional `file`, `after`).
HTTP uses `/api/library/proof-import` with the reader credential.

CAR browsing reuses the migration framing/hash scanner and displays supported
individually signed claims, including released v1 records, with exact imported
frame byte ranges. Claim citations and attribution remain in the displayed data.
Structural, unsupported and unverifiable blocks remain labeled. Block signatures
alone do not establish repository membership or a trustworthy folded state;
`did:kan` claims requiring external identity history remain uninterpreted here.
An owner can create a separate v2 annotation citing an imported claim's evidence.

Presentation is bounded to 1,024 selected frames / 40 MiB, 100 blocks per page,
4 MiB of rendered records, and 1 MiB per interpreted claim. These are read-window
limits, not storage or migration limits. Exact retained Source remains available.
The last grant check runs after reconstruction, and lock clears the derived view.

### Owner migration and import recovery

The owner configuration also accepts fixed `migration` targets. A target contains
`id`, absolute `source` and `spool` paths, `selection` (`store`, `workspace` or
`identity`), a 32-byte hexadecimal `source_id`, hexadecimal public `recipient`,
and `batch` (1–1024 operations). Its spool writer must match the owner journal's
signing identity. Existing `import-plan` can inspect a source before configuring
it. The owner API/CLI/browser uses the `import` operation: preview hashes the
selected source inventory and shows the route, file/operation counts and notices;
submit checks that exact plan again before queueing. It never sends the queue or
changes originals. A new linked attempt queues the next batch; an exact retry
returns the original job even if the source has since changed. Queue coverage is
separate from remote delivery and recovery verification. Use the existing shared
spool worker to deliver queued operations.

An `import-recovery` target contains `id`, absolute `database`, `output`, and
`recipient_key` paths, `plan`, hexadecimal `scope`, `writer`, `max_records`
(1–1,000,000), and an optional explicit proof `binding`. The `restore-import`
operation previews a new directory under `output` and the plaintext side effect.
It reconstructs and verifies every selected file, preserves originals/failed
outputs, and writes the complete per-operation provenance to `report.json`.
The encrypted job receipt links this report and records success or interruption.
No output is activated and no independent-backup claim is made.

Offline `kan-v2 restore-import` now accepts the same `--proof-archive`,
`--proof-scope`, `--proof-issuer`, and optional `--copy-profile` pins as other owner
commands. Without them it continues to require the legacy archive profile. A
proof restore audits the issuer-bound metadata chain and reads source bytes from
that same pinned transaction. It verifies imported file bytes; repository graph
reachability, identity migration and final cutover remain separate checks.

Search filters include verified writer, capture observer, exact attempt ID,
evidence kind, and inclusive issuer-attestation time bounds. The API names the
latter `attested_from` / `attested_to` as canonical unsigned millisecond strings;
the browser converts local date/time inputs. These are distinct from observer
clock claims inside captures. Saved views retain the complete filter.

The encrypted `raw-text/3` projection also indexes up to 2,048 string values from
each complete JSON span (bounded to 8,192 visited JSON values). Escaped string
matches are marked `json-string` / `coarse` and cite the enclosing original span,
not an invented exact substring. Current source is re-read before returning a hit.
The raw page index explicitly reports its chunk boundary limitation. The browser
then reconstructs discovered capture attempts after each selected archive scan
finishes, in windows of four attempts and up to 1,024 retained members per archive.
`search-attempt` accepts a pinned target, explicit selections and the same filter;
it searches supported message text across capture chunks under fresh source access.
Request JSON and response JSON/SSE use the existing bounded interpreters. Every hit
links all enclosing source byte ranges; incomplete streams remain visible. Distinct
messages and SSE delta items are not concatenated. The result is bounded to 128
matches and 8,192 citations, and a limit refusal remains retryable rather than
claiming no matches. This reconstruction is disposable and is not stored as another
authoritative transcript. Older projection pages remain
retained and are not treated as the new interpretation.

A migration target may additionally configure an absolute `recovered` directory.
This enables `reconcile-import` in the owner API/CLI/browser. It checks the exact
retained plan document, independently hashes every recovered selected file,
rechecks the current source inventory, and reports queue acknowledgment progress.
It never trusts `report.json` as evidence of success and never modifies originals
or the recovery copy. Changed files, mismatched plans and unsafe paths refuse.

The standalone CLI is `kan-v2 reconcile-import SOURCE --spool ... --source-id ...
--recipient ... --selection store --recovered RECOVERY_DIRECTORY`. Reconciliation
reports writer fencing, native semantic/identity validation, independent backup
and key recovery, and explicit activation as separate outstanding conditions.
A matching copy alone never makes `ready_for_cutover` true. The owner UI displays
batch progress, verified file counts, output locations and those preconditions.

Leave search text empty to browse by facets alone. These rows are labeled metadata
filter matches and do not claim an exact text match. Import framing headers and
UTF-8 inventory bodies are indexed separately from binary CAR bodies.

### Recover an interrupted reader or owner workspace

Stop all processes using the workspace, including older versions. Keep its database,
`-journal` and keys together. The recovery command writes a new file, replays SQLite
rollback there and authenticates every retained encrypted record:

```sh
kan-v2 recover-workspace /private/kan/reader.sqlite /private/kan/recovered.sqlite \
  --signing-key /private/keys/reader.signing \
  --recipient-key /private/keys/reader.recipient
```

The original database and journal remain unchanged. Failed copies are retained.
A successful report lists authenticated entry counts and source hashes, without
activating the result or claiming an independent backup. Compare your retained
checkpoint and expected history before selecting the new path. WAL, malformed
journals, super-journal pointers, wrong keys and corrupt signed entries are refused.
Current clients hold shared maintenance locks; recovery requires exclusive access.

For the browser, configure a separate functioning owner journal with a fixed target:

```json
{"kind":"workspace-recovery","id":"reader-history",
 "database":"/private/kan/reader.sqlite","output":"/private/kan/recovery",
 "signing_key":"/private/keys/reader.signing",
 "recipient_key":"/private/keys/reader.recipient"}
```

The owner console previews and runs `recover` into a new nonce-named output. If the
owner journal itself cannot open, use the CLI recovery path first. No key is sent
to the browser. The output directory must already exist with owner-only permissions.

### Portable references and restoring published annotations

Source inspection exposes a portable reference containing the archive binding,
sequence, manifest, attestation and receipt. It contains no decryption key or
read grant. Paste its JSON into **Open an evidence reference** to resolve it with
the current reader's fresh snapshot. The shared `resolve-reference` API verifies
current archive membership and grants, then returns current reader selections.
Missing payloads retain their reference and provenance. Wrong identities or
receipts refuse resolution; possession of a reference does not grant access.

A retained `kan-annotation/1` source offers **Restore published annotation**.
The shared `restore-annotation` API takes a reference; without `preview` it returns
a digest-bound plan, and with that digest it installs the verified declaration in
the encrypted workspace. It preserves the original author, ID, timestamp, draft,
correction/analysis references and publication origin. The retained request writer
must match the declared author and the original declaration digest must match.
Exact retries reuse the original record. Restoration does not schedule analysis
or republish. A different reader may restore an authorized annotation, but cannot
publish it as though they were its original author.

Restored annotations are disclosed only with current access to both their
publication archive and every cited archive. `citation-source` resolves a signed
citation under the current reader; the service proves current membership and
access independently of the original reader. Original citation data remains in
the annotation. Missing correction parents and analysis jobs stay unresolved until
separately recovered. This restores selected publications; it does not certify
that all annotations were published or all local history has been recovered.

Imported `repo.car` files now show membership under the exact saved sibling
`HEAD`, with separate commit-signature and claim-signature results. A missing,
invalid or incomplete HEAD/tree keeps membership unknown; historical CAR roots
are never substituted. Exact HEAD and claim source links remain available.

In the repository panel, select the authors to include and choose **Apply
repository trust view**. This runs Kan's native v1 fold, showing subjects,
correction/retraction effects, identity witnesses and settled/confirmed/contested
status. The initial view includes no authors; it reports claims excluded by that
choice. Agent-qualified identities stay distinct. **Inspect claim** opens the
original block and its byte citations. **Next repository subjects** continues
large results. The equivalent Library/CLI request adds
`"view":{"trust":[{"did":"did:key:…","agent":null}],"subjects_after":0}` to
`proof-import`. This interpretation does not change grants, source records or
repository ownership. Unsupported/current identity-governed records remain
outside this legacy fold with explicit coverage; bounds and missing inputs are
shown rather than converted into an empty authoritative result.

For live owner-controlled access, provision an empty private policy directory and
an access config containing `directory`, the exact proof `binding`, `owner` DID,
and optional `minimum` signed policy digest. Run
`kan-v2 init-access-policy /absolute/access.json`. Add an owner target shaped as
`{"kind":"access-policy","id":"archive-access","policy":{…},"signing_key":"/absolute/owner.key"}`.
The signing key must match the configured policy owner; proof services need only
the public owner DID and read access to the policy journal, never that signing key.

Choose that target in Owner maintenance and **Inspect access policy**. Add/remove
principals and independently select append and inventory permissions; preview
and apply the complete replacement set. No principal has either capability until
the first policy is applied. Start `serve-admitted` and `serve-proof` with
`--access-policy /absolute/access.json` in place of `--grants`. Each request checks
the current signed policy. Failed reads or corrupt policy do not fall back to old
grants. Static `--grants` mode remains available with its restart-only semantics.

The shared `kan-v2 owner --config … --request …` commands are `access` (target,
optional history offset `after`), `preview-access` (target and full `grants`), and
`apply-access` (target, exact preview `change`, and digest as `preview`). Stale
previews conflict. Exact applied requests remain idempotent after later changes.
Policy history is append-only; the current view and paged history survive restart.

Policy metadata is signed plaintext in the private instance directory. It grants
no decryption, forwarding or owner powers. Back up the complete policy directory
alongside the archive and retain the current digest independently; configure that
digest as `minimum` when restoring to detect rollback before the checkpoint.
Without an external checkpoint, signatures cannot detect replacement of the whole
journal with a valid older prefix. Revocation does not recall previously copied
plaintext or keys. Current bounds are 256 principals per policy, 1,024 changes and
16 MiB total history; capacity fails explicitly and never deletes earlier policy.
Pending files from interrupted writes are not policy authority and are retained
for owner inspection. Key rotation and payload erasure remain separate operations.


### Encryption epoch rotation and wrapped key recovery

A `key-history` owner target manages a separate signed, append-only key directory.
Provision an existing absolute directory with mode 0700 and an independent,
32-byte recovery credential file with mode 0600. Pin its public recipient in an
access configuration:

```json
{
  "directory": "/absolute/instance/keys",
  "binding": {"profile":"admitted","archive":"<64 hex>","scope":"<64 hex>","issuer":"<storage did:key>"},
  "owner": "<owner signing did:key>",
  "recovery_recipient": "<64 hex public X25519 recipient>",
  "minimum": null
}
```

Initialize it with `kan-v2 init-key-history /absolute/keys.json`. Add an owner
target containing `kind: "key-history"`, `id`, `history` (the object above),
`signing_key` and `recovery_key` (absolute existing private files). In Owner
maintenance, inspect the history, preview a new epoch, then activate that exact
preview. Prior epochs and all evidence remain retained. The API/owner CLI actions
are `keys`, `preview-key-rotation`, `apply-key-rotation` (`change` and `preview`),
`export-keys`, and `restore-keys` (`package`, `preview: null` to preview, then its
digest to apply). All name the configured `target`.

Add `--key-history /absolute/keys.json` to an existing collector/gateway command
to select the latest signed recipient at each new attempt. Its fixed `--recipient`
remains the compatibility setting and is not a fallback if the configured history
fails. An unreadable history produces a visible recording gap while inference
continues. Existing attempts and queued ciphertext retain their original epoch.

Proof Library scope entries may add `epoch_keys` containing `history` and
`recovery_key`. The reader reloads the verified key history when reading and
checks current inventory grants independently. Existing `private_key_file`
remains the original compatibility credential; `historical_key_files` optionally
lists up to 64 additional absolute existing recipient key files. Neither list
changes read authorization. Missing matching keys show `key-unavailable` while
the attested occurrence remains browsable. Imports validate their own actual
recipient; selecting a newer epoch does not change the imported plan.

Export the wrapped recovery package after rotation and keep it independently
from the recovery private credential. The browser can display/download this
wrapped JSON; no unwrapped private key is returned. For a clean-host restore,
initialize a new private key directory, configure a separate owner target with
the same binding/owner/recovery recipient, paste the package and preview/restore.
An identical partial prefix can resume; a divergent history is refused. A
separately retained `minimum` record digest detects truncated histories. No
reader or capture routing is activated automatically.

The format retains at most 64 epochs / 128 KiB of signed history and reports
capacity rather than deleting keys. Rotation cannot recall already distributed
keys or plaintext. Archive ciphertext, policy history, encrypted workspaces and
independent credentials must also be backed up; this package alone is not an
instance backup. Delegated per-reader wrapping, recovery-credential replacement
and payload erasure remain distinct lifecycle work.


### Current claims in imported repositories

Open a retained public control `.cbor` file and choose **Use this control evidence**.
The selection survives browsing other imported files, so identity histories and
scope inception can come from independently imported public stores. Open the
repository CAR, choose **Current principals included in this view**, then apply.
The current-claim section shows native identity/governance resolutions, the four
separate claim judgments, status conflicts, witnesses and exact source links.
Legacy author/agent trust remains a separate selector. Clear control evidence or
lock the Library to discard this in-memory selection.

The `proof-import` request's `view` optionally includes `principals`,
`current_after`, and `controls: [{"parts":[{"source":…, "pin":…, "selection":…}]}]`.
Each control is one raw retained canonical control event or all ordered data-frame
parts of one imported control file. The API verifies the selected sources again;
it never accepts a browser-supplied resolved identity or admission verdict.
Limits are 128 control records, four parts / 256 KiB each and 4 MiB total, alongside
the existing repository/presentation bounds. Missing/unreadable selected controls
refuse the view; omit them to inspect the resulting unresolved authority state.

These are conclusions relative to selected control history. A missing later
revocation cannot be discovered from absent evidence; there is no implicit claim
of globally current authority. The native verifier's unsupported identity or
control versions remain explicitly unresolved, with raw source access preserved.
