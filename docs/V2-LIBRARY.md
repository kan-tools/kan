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
