# Feature: Authorized evidence Library vertical slice

## Summary
Implement the first real browsing area from `.design/kan-v2-human-frontend.md`:
read an explicitly authorized, snapshot-pinned evidence inventory and inspect its
retained source and provenance. Serve the technical-studio shell with the shared
System/Light/Dark controller. This serves `telos/raw-data-and-projections` and
must never treat the current synthetic Studio as an integrated application.

## Requirements
- REQ-1: Run the reader as an explicitly configured principal separate from blind storage, inference gateway, operations, administration and annotation signing. Deployable location is not hard-coded; no production key placement is inferred.
- REQ-2: Validate signed storage replies and scope membership before returning inventory, counts, snippets or source bytes. An unknown, revoked or unauthorized scope has one indistinguishable denial shape. Filter before derived counts or facets.
- REQ-3: Pin inventory to a signed evidence snapshot and selected scopes. Bound rows, bytes, requests and concurrency; return explicit continuation and coverage rather than an unbounded scan. Cursors bind selection, snapshot and version.
- REQ-4: Show retained occurrence identity, observer, claimed speaker, admission and cryptographic verification separately. Source bytes have explicit encoding, byte ranges and retained identity; an unsupported semantic format remains inspectable.
- REQ-5: Keep decrypted material in bounded reader memory for this first slice. No plaintext index, temporary file, log, URL or browser storage is created. An explicit user-triggered byte-range download creates the requested local export and rechecks authorization. Index-backed search remains an explicit unavailable capability until encrypted projections and their grant invalidation are implemented.
- REQ-6: Production Library navigation and inspector use real typed endpoints. Lock aborts/invalidates in-flight reads, clears DOM and client caches. Captured content is text, never executable HTML or active attachments. Responses are no-store and cross-origin use is denied.
- REQ-7: Expose an implementation matrix distinguishing inventory/source inspection from later transcript normalization, annotation writes, saved views, analysis and admin jobs. Missing capability is visible; no synthetic success state appears in production.

## Acceptance Criteria
- [ ] AC-1: Browse two synthetic authorized scopes at a pinned snapshot with pagination and stable return-to-list state. A third unauthorized scope changes neither counts nor snippets; test unknown and revoked scopes at the same API boundary. (REQ-1, REQ-2, REQ-3)
- [ ] AC-2: Tampered reply signatures, mismatched snapshots, malformed cursors and cross-scope object IDs fail closed before source disclosure. Limits hold under hostile page sizes, many requests and large ciphertext. (REQ-2, REQ-3)
- [ ] AC-3: Inspect retained source with byte-exact export/range comparison and separate provenance judgments. Unknown semantic payload and missing object remain distinct authorized states, not silent omissions. (REQ-4)
- [ ] AC-4: A captured script, external image and instruction to schedule work execute nothing and produce no external request. Reader credentials cannot rotate, annotate, decrypt a different scope or access administrative routes. (REQ-1, REQ-5, REQ-6)
- [ ] AC-5: Lock during pagination/source retrieval leaves no plaintext in DOM or caches after late responses. No key/token/content persists in browser storage; only the shared enumerated theme preference does. Revoke access and verify the next source/page/export read is denied. (REQ-2, REQ-5, REQ-6)
- [ ] AC-6: Real-browser desktop/tablet/phone tests cover inventory, pagination, inspector, source/provenance tabs, locked, empty, denied, stale and failed states. Fresh Opus 5.5 review identifies exact implemented commits; the full-frontend matrix remains partial. (REQ-6, REQ-7)

## Architecture
The existing `evidence_service::{SignedRequest,SignedReply,Command,Output}`
contracts supply signed Snapshot/Page/Read requests. Read returns the exact retained signed append request and its committed record view; there is no separate Record/Object RPC in the current implementation. Compose these
through a bounded reader adapter; do not give the browser an archive-wide token
or silently mount a whole ledger. The `evidence_crypto` primitives implement
scope-bound ciphertext opening; they do not supply reader authorization.
Authorization must precede object opening and any derived response.

The first API contract is inventory/source/provenance, not semantic search. A
reader session selects from its configured grants and pins a snapshot. A typed
cursor carries snapshot and scope selection plus continuation state and is
validated on every request. No opaque client-provided cursor grants a new scope.
Durable capture/resource identifiers must follow RFC 2's extension rules; UI
fragment routes are navigation state, not invented canonical evidence URIs.

The app shell shares the approved Studio typography, master/detail layout and
appearance controller. The evidence inspector has source/provenance states and
explicit unavailable representations. The existing operations endpoint retains
its separate capability. Later admin plans/jobs and annotation signing must have
separate authorizations even if presented in the same application shell.

A plaintext index is unnecessary for bounded inventory. Implementing encrypted
search projections later requires a separate persisted-surface design covering
WAL, temporary files, backups, replay/frontier and revocation. Full cross-project
search, normalized transcripts, annotations, views, analysis and admin workflows
remain required by the parent design; this slice does not close those criteria.

## Open Questions
The previously asked deployment-location question remains unanswered. Portable
configuration and synthetic fixture tests can proceed independently; installation,
production keys and a home-server/local default must wait for that decision.

## Out of Scope
Live installation, production archive access, real keys, provider traffic, public
network exposure, automatic indexing of the user's existing archive, or declaring
the full frontend complete after this initial read-only slice.

## Process record
Initial implementation and author verification are recorded below. Independent review is pending; composite acceptance criteria remain unchecked where browser or operational qualification is incomplete.
Legacy kan/day claim backfill remains subject to the recorded partial-trust
limitation; this document does not fabricate witnesses or evidence claims.

## Concrete adapter boundaries (code inspection)
The current service is one scope per endpoint, with `inventory` permission
covering Snapshot, Page and Read. A reader composes explicitly configured scope
endpoints under a separate signing principal; the browser receives neither
that signer nor scope decryption keys. A signed Read reply authenticates the
service's record view. The retained append signature and recomputed manifest
must also agree before decrypting. Those checks remain separate from a writer's
claimed speaker and from trust in the captured content.

A source read must first prove membership at the selected snapshot using Page
at sequence minus one, then match the returned Read record exactly. Merely
checking sequence <= snapshot through is insufficient when a snapshot tip is
wrong. Remote authorization must be exercised for every page/source/export
request, so revocation cannot be bypassed with a cached plaintext object.

Initial inventory has committed occurrence metadata only; snippets require
bounded authenticated source reads. Do not claim server-side semantic search,
facets, session normalization or complete corpus inspection from that inventory.
The current evidence HTTP client already verifies signed reply/request binding,
refuses redirects/proxies and bounds replies. The new adapter must additionally
validate response shape, page continuity, source commitment, selected scopes,
byte ranges, total work and client cancellation.

## First Library implementation scope
The first client switches between up to 16 explicitly configured scopes. Each
scope has its own authenticated snapshot and page position; this is not a merged
cross-scope result set or semantic search. Pins carry the original signed
Snapshot request/reply. Page continuation is a bounded offset under that pin;
clients may choose a different offset, but cannot change scope/frontier proof.

Inventory pages contain at most 40 records (UI requests 20). Source responses
contain at most 256 KiB (UI requests 64 KiB), with exact hex bytes, optional UTF-8,
range offsets and total size. Each range currently decrypts one service-bounded
object in memory; it is not streaming whole-object decryption. The HTTP adapter
allows four executing connections and eight bounded queued connections, limits
request bodies to 16 KiB, and has queue, header and overall deadlines. No plaintext index or automatic file write exists.
Export is explicitly triggered and downloads only the current range after fresh
membership/authorization checks. A .bin download never executes source HTML.

The browser displays manifest/receipt identifiers and separate writer signature,
service admission and content-trust descriptions. No claimed speaker is inferred
from a writer key. Unknown semantic payloads remain source bytes. Session
normalization, annotations, stable evidence URI extensions, saved views, analysis,
admin jobs and integration of the separate Operations service remain subsequent
required work. The live UI visibly lists those unavailable capabilities.

## Author verification checkpoint — 2026-10-18

Implemented the real read-only Library, its separate signed reader adapter and
loopback presentation command. Author verification passes eight reader/API
integration tests, one real CLI end-to-end test, 19 surface conformance tests,
29 Node UI/theme/operations tests, strict v2 all-target Clippy and formatting.
The manually invoked browser fixture is ignored in the ordinary test run.

Real-browser checks used the production compiled assets and a synthetic signed,
encrypted ledger: two scopes, 25 text occurrences and binary bytes. Desktop,
tablet and phone layouts, pagination, scope switching, source/provenance,
control-byte hex display and locking were exercised. Screenshots and exact
limits are in `reviews/library-browser/README.md`. No production archive,
keys, provider traffic or installation was used.

AC-1 and AC-2 have substantial API/CLI evidence, but resource pressure across
many hostile connections has not been independently qualified. AC-3 is partial:
API ranges and generated Blob bytes compare exactly, but the in-app browser's
download event times out; local file delivery is not claimed. The anchor is
attached for activation and the object URL remains live for one second, with
immediate release on lock/pagehide. No download completion claim follows from
that implementation alone. AC-4 has text-only DOM/CSP and authority tests;
a browser-wide external-request trace was unavailable. AC-5 has API revocation
and deterministic late-response/lock tests; this does not claim operating-system
memory scrubbing. AC-6 is partial: empty/denied/stale/error cases have API/Node
coverage rather than all being exercised in the real browser. Fresh review
remains required. The parent complete-frontend acceptance criteria stay open.


## Review-driven UI corrections in progress

The author and independent reviewer both reproduced stale rows/continuation
remaining actionable during a scope switch. The client now clears old rows,
counts and navigation before requesting a page under the new pin. This has a
named assertion kill under whole-fix reversion (61e2487).

A second correction distinguishes 404 unavailable source from verification and
transport failures, preserves other browsing after non-authorization errors,
and defaults directional formatting controls to exact hex. Every failed source
read clears displayed plaintext; 401/403 still lock everything. These changes
have Node coverage and real whole-fix reversion, but require their own fresh
review. The backend still fails a page containing a missing/corrupt referenced
object; per-occurrence unavailable-evidence rows remain an explicit AC-3 gap.


The next correction refuses a reader signer equal to a configured storage issuer,
classifies transport signature failures as integrity failures rather than signed
grant denials, queues up to eight additional accepted sockets for at most six
seconds behind four executing requests, and renders the authenticated capability
list as a visible matrix. The overall 35-second connection deadline includes
queueing. Excess load remains visibly unavailable; this is not a guarantee of
availability against hostile local processes. Remote calls can exhaust the
connection budget, especially a multi-scope catalog; per-scope error rows and
composed timeout budgeting remain follow-ups.

Author tests now directly exercise hostile signed pin principal/audience and
signature, page completeness/tip, duplicate auth, content type, scope-count,
loopback/token-floor and capability-display boundaries. These strengthen the
reported mutation gaps; only actual observed mutation/reversion results count as
kills. Future review must independently verify them.


Correction validation: 15 reader tests plus one ignored manual fixture, one CLI,
19 surface tests, 34 Node tests, strict v2 all-target Clippy and formatting pass.
Whole-correction reversion compiled and killed the catalog-signature, reused-
issuer-key and fifth-connection assertions, plus the Node capability matrix test;
all passed before and after restoration. Exact generated trailer and raw logs
are in `reviews/kan-v2-library-correction-author/`. Desktop/phone browser checks
confirm the visible matrix and corrected navigation. Fresh correction review
is pending; the earlier approval covers only df74506.

## Correction review outcome
Fresh actual Claude Code Opus 5.5 session
efa9d730-4e15-4369-b0cd-ca2869a01b29 approved df74506..a8cbf21 with follow-ups.
The exact report, disposition and probe/reversion logs are retained under
`.design/reviews/kan-v2-library-correction-2026-10-18.*` and
`kan-v2-library-correction-probes/`. The corrections preserve authorization and
plaintext clearing; all three correction trailers replayed with actual assertion
failures. The criteria above remain open at their documented partial/unmet state.
Per-record unavailable evidence, per-scope catalog recovery, stronger resource
boundary tests and actual browser file delivery are not supplied by that approval.
