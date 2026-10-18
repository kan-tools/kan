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
- REQ-5: Keep decrypted material in bounded reader memory for this first slice. No plaintext index, temporary file, log, URL or browser storage is created. Index-backed search remains an explicit unavailable capability until encrypted projections and their grant invalidation are implemented.
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
contracts supply signed Snapshot/Page/Record/Object requests. Compose these
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
Planning only. No reader API implementation or acceptance criterion is claimed.
Legacy kan/day claim backfill remains subject to the recorded partial-trust
limitation; this document does not fabricate witnesses or evidence claims.
