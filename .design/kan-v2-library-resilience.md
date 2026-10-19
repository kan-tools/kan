# Feature: Library resilience and verified exports

## Summary
Continue the approved Library roadmap with useful partial browsing when an upstream
source fails, bounded request scheduling and stronger regression evidence. Serve
`telos/raw-data-and-projections`: an incomplete check must remain visible and must
not erase accessible neighbours or promote unverified metadata to authority.

## Requirements
- REQ-1: Keep successfully authorized scopes usable when another configured scope is unreachable, malformed or unverifiable. Emit an explicit complete/partial catalog-coverage field. Verified denial remains omitted; never expose failed-scope identifiers, endpoints, failure counts, pins or source bytes.
- REQ-2: Bound remote calls to five seconds each, catalog concurrency to four within the existing sixteen-scope configuration limit, request-body reading to three seconds, and keep four executing/twelve accepted connections with six-second queue and thirty-five-second whole-connection deadlines. Cancellation must drop unfinished reads.
- REQ-3: Show partial catalog coverage persistently during page/source navigation; supply an explicit retry-sources action. Clear prior pins, rows and plaintext before rechecking sources. Lock must invalidate late replies and clear coverage and capability metadata.
- REQ-4: Pin actual API capability lists and negative UI cases: 401/403 denial, Previous during loading, malformed/duplicate capabilities and all directional-control families. Preserve byte-exact explicit UTF-8 inspection.
- REQ-5: Exercise explicit range export in a real browser and compare delivered bytes when the browser exposes a file. Keep authorization rechecks and bounded memory. If the browser cannot deliver or inspect downloads, record the exact limitation without marking delivery verified.
- REQ-6: Preserve raw storage and current admission proofs. Commit fresh actual Opus 5.5 review, meaningful whole-production reversion and surviving coverage gaps. Keep subsequent missing-evidence, collection overview and full-frontend work visible.

## Acceptance Criteria
- [ ] AC-1: Real signed synthetic endpoints demonstrate healthy-neighbour page/source access alongside forged, refused and stalled sources, explicit partial coverage, recovery on retry, and indistinguishable omission of denied/unknown scopes. No failed identifier appears in serialized responses. Reverting partial-catalog handling fails a named assertion. (REQ-1, REQ-3, REQ-6)
- [ ] AC-2: Production scheduling tests demonstrate four executing and twelve admitted jobs, exact queue/whole deadlines, permit release on cancellation and refusal of excess sockets. A real fifth-socket test checks both success and queued latency. Catalog scheduling reaches later healthy scopes despite stalled earlier ones. (REQ-2, REQ-6)
- [ ] AC-3: Node tests verify persistent partial coverage through paging/inspection, retry recovery, all-failed distinct from complete-empty, and no late repaint after lock. Actual API capability arrays are asserted. (REQ-3, REQ-4)
- [ ] AC-4: Negative tests exercise both denial statuses, Previous during an in-flight page, malformed/duplicate capabilities, and isolates/LRM/RLM/ALM as well as embedding controls. Mutation checks must fail assertions, not compilation. (REQ-4, REQ-6)
- [ ] AC-5: Real-browser fixture checks desktop/mobile partial-state rendering and retry, plus exact exported bytes or an explicitly retained browser-delivery limitation. Captured markup stays inert and lock clears source. (REQ-3, REQ-5)
- [ ] AC-6: Source/store surfaces remain unchanged; fresh Opus review and correction evidence are retained. The follow-up ledger distinguishes this completed checkpoint from unimplemented later roadmap items. (REQ-6)

## Architecture
The modules remain registered through `src/lib.rs`; `Cargo.toml` enables Tokio
time control for deterministic tests without adding a persistent surface.

`src/evidence_library.rs` composes catalog snapshots in groups of at most four,
without detached tasks; dropping the query cancels its in-flight group. Only a
verified Snapshot becomes a selectable scope. The wire response adds `coverage`
(`complete` or `partial`) to the existing catalog. Partial coverage reports that
some configured checks failed, without identifying or counting them in the response body. Response latency can
reveal how many groups contain stalled checks; this profile does not hide timing. A signed
denial remains indistinguishable from an unknown grant. This is an intentional
privacy refinement of the requested per-scope error rows: unauthenticated scope
identities do not become browser-visible merely because their transport failed.
All-failed catalogs are partial with no selectable scopes, not complete-empty.

`src/evidence_reader.rs` bounds each signed upstream operation to five seconds.
Sixteen catalog checks take at most four five-second groups; a source request
uses at most two five-second calls. Queue six + headers five + body three +
catalog twenty leaves one second inside the overall thirty-five-second deadline;
this is a budget composition, not a hard CPU scheduling guarantee. Timeouts are
unavailable observations, never authenticated grant denials. Slow healthy
services may be reported partial and can be retried.

Extract the existing connection admission/deadline code out of the select macro
into a private production helper shared by deterministic time-controlled tests.
The live server still owns all tasks and socket permits; abort/drop releases both
execution and admission permits. Keep read authority separate from administration.
No request begins queued work after its deadline or leaves detached remote work.

`web/library/app.js` and `web/library/index.html` retain a separate persistent
catalog-coverage region and retry action, so normal notices cannot overwrite the
partial warning. Rechecking clears old inventory and selected source immediately.
Unknown/malformed capability responses fail closed. Use textContent for all labels.
The existing source-range export remains user-triggered and reauthorized; no
clipboard, automatic export, browser persistence or new plaintext server surface.

## Resolved Questions
- Continue in a permanent worktree, stacked on the Library and overview-design PRs.
- Partial catalog failure is visible without exposing identifiers whose grants could not be verified. This preserves the original pre-filter authorization contract.
- Five-second per-call limits make bounded partial results practical; they are visible availability limits, not proof that a slow source is absent.

## Open Questions
No new owner preference is needed for this checkpoint. Deployment placement is
still unanswered and remains independent of synthetic implementation/review.

## Out of Scope
Missing historical objects still require a separate authenticated-metadata design;
do not bypass Service::audit_suffix/read_signed. Collection overview, normalized
conversations, search, annotations, views, analysis and admin remain required next
roadmap steps. No live installation, migration/cutover, production keys or main merge.

## Process record
Continuation of the approved roadmap and Library design. Main `day doctor` finds
seven atoms but cannot establish complete composition because two claims remain
withheld. The live raw-data-and-projections telos deliberately has no witnesses;
none are invented. Git-first records remain the agreed backfill path while the
worktree/shared-log limitation persists. `day next design` names generative-build.

Validation: the worktree-local day check refuses shared-workspace discovery
(day#168 / kan#197), not an empty log. Read-only validation from the main checkout
passes six requirements, six criteria, mappings and placeholders; it warns about
four branch-only paths and two withheld claims. All four paths exist here. No
kan/day claim writes or inferred witnesses.
