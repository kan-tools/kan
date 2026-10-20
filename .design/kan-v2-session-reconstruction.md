# Feature: evidence-backed conversation reconstruction

## Current implementation flow

The owner-approved SOP in `kan-v2-next-build-status.md` supersedes the historical
per-slice review requirements below. Complete integrated implementation first,
then one thorough independent review campaign.

## Summary
A human can open an authorized retained attempt, read its available request and
response, inspect normalized items against captured bytes, and see gaps and
unsupported formats. This versioned interpretation serves
`telos/raw-data-and-projections`; it never replaces the raw record or asserts
that a displayed speaker signed the content. This is a build contract proposal,
not an implemented or independently accepted capability.

## Requirements
- REQ-1: Acquire every input through authorized occurrence selection and fresh source verification. Preserve snapshot, scope, occurrence, writer, proof and availability lineage; no arbitrary-CID source bypass.
- REQ-2: Decode bounded KANC2 frames with checked arithmetic and strict recognized shapes. Distinguish malformed, unsupported and non-capture input; account for every supplied occurrence.
- REQ-3: Assemble only within scope/writer/observer/attempt identity, retaining duplicates, conflicting ordinals, holes, overlaps, unknown outcomes and untrusted transport-link claims.
- REQ-4: Cite normalized output to exact decrypted-frame byte intervals with exclusive ends; explicitly mark enclosing/coarse spans. Do not invent precision or collapse repeated request history into new messages.
- REQ-5: Bound input records, source/output bytes and work. Expose partial coverage and refusal, keep integer identities exact through JavaScript, and avoid hidden whole-archive discovery.
- REQ-6: Version provider/harness adapters, preserve unsupported events and incomplete streaming/tool input, and distinguish protocol completeness from capture coverage. Never execute or fetch content as a side effect of rendering.
- REQ-7: Add human-readable Content with Source and Provenance navigation through the real API. Lock/revocation clears plaintext, selection and late responses; no persistent plaintext cache or index in this slice.
- REQ-8: Keep reconstruction disposable and reproducible from selected evidence plus adapter identity, preserve branches/compaction uncertainty, and qualify each substantive implementation through fresh actual Opus 5.5 review.

## Acceptance Criteria
- [ ] AC-1: Byte-exact envelope fixtures reject malformed lengths, duplicate keys, body/event contradictions and unsafe integers while retaining unsupported variants visibly. (REQ-2, REQ-5)
- [ ] AC-2: Interleaved scopes/writers/observers, repeated identical frames, ordinal conflicts, missing chunks and contradictory end markers preserve every input lineage and explicit coverage. (REQ-1, REQ-3, REQ-8)
- [ ] AC-3: Independently authored fixtures verify source spans for escaped and multibyte text across capture/SSE boundaries; imprecise mappings are visibly coarse. (REQ-4, REQ-6)
- [ ] AC-4: Provider/harness fixtures cover tool input/result, attachments, streaming errors, unknown variants, truncated JSON, repeated history, branches and compaction without invented authorship or completeness. (REQ-3, REQ-4, REQ-6, REQ-8)
- [ ] AC-5: API tests reject cross-scope and revoked source selection before returning snippets/counts; cancellation and all budgets fail or report partial coverage without hidden archive scans. (REQ-1, REQ-5, REQ-7)
- [ ] AC-6: Real browser verification covers Content/Source/Provenance return navigation, keyboard/focus, light/dark/mobile, lock during assembly and hostile content without script execution or external requests. (REQ-4, REQ-6, REQ-7)
- [ ] AC-7: Reassembly after discarding derived state reproduces normalized output and citations for the same selected inputs and adapter version; unavailable inputs remain visible. (REQ-1, REQ-2, REQ-8)
- [ ] AC-8: Fresh actual Claude Code Opus 5.5 review tests scope/identity, source lineage, limits and incomplete-coverage boundaries with independently authored probes and meaningful guard-removal controls. (REQ-1, REQ-2, REQ-3, REQ-4, REQ-5, REQ-6, REQ-7, REQ-8)

## Architecture

The immutable-evidence and disposable-projection distinction follows
`docs/SPEC.md` and `CLAUDE.md`. The capture wire shape is implemented by
`src/evidence_capture.rs` (`Header`, `Event`, `Recorder::record`). Membership and
source verification come from `src/evidence_reader.rs`; the new explicit
availability boundary is `src/evidence_store/inventory.rs`. Integrate through the
existing frontend and reader contracts, not a second authority or a semantic
log rewrite. Parent scope remains `.design/kan-v2-human-frontend.md`.

### Evidence and authorization

All inputs enter through the configured reader, pinned inventory and fresh
membership checks. Parsing plaintext does not confer an archive grant. Each
input carries scope, selected snapshot, occurrence sequence, manifest/receipt
identities, authenticated writer and the available/missing/corrupt state supplied
by the reviewed inventory contract. An unavailable input stays a visible item.
The browser cannot pass an arbitrary object CID to bypass membership checks.

Every output cites one or more input byte intervals, using exclusive ends. These
are offsets in decrypted retained frame bytes, not Unicode characters. If a
provider field cannot be mapped precisely, cite the enclosing exact JSON value
or entire body and label the span coarse; never invent a precise range. Escapes,
non-ASCII text, chunk boundaries and repeated text need independent span tests.
Resource links use the existing occurrence selection until a canonical URI
extension is reviewed. A browser fragment is not a new evidence URI scheme.

### First adapter: the captured observation envelope

Current recorder bytes are `KANC2`, a four-byte big-endian JSON-header length,
the header, then body. The writer bounds the header to 128 KiB and body to 64 KiB.
The decoder checks length arithmetic before allocation, UTF-8/header shape,
version, bounded identifiers and event/body constraints. Duplicate JSON keys
cannot choose different interpretations in different readers. Unknown versions
or event variants remain explicitly unsupported with exact source access;
malformed recognized envelopes are distinguished from opaque non-capture input.
Parsing uses no network, execution, attachment activation or persistent cache.

Group only by `(scope, authenticated writer, observer, attempt)`. Within a group,
ordinal orders observations. Same-ordinal differing frames are a conflict, not
last-write-wins. Repeated occurrences of exact frame bytes retain all occurrence
lineage. A shared transport exchange is a claimed relation, not authority to
collapse observers or writers into one sequence. Wall-clock time never repairs
missing order or proves causal linkage.

Request/response offsets determine byte assembly. Holes, overlaps, contradictory
end counts, missing initial events and truncated selections remain visible.
`unconfirmed_before` is an observer claim, not an exact count of lost remote
records. RequestEnd may establish the recorded request byte extent when all
segments agree. A completed terminal observation does not establish complete
traffic capture. Missing terminal observations display outcome unknown.

Assembly has explicit input-record, source-byte, output-byte and time budgets;
limits return partial coverage and continuation or a refusal, never empty success.
No request silently scans the whole archive to find an attempt. The first API
accepts a bounded authorized occurrence selection; broader discovery requires
the later indexed selection contract. All u64 coordinates cross JavaScript as
validated decimal strings or checked safe integers, never rounded identifiers.

### Provider and harness adapters

Adapters have explicit name/version and report supported event forms. The first
provider adapter targets the existing Anthropic harness profile. Protocol
references were checked on 2026-10-19; supported forms remain versioned, not
inferred from a provider name alone. It must handle streamed event
boundaries independently of capture chunks, incomplete SSE events, tool inputs
and results, text blocks, attachments, errors and unknown variants. Each new
provider is a separate reviewed adapter with preserved raw fixtures.

A request often repeats earlier conversation history. It is not a new occurrence
of every historical message. Cross-request sessions require explicit evidence
links and a declared reconstruction rule; matching content or timestamps alone
cannot invent identity. Branches and compaction retain their source relationships
and ambiguity. Tool labels are provider/harness claims, not cryptographic authors.
Unknown attachment bytes remain inspectable/downloadable under existing grants;
no external URL is fetched just because it appears in a message.

### Human workflow

The Library adds Content beside Source and Provenance. Attempt view shows ordered
observations, request/response reading panes, gaps/conflicts and adapter coverage.
Selecting a rendered item selects its source intervals. Unsupported content
always retains a path to authorized raw inspection. Session navigation appears
only when that real API is integrated; it is not enabled by a synthetic mock.

Lock and access revocation invalidate assembly, selections and late responses in
the same way as source reads. Responses are no-store. No decrypted reconstruction
is persisted in browser storage, temporary files, logs or a server index in this
slice. Persistent search comes later with encrypted projection and revocation
contracts; that remains required by the full frontend, not removed from scope.


### Primary protocol grounding

The provider adapter follows message and indexed-content-block boundaries,
retains ping/error/unknown events, and handles text, tool-input and thinking
variants separately. Transport chunks are not provider event boundaries.
See [Anthropic streaming messages](https://platform.claude.com/docs/en/build-with-claude/streaming).

Tool-input fragments may remain invalid JSON even when streaming ends; the
initial empty input object is a placeholder. Concatenate bounded fragments,
guard parsing and retain truncated input as an explicit partial item. Do not
repair it silently or run the tool.
See [Anthropic fine-grained tool streaming](https://platform.claude.com/docs/en/agents-and-tools/tool-use/fine-grained-tool-streaming).

These are protocol inputs to a Kan interpretation, not promises that every
existing provider extension is supported. Fixtures must name their adapter
version and cover unknown variants. Recheck primary docs when implementing a
new adapter rather than updating old derived records in place.

## Sequencing and remaining scope

First qualify the pure envelope decoder and occurrence assembly using synthetic
fixtures. Then qualify the initial provider adapter and source spans, followed
by authorized API integration and real browser behavior. Storage inventory and
recovery integration remain separate prerequisites to browsing damaged archives.
Search, annotations, saved views, background extraction/day assessment and full
administration remain required by the overall frontend roadmap. None is closed
by this document or the first Content panel.

## Recording and validation status

This continues the existing local draft; no new product decision is required.
Git-first recording remains necessary while worktree day/kan discovery refuses
shared repository state (day#168/kan#197). Do not reconstruct the two withheld
claims or invent witnesses for the existing telos. Design recording and bridge
claims require later backfill; no claim CIDs or witnessed completion are asserted.
Run the actual design validator and preserve its output, including any root-
checkout path warnings, separately from implementation acceptance.

## First implementation checkpoint: pure frame decoder

`src/evidence_reconstruction.rs` adds a bounded, non-persistent decoder only.
It returns opaque, unsupported, malformed or recognized capture input separately.
The recognized frame exposes borrowed body bytes and exact header/body ranges;
it has no wire serializer, grant, signature judgment or assembly-completeness
claim. JSON maps reject duplicate keys recursively, including escaped aliases,
before variant selection. Unknown envelope/version/observer/event/outcome is
unsupported; unsupported means no semantic fields are accepted, not that all
remaining fields satisfy a known schema. Recognized shapes use the current
strict capture Header/Event types and recorder byte/identifier limits.

HTTP directions, offsets, totals, status and timestamps remain observer claims;
coherence belongs to later assembly. This checkpoint does not silently tighten
the recorder's historical semantic guarantees. KANC-family truncation beginning
with the four-byte family prefix is malformed; inputs without that prefix are
opaque. Decode requires a complete retained frame, not a source-range fragment.
All storage/RPC/browser/session acceptance remains open. No persistence surface
is added by this pure function.

### Decoder review decisions

The first independent decoder review found that Serde's internally tagged unit
variant silently ignores extra fields. Forwarding-intent now explicitly refuses
anything beyond its type field; every recognized event has an extra-field test.
A recognized header must include `observed_at_unix_micros`: explicit null retains
the recorder's unavailable-clock claim, whereas absence is malformed. Unknown
variants still accept no semantic interpretation. Noncanonical JSON whitespace
and escaping remain accepted when unambiguous; exact original spans are retained.

For every input beginning `KANC`, the total-frame size limit precedes envelope
version classification, including unknown envelope versions. Thus oversized
unknown KANC-family data is a limit refusal. Inputs without the KANC prefix remain
opaque without parsing or copying, regardless of size. Downstream source-read
budgets remain responsible for all input acquisition. These choices do not
assert coverage or close the parent reconstruction acceptance criteria.

The second cold review's PA1/PA2 probes are promoted into the normal test suite:
accepted recognized frames must round-trip to the parsed JSON value across the
mutation corpus, and absent clocks on unknown versions/observers/events/outcomes
remain Unsupported. This pins classification precedence and catches future
optional-field or unit-variant narrowing before a consumer is added.

## Next implementation checkpoint: bounded occurrence assembly

The next pure component consumes a bounded caller-selected list of authorized
occurrences, with caller-supplied scope/writer identity and available or typed
unavailable frame bytes. Source indices refer back to that complete input list;
the caller must retain snapshot/proof/occurrence lineage with each index. This
component grants no access and discovers no additional records. All inputs,
including malformed, opaque, unsupported and unavailable ones, remain represented.

Group recognized captures only by scope, authenticated writer, observer and attempt.
Preserve each input at its observer ordinal. Exact duplicate frames may share one
stream segment but retain every source index; different frames at the same ordinal
are visible conflicts, never last-write-wins. Report observed ordinal holes without
expanding missing integers or treating wall clocks/transport links as identity.

Request/response assembly retains offset segments with exact frame-body spans.
Checked end arithmetic, holes, overlaps, chunks after request-end and conflicting request-end claims prevent
a synthetic contiguous rendering. Never allocate by a claimed offset or pad a hole.
A contiguous response prefix and a claimed terminal outcome do not certify complete
capture. An unknown request extent stays unknown. Metadata and other events remain
inspectable as observations; provider semantics and metadata-chunk interpretation
belong to the adapter stage.

Explicit occurrence, encoded-input, scanned-byte, assembled-byte and time/cancel
budgets return a refusal without partial success. Containers are bounded by input
count; byte budgets are not an exact RSS/CPU promise. Arithmetic uses native u64
coordinates and this pure result has no wire serializer. The later API must use
validated decimal strings for JavaScript.

Qualification must independently cover isolation, exact duplicates, same-ordinal
conflicts, missing starts/terminals, contradictory request extents, offset overflow,
large sparse coordinates, non-ASCII/binary source spans, unavailable input,
determinism and cancellation/budget boundaries. This checkpoint does not implement
provider adapters, source authorization, the Content API or the session UI and
closes no full-session acceptance criterion.

### Assembly author qualification

The pure assembly checkpoint passes 30 affected integration checks and one
deterministic cancellation unit, strict all-target v2 Clippy and formatting.
Eight selected semantic mutants compile and fail named behavioral assertions;
the restored assembly suite passes. Raw runs, the control-harness correction
and initial CI performance failure are retained in
`.design/reviews/kan-v2-session-assembly-author/`. Fresh independent review is
still required; API, provider interpretation and browser acceptance stay open.

### Fresh assembly review follow-through

Actual cold Opus 5.5 reviewed frozen `eb4f471`: **APPROVE WITH FOLLOW-UPS**
for assembly and the reader correction. The complete unchanged report, sixteen
assembly probes, ten physical probes, all mutations and exact custody checks
are retained in `.design/reviews/kan-v2-assembly-opening-opus/`.

B-N1/N2/N3 add absolute decode/duplicate-comparison/copy scan accounting,
out-of-ordinal-order offsets and every duplicate RequestEnd source to CI. B-N4
clarifies that ordinal gaps mean no recognized capture at those ordinals, not
proof that no input exists. Consumers must show unplaced unsupported, malformed
and unavailable observations beside groups. A conflict can conservatively block
both streams even when one has contiguous bytes; the UI must explain this.
These changes are being qualified; no runtime assembly behavior changed.

The same initial CI commit passed the requested performance rerun with ratio
6.8 against unchanged bound 8; both runs are retained. Later commits need their
own CI results. API, provider interpretation and full browser acceptance remain
open. The new actual IAB recheck confirms browser access but the download event
still timed out; delivery remains unverified.

Follow-through qualification at 2906902 passes 84 integrations, four units, strict Clippy/fmt and five selected semantic controls with restored 17 assembly tests. Evidence: `.design/reviews/kan-v2-assembly-followup-author/`.

## Resumable attempt discovery

The proof Library adds `proof-discover`: one explicit signed-inventory page of
1–20 occurrences, each freshly read and verified, with a final authorization
check. It returns existing source-selection tokens and bounded capture header
interpretations, never request/response bodies. Missing, corrupt, opaque,
unsupported and malformed evidence remain unassigned and inspectable. The work
shares the Content worker limit and has an 8 MiB input / 20 second batch budget.
Failure returns no partial batch; the caller may retry its unchanged cursor.

The UI groups only by configured archive, scope, verified writer, observer and
attempt. It retains at most 500 occurrence descriptions in memory; the explicit
next-window action continues from the signed cursor and discards the prior
window. Scope/snapshot changes and lock clear discovery. Coverage distinguishes
scanned windows, the end of pinned inventory, and unknown traffic completeness.
Content remains explicit selections of at most 40 occurrences, including selection
across inventory pages. This is attempt navigation, not a persistent search index
or a claim to reconstruct linked sessions or assemble arbitrarily large attempts.
Those remain required work in the full frontend checklist.

## Larger attempts and explicit session links

The next integration adds a distinct `proof-attempt` action rather than changing
legacy selection limits. It accepts up to 1,024 verified selections, 40 MiB raw
input, 96 MiB output and a 512 MiB scan-work allowance, with a 120-second
attempt deadline and cancellation checks. The Library connection deadline is
150 seconds; small Content remains at 20 seconds. It exclusively takes the two shared Content
permits. Available inputs must all be recognized captures for the same verified
writer/observer/attempt; unavailable inputs remain unplaced evidence. Mapping,
assembly and citation limits scale together. Browser long text is paged without
altering source coordinates or truncating the underlying derived result.

Discovery now retains 1,000 descriptions per explicit window and can advance
batches until the window ends or the user stops it. Session relationships come
only from strict incoming HTTP metadata: the Kan session/parent/transition headers
or a separately namespaced Claude Code session-membership header. Duplicate,
malformed and conflicting claims remain visible. Parent links are not used for
recursive identity collapse, rewriting source history or asserting causal order.
The collector forwards Kan headers only to the gateway, which records then strips
them before the provider. No new capture-wire variant or persistent store is added.
Cross-archive sessions, fragmented-header relationship extraction and persistent
indexing remain explicit required follow-ups, not implied by this windowed view.

### Bounded proof reads (2026-10-19)

Attempt acquisition uses an additive `read-batch` proof operation: at most eight
explicit coordinates per request, with a reply containing a nonempty ordered
prefix bounded to 4 MiB of retained request bytes. One current metadata audit
covers that batch; each selection and fresh payload is still checked separately.
There is no audit cache across requests or persistent plaintext cache. The reader
verifies every returned coordinate, proof, writer signature and encryption binding;
it resumes only the unreturned suffix. Current grants are checked on every batch
and again before publishing derived Content. Legacy single reads remain supported.
Batch capability is optional for older services. This addresses repeated read
audits; admission's full payload audits require separate integrity-preserving work.

### Cross-archive session workspace (2026-10-19)

An explicit human scan visits authorized proof archives at their separate catalog
pins, round-robin, retaining at most 1,000 descriptions in tab memory per window.
It displays per-archive cursors/coverage and unavailable sources. Equal explicit
session IDs are grouped only within the same verified writer, observer and scheme;
archives and their occurrences remain separate. Parent lookup uses that same
identity boundary and reports every observed archive match rather than silently
choosing or deduplicating a copy. Link evidence and attempt Content reopen through
the chosen archive's original pin and current access checks. A stopped or bounded
scan remains partial; a new window retains continuation but discards prior window
descriptions. Lock and catalog refresh clear the workspace. This is navigation over
verified observations, not a persistent search index or authoritative session merge.
