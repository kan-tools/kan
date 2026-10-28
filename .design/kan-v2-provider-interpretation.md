# Feature: source-linked provider interpretation

## Summary
Turn a selected, contiguous captured request or response into bounded human-readable items. The first explicitly selected format is the Anthropic Messages request, JSON response or SSE response. Interpretation is disposable and cannot authenticate a provider, grant access, establish session identity or certify capture completeness.

## Requirements
- REQ-1: Keep the exact assembled input available and report source ranges in bytes with exclusive ends. Each normalized item cites an enclosing region and explicitly declares coarse attribution; source mapping preserves all duplicate occurrence spans from `src/evidence_assembly.rs`.
- REQ-2: Parse JSON with duplicate-key rejection, depth and byte limits. Unknown blocks, fields and events retain their raw source rather than being mistaken for supported text. Invalid/truncated inputs produce visible items; resource limits refuse the operation.
- REQ-3: Render request history as supplied historical context, not newly observed utterances. Recognize text, tool use/results, thinking and attachment descriptors without executing tools or fetching URLs. Provider roles, indices, signatures and outcomes remain claims.
- REQ-4: Frame SSE across arbitrary capture boundaries with LF, CRLF or CR line endings, comments and multiline data. Preserve incomplete trailing events, malformed event/data pairs, errors and unknown variants. Protocol stop observation does not imply complete traffic capture.
- REQ-5: Bound input bytes, items, normalized output bytes, citations and work; support cancellation/deadline with no persistent plaintext cache. Sparse indices never allocate index-sized arrays. A budget failure returns no partial success.
- REQ-6: Qualify exact source mapping, escaped/multibyte text, unknown/malformed events, tool fragments, contradictory sequencing and all limits using meaningful regressions and fresh actual Opus review before API integration.

## Acceptance Criteria
- [ ] AC-1: Independently constructed JSON fixtures exercise string/array content, repeated history, tools/results, thinking and attachments, duplicate/escaped duplicate keys, unknown fields/types and malformed/truncated bodies. Every item retains an enclosing source region. (REQ-1, REQ-2, REQ-3)
- [ ] AC-2: SSE fixtures split every byte boundary across capture chunks, include all three newline forms, multiline data, comments, ping/error/unknown events and a trailing unfinished event. Invalid sequencing and unmatched names/types remain visible and never certify completion. (REQ-2, REQ-4)
- [ ] AC-3: Mapping regions across multibyte and escaped input retains every duplicate source occurrence; gaps, overlaps, forged/out-of-range spans and inconsistent source bytes refuse. No offsets are rounded for JavaScript. (REQ-1, REQ-5)
- [ ] AC-4: Exact budget edges, sparse integer indices, cancellation and a deterministic in-flight interruption fail without hidden persistence or network. Selected semantic controls fail behavior assertions; strict lint and fresh review pass. (REQ-5, REQ-6)

## Architecture
The new pure module consumes explicitly selected assembled bytes and an explicit format, not guessed provider identity from captured text. The caller retains the source occurrence selection and assembles through `src/evidence_assembly.rs`. Parsing exposes ordered items with raw protocol data and an enclosing byte range. It does not coalesce repeated requests into a cross-request session. A separate mapping helper intersects those ranges with verified stream segments and checks the referenced original bytes, returning every exact duplicate source span. Request JSON item ranges may cover the whole body and SSE item ranges cover the enclosing event; these are deliberately coarse semantic citations.

The parser uses strict bounded JSON and never interprets HTML, links, attachments or tools as executable content. SSE transport framing is separate from message/block sequencing. A state machine reports duplicate/missing starts, unknown block indices, contradictory delta types, messages after stop and truncated tool JSON. Preserve original events even when a derived block summary is unavailable; no last-write-wins repair of contradictions. Tool-input fragments remain partial text until a bounded valid object can be established; an empty initial object is not the completed streamed tool input.

`Limits` separates bytes scanned, number of items, normalized bytes and source-citation count. Bound before parsing/copying and poll between bounded parsing units; no claim of preemptible arbitrary allocation or exact RSS. Caller input is already bounded and plaintext remains memory-only. This module has no serializer; later API coordinates must use exact decimal strings or checked safe integers.

## Protocol grounding
Primary references checked 2026-10-19: [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming) defines message/block lifecycle, indexed deltas, ping/error and extensible events; [fine-grained tool streaming](https://platform.claude.com/docs/en/agents-and-tools/tool-use/fine-grained-tool-streaming) requires retaining potentially incomplete JSON. This document specifies Kan's interpretation policy, not provider authority. Unknown extensions stay visible under the versioned adapter.

## Open Questions
No new product preference is needed. Contradictions are displayed as evidence, not repaired. Any change to capture authority or retention must return to the parent architecture.

## Out of Scope
Authorized API selection, Content/Source/Provenance frontend, session discovery, search, annotations and analysis/day remain required later integration. This pure module does not close the parent human-frontend or reconstruction acceptance criteria.

## Recording
Continues `.design/kan-v2-session-reconstruction.md` and the approved full frontend roadmap. Git-first recording remains necessary under day#168/kan#197; no live-log access, reconstructed excluded claims or invented witnesses. Run and retain actual day validation; a failed workspace lookup is not validation success.

## Author qualification checkpoint

The pure adapter passes 43 affected integration tests, one deterministic
cancellation unit, strict all-target v2 Clippy and formatting. Seven selected
compiled controls fail named behavior assertions, and restored tests pass.
Evidence, including the initial formatting and CI fixture compilation failure,
is retained in `.design/reviews/kan-v2-provider-interpretation-author/`.
Day validation returned exit 2 (worktree lookup refusal), not validation success.
Fresh actual Opus review is required before accepting this component.

Assembly review B-N4 carries forward: a gap means no recognized capture at those
ordinals, not proof of absent inputs. The Content consumer must show unplaced
unsupported, malformed and unavailable observations beside the attempt groups.
This adapter interprets one eligible byte stream and cannot itself provide that
selection-wide view; `.design/kan-v2-content-api.md` must preserve it.

Combined qualification after merging the reader/assembly follow-through: 97 affected integration tests, five units, strict all-target v2 Clippy and formatting pass. Runtime behavior is unchanged by the parent merge. Raw logs are retained under the author evidence directory.

## Fresh review and version 2 follow-through
Fresh actual Opus 5.5 reviewed frozen 0d04848: provider APPROVE WITH FOLLOW-UPS and parent reader/assembly follow-through APPROVE. The complete report and raw results are retained under `.design/reviews/kan-v2-provider-interpretation-opus/`; source identities matched before and after. A-F1/A-F2 must be qualified before accepting Content integration.

Version `kan-anthropic-messages/2` promotes independent source-forgery/state tests and pins absolute JSON/SSE output accounting. It accepts validated empty chunks at covered offsets when mapping; empty regions cite all segments touching the point, including both adjacent segments and duplicates. Such zero-width citations locate evidence; they do not assert nonempty content. RequestEnd-only empty streams still have no chunk citations, so consumers also retain ordinal/extent lineage.

Nested array tool results now emit their text/attachment/unknown children with root JSON pointers. Malformed and Unsupported items carry explicit Shape/Unknown reasons; wrong response roles are flagged. Completed accumulated tool JSON is exposed separately with an enclosing block-wide `tool_region`, while the stop event keeps its own exact event region. The consumer must map both independently. Request items remain supplied history; the human renderer labels that on each item, including historical assistant/tool content.

Primary references rechecked 2026-10-19: [Anthropic citations](https://platform.claude.com/docs/en/build-with-claude/citations) specifies citations_delta on text blocks; supported citation objects no longer create a false DeltaType conflict. Unknown delta types keep Unknown without guessing an incompatible block kind. [Tool streaming](https://platform.claude.com/docs/en/docs/agents-and-tools/tool-use/fine-grained-tool-streaming) requires concatenating and parsing fragments; an empty-only fragment sequence remains invalid JSON, while an empty fragment followed by a valid object is accepted. The initial empty object is a placeholder, not repaired input. No evidence was found that empty-only fragments constitute a valid final object.

[WHATWG SSE](https://html.spec.whatwg.org/multipage/server-sent-events.html) specifies stripping one leading UTF-8 BOM. Version 2 parses past it while keeping it inside the first source region and charging those bytes. Dataless blocks become visibly Undispatched Framing; they are not message events, including after a stop. Unknown field names receive Unknown and prevent a coherent-stop assertion; id/retry/comments remain ordinary framing.

A-F3 allocation evidence is retained: the byte counters do not measure heap. A consuming API must bound items separately, account cumulative mapping passes, bound worker admission through cancellation, and cap actual serialized output independently. A-F6 remains an explicit parser limitation: parsed Values may round integers outside i64/u64 and reject exponent overflow; parsed JSON is a derived display, never a raw numeric record. Exact captured bytes remain available through Source. No global decoder-number or serde feature change is made here.

Version 2 passes 122 integration tests and six units, strict all-target v2 Clippy and formatting. All twelve selected review-derived controls compile and fail behavior assertions; restored tests pass. Whole-production-fix reversion demonstrates four new regressions failing with the fix removed and passing after restoration. Failed methods (offset shadowing, a style lint, a wrong-worktree command and two overly narrow control-result classifiers) are retained separately from successful evidence in `.design/reviews/kan-v2-provider-followup-author/`. Fresh independent review of version 2 remains required and will accompany the Content integration checkpoint. Parent human-frontend/recovery acceptance remains open.


Version `kan-anthropic-messages/3` is a review-correction candidate. Malformed error envelopes retain a resolving root or `/error` pointer plus a Shape reason; object/null/number tool-result content receives Shape while raw JSON is retained. The internal validated mapping borrows both immutable stream and input evidence. Its constructor verifies all source correspondence once, while the public `map_region` compatibility API still performs full validation per call. Exact duplicate and zero-width boundary citation rules are unchanged. Qualification and independent acceptance are pending.
