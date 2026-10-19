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
