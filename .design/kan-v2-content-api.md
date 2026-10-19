# Feature: authorized Content inspection

## Summary
Connect the reviewed frame, assembly and provider interpretation components to the real Library reader. A human explicitly selects retained occurrences, reads the resulting attempt groups and follows normalized items back to Source and Provenance. This is a bounded selection workflow; archive-wide discovery and cross-request session identity remain separate work.

## Requirements
- REQ-1: Accept only a pinned authorized occurrence selection through `src/evidence_reader.rs`; reverify current permission, snapshot membership, retained writer signature and ciphertext before decoding. No arbitrary-CID or supplied-plaintext bypass.
- REQ-2: Bound selection cardinality, acquired plaintext, assembly, interpretation, citations and serialized response size. Refuse incomplete acquisition; no successful partial body masquerades as a complete captured frame.
- REQ-3: Preserve each occurrence's scope, sequence, manifest/receipt, writer and snapshot lineage through group/source references. Encode all u64 coordinates as canonical decimal strings in the new response and request surface.
- REQ-4: Interpret only a user-selected provider format. Report malformed/opaque/unsupported/unavailable observations, group gaps/conflicts, observer-claimed outcomes and coarse source regions visibly; no capture-completeness or provider-authorship claim.
- REQ-5: Add Content, Source and Provenance navigation in `web/library/`; selection is explicit and bounded, persisted only in tab memory. Lock, scope/snapshot changes and access denial clear plaintext, selection, ongoing work and late responses.
- REQ-6: Propagate cancellation to bounded synchronous assembly/interpretation and current network reads. No unbounded background task, plaintext file/cache/index, external link fetch or content execution.
- REQ-7: Qualify real API authorization, cardinality/byte/time limits, tampered snapshot and revoked access; verify real browser light/dark/mobile/focus/source return and hostile content, then obtain fresh actual Opus review.

## Acceptance Criteria
- [ ] AC-1: Real signed service fixtures accept selected occurrences and refuse foreign scope, forged pin, revoked grant, mismatched writer binding, out-of-snapshot coordinates and truncated acquisition without snippets or counts. (REQ-1, REQ-2, REQ-4)
- [ ] AC-2: Interleaved attempts and duplicate selections preserve exact occurrence identities and frame-body spans; all new wire integer coordinates round-trip above the JavaScript safe-integer limit without rounding. (REQ-3, REQ-4)
- [ ] AC-3: Empty/oversized selections, duplicate coordinates, byte/item/work/output limits and cancellation return explicit refusal. No assembly operation continues unbounded after the connection is dropped. (REQ-2, REQ-6)
- [ ] AC-4: Browser fixtures exercise multi-selection, returned groups, unsupported/corrupt inputs, partial streams, item-to-source navigation and return, hostile strings, lock/revoke during network and interpretation, focus, mobile and both themes. (REQ-4, REQ-5, REQ-6)
- [ ] AC-5: Selected behavioral mutations fail named assertions; source/library compatibility checks, lint and fresh review pass. Pending actual browser download delivery remains separately visible. (REQ-7)

## Architecture
Refactor `Reader::source` internally so verified decrypted acquisition can be reused without round-tripping through hex/UTF-8 output. Existing Source behavior and authorization remain covered by their tests. The new entry point consumes one Pin and a bounded list of canonical decimal sequence strings, rejects duplicates, and performs current membership/read checks for every coordinate. Selection initially caps at one page's 40 occurrences, with explicit per-request resource limits; these are presentation work budgets, not archive-retention caps. Oversized non-capture payloads remain available through ordinary Source; Content refuses to treat a range fragment as a full frame.

Construct `evidence_assembly::Input` only from the verified acquired records. Caller-owned occurrence records remain adjacent to each input index. Provider interpretation operates separately on each eligible contiguous request/response stream and a declared format; unavailable or conflicted streams stay visible. Show all unplaced Unsupported/Malformed/Unavailable inputs beside groups: ordinal gaps are no recognized capture at those positions, not proof of absent data. Explain conservative conflict suppression even when a stream has contiguous bytes. Use `evidence_interpretation::map_region` to bind displayed regions back to original complete capture frames and every duplicate occurrence. Emit structured reason codes rather than unbounded debug strings. Serialized response size has an explicit ceiling checked with a bounded writer before HTTP success.

`src/evidence_library.rs` adds one authenticated action using the existing Host/Origin/token and no-store boundary. New coordinates are decimal strings; no generic serde serialization of u64-rich internal structs. A cancellation token is owned by a drop guard around a bounded worker. Network futures are borrowed/cancellable; synchronous work polls the token and deadline. Runtime worker count is bounded by existing connection admission, with no detached infinite queue.

The UI adds checkboxes beside occurrence navigation, a selection count and an Interpret selection control with explicit format choice. Selection belongs to exactly one snapshot and is cleared on refresh/scope change. The Content panel lists returned attempt groups and readable items, including gaps and protocol issues. An item's source citation uses the same authorized Source request and can return to the same item; no browser-supplied CID is an access path. Keep provider claims visually distinct from authenticated writer provenance. All content uses text nodes; attachment URLs are inert descriptors.

This document is an integration plan. Physical recovery jobs and proof-aware unavailable inventory must still be connected before damaged archives can be browsed through the same UI; a generic network failure must not be relabeled Missing. Search/facets, annotations, saved views, broader session discovery, analysis/day and owner administration remain required roadmap items.

## Open Questions
No new preference is needed. Any implementation finding that requires changing permission or retention semantics returns to the governing design.

## Out of Scope
This checkpoint does not infer cross-request session identity, scan the archive for matching text, maintain a persistent plaintext projection, activate recovery writers or perform deployment/live migration.

## Recording
Continues `.design/kan-v2-session-reconstruction.md`, `.design/kan-v2-provider-interpretation.md` and the full human frontend contract. Git-first recording under day#168/kan#197; no claimed live-log read or invented witness. Parent acceptance remains open until real implementation, browser evidence and fresh review exist.
