# Feature: evidence contract review corrections

## Summary

Close the first P2 cold review's blocking byte/link confusion before extending storage. The reviewed baseline is 540cabe (code equivalent to 3f8ce6a). Existing v1 codecs and stored data are unchanged. No production service or migration readiness is claimed.

## Requirements

- REQ-1: Preserve CBOR byte strings independently of their contents; only tag 42 creates links. Reject malformed framing before allocating from declared lengths. (F1)
- REQ-2: Make the independent Python value model distinguish maps, bytes and links; define and test the general CID profile, including unsupported records. (F2/F3)
- REQ-3: Expose stable canonical/schema error classes; pin scalar, identity, exact-size and inventory decision vectors and execute regression negative controls. (F4/F5/F7)
- REQ-4: Clarify snapshot and parent coverage limits without claiming authenticated service behavior. (F6/F8)

## Acceptance Criteria

- [x] AC-1: Python and Rust accept CID-shaped byte strings in every opaque field and retain exact bytes, while malformed tagged values and trailing/nonminimal CID bytes fail. Reverting the Rust decoding fix fails a new regression test. (REQ-1, REQ-2)
- [x] AC-2: Both independently reject canonical-invalid fixtures with the same class; schema validation remains Rust's explicit responsibility. Invalid observer/writer/issuer, unknown-record unsafe scalars, and valid records at and beyond 65536 bytes are covered. (REQ-3)
- [x] AC-3: Pinned inventory/operation vectors exercise withholding, mismatched/unknown coverage, unsupported evidence and conflicts independently of display trust; these remain pure models. (REQ-3)
- [x] AC-4: RFC distinguishes a scope snapshot from a single writer manifest; parent dependencies and first review disposition are recorded. Fresh Claude Code claude-opus-5-5 review judges this exact round. (REQ-4)

## Architecture

`src/evidence.rs` owns decoding; `scripts/evidence_reference.py` is the independent oracle; `tests/evidence_contract.rs` consumes pinned vectors. `src/identity/authorship.rs` supplies existing Author validation.

Use a small bounded CBOR parser for the experimental codec, retaining the existing dependency's IPLD value, CID and encoder. Parse type tags directly, enforce shortest headers, UTF-8, map ordering, exact CID consumption and depth before constructing values. Maximum encoded input is 64 KiB; counts must fit remaining bytes and allocation grows only with consumed input. The dependency's generic IPLD visitor is unsuitable because it guesses link identity from ordinary bytes.

Python uses native bytes and a distinct Link type internally. JSON fixture sentinels are only an explicit input/output conversion, with an escaped map form for literal sentinel-shaped maps. General links accept canonical CIDv0 SHA2-256 and CIDv1 with unsigned minimal varints and at most 64 digest bytes; field-specific record/ciphertext profiles remain narrower and RFC 1 author validation remains authoritative. Canonical errors cover framing, scalar and resource constraints; schema errors cover envelope and known-kind fields.

This round does not implement P3 performance recovery or P5 preflight corrections. Those remain separately tracked dependent changes. Day recording remains unavailable because of the known partial-trust read failure; versioned evidence is retained without fabricated claim CIDs.

## Local validation before cold review

2026-10-16: Python reports 18 positive / 46 negative records plus 12 inventory and six operation examples. Seven Rust evidence tests pass. `scripts/evidence_negative_controls.py` restores the original dependency decoder and separately removes decode scalar, writer/issuer and byte-size checks: all four mutants execute the seven-test suite and fail; restored source passes. Logs are retained privately in `.local-state/reviews/contract-fix-negative-controls.log`.

The day repository's `scripts/revert-demo.py` now delegates to an xtask which selects default-feature tests and has no feature argument; kan has no such script. It cannot execute this feature-gated suite unchanged. The committed negative-control runner is the executable equivalent, and this round does not claim a trailer produced by that unavailable workflow. The canonical re-encoding equality check is defense in depth: the new strict parser independently rejects noncanonical framing, so removing equality alone is no longer expected to fail.

Feature Clippy with warnings denied, format, diff whitespace, and citation/RFC/URI/Lexicon checks pass. Fresh independent review is still pending. The first day design check found missing file references in Architecture; explicit references were added. Day recording remains unverified due to the known withheld-claim condition; no design CID is asserted.

## Round 3: Author boundary and executable evidence

Round 2 reviewed 540cabe..5559796 with Claude Code `claude-opus-5-5`, session 781d005a-4bac-41b2-94eb-ab2d4d7d2096, and returned REDIRECT. Its inferred M1 identifies a second generic-visitor path: RFC 1 Author deserialization reads identityVersion.value as IPLD. This round will reproduce that path before replacing it with construction of the existing typed IdentityVersion/Author from the strictly decoded value. Existing v1 callers remain unchanged.

AC-1 additionally requires did:web and did:kan identity-state byte-vs-link negative vectors for observer/writer/issuer, and an old-Author-path negative control. AC-2 additionally requires Python optimized mode to fail explicitly before any mutation/testing claim; type-sensitive oracle comparisons must distinguish bool, int and float. Receipt opaque-field and nested unknown-byte vectors close the coverage wording gap. These address round-2 M1 and L1–L3; they require another fresh review.

The round-2 reviewer independently ran both builds, seven feature tests, the full default suite, both lints, format and citation checks successfully. Ad-hoc probes were denied by its tool policy, so M1 was explicitly inferred. Private teloi and previous reports were excluded after automatic approval review rejected sending those private inputs; the successful review used published repository source only and disclosed that limitation.

Round-3 local evidence: the new did:web observer byte-state fixture was accepted by the old Author path, reproducing M1 (test exit 101). After typed construction, 27 positive and 58 negative vectors and all seven tests pass. All five negative controls fail under the broken behavior and pass after restoration, including restoration of the old Author decoder. Both scripts explicitly refuse `python3 -O` before mutation or success output. Type-sensitive comparison rejects a pinned bool-to-integer substitution. Python now also confirms schema-invalid vectors remain canonical. Feature Clippy, formatting and whitespace checks pass; the fresh round-3 verdict remains pending.

## Current review outcome

Fresh Claude Code `claude-opus-5-5` round 3 returned **APPROVE WITH FOLLOW-UPS** for 5559796..bc24e2b. Session: `83cc0d29-0542-4af0-b0c0-bd8e02ff822e`. The unedited local report is `.local-state/reviews/contract-round-3-report.md`, SHA-256 `6a4586669484e7b22e16f99f4c5fc943738289f7d28be96b112d6c47df5ad521`. Model identity is confirmed by the CLI init and final model-usage metadata. This documentation update changes no reviewed implementation.

The reviewer independently passed feature/default builds, the seven feature tests, 27/58 Python vectors, the full default suite, both lints, formatting and whitespace checks. It executed the oracle's optimized-mode refusal. Scratch probes and environment-prefixed shell commands were denied by its tool policy; negative-control execution was excluded because that runner mutates tracked source. The author's five negative controls and both optimized-mode refusals are separately recorded above, not misrepresented as independent execution. Private teloi were excluded; the review measured the published design and disclosed the limitation.

Nonblocking follow-ups: add complete-CID (no trailing padding) opaque-field fixtures in the next conformance round; enforce RFC 1's method-specific identity-state CID/text profiles at P4 admission, with explicit negative fixtures before production use. Current Author validation is syntactic and does not establish those resolver profiles, signature validity or authority. This does not waive the RFC 1 requirement or change v1 behavior. The storage branch has now made the typed Python API adaptation and is under its own fresh review. Broader P2 parent requirements remain partial as documented in the buildout plan.
