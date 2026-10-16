# Feature: evidence contract review corrections

## Summary

Close the first P2 cold review's blocking byte/link confusion before extending storage. The reviewed baseline is 540cabe (code equivalent to 3f8ce6a). Existing v1 codecs and stored data are unchanged. No production service or migration readiness is claimed.

## Requirements

- REQ-1: Preserve CBOR byte strings independently of their contents; only tag 42 creates links. Reject malformed framing before allocating from declared lengths. (F1)
- REQ-2: Make the independent Python value model distinguish maps, bytes and links; define and test the general CID profile, including unsupported records. (F2/F3)
- REQ-3: Expose stable canonical/schema error classes; pin scalar, identity, exact-size and inventory decision vectors and execute regression negative controls. (F4/F5/F7)
- REQ-4: Clarify snapshot and parent coverage limits without claiming authenticated service behavior. (F6/F8)

## Acceptance Criteria

- [ ] AC-1: Python and Rust accept CID-shaped byte strings in every opaque field and retain exact bytes, while malformed tagged values and trailing/nonminimal CID bytes fail. Reverting the Rust decoding fix fails a new regression test. (REQ-1, REQ-2)
- [ ] AC-2: Both independently reject canonical-invalid fixtures with the same class; schema validation remains Rust's explicit responsibility. Invalid observer/writer/issuer, unknown-record unsafe scalars, and valid records at and beyond 65536 bytes are covered. (REQ-3)
- [ ] AC-3: Pinned inventory/operation vectors exercise withholding, mismatched/unknown coverage, unsupported evidence and conflicts independently of display trust; these remain pure models. (REQ-3)
- [ ] AC-4: RFC distinguishes a scope snapshot from a single writer manifest; parent dependencies and first review disposition are recorded. Fresh Claude Code claude-opus-5-5 review judges this exact round. (REQ-4)

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
