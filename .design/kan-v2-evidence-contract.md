# Feature: experimental kan v2 evidence contract

## Summary

Implement the bounded P2 format slice of `.design/kan-v2-buildout.md`: a draft RFC, pure reference codec, independent canonical byte/CID vectors, and inventory/append decision functions. This precedes storage implementation. Enable the reference API only with the `evidence-contract` Cargo feature; default builds expose no new service, persistence path, or claim format. RFC review may still change these experimental bytes.

## Requirements

- REQ-1: Separate private capture provenance from blind-storage manifests and receipts; reuse RFC 1 author and scope identities without changing existing claim bytes or RFC 2 URI semantics.
- REQ-2: Define bounded canonical DAG-CBOR records, identifiers and signing preimages; reject malformed known records and retain canonical unknown records as unsupported, never as validated evidence.
- REQ-3: Compare Rust bytes and identifiers to an independently implemented Python reference with pinned positive and negative vectors, including malformed CBOR and unknown versions.
- REQ-4: Define inventory absence only for an authorized, complete, supported index at the requested snapshot. Consumer trust exclusions must not enter existence or append decisions.
- REQ-5: Bind receipt statements to their exact manifest and distinguish structural conformance from signature verification, admission, durable commit, backup and decryption.
- REQ-6: Preserve a bounded implementation and review sequence: no production persistence until P3 and no production cryptographic profile until P4 resolves key custody.

## Acceptance Criteria

The checked criteria below have local executable evidence listed after the criteria. They prove only the pure contract boundary; CI and independent review remain separate.

- [x] AC-1: The fixture suite accepts capture, manifest and receipt records, preserves RFC 1 identity bytes, and rejects private capture fields in manifest envelopes. (REQ-1)
- [x] AC-2: Canonical byte vectors, CID vectors and signing preimages agree in Python and Rust; noncanonical, oversized, invalid-field and invalid-chain-shape records fail; unknown canonical versions remain byte-identical unsupported records. (REQ-2, REQ-3)
- [x] AC-3: Inventory tests exercise present, absent-at-snapshot, incomplete and access-limited; a requested/covered snapshot mismatch cannot prove absence. Append decisions depend on admission and operation commitment, never a display trust filter. (REQ-4)
- [x] AC-4: Receipt binding tests reject a changed manifest, operation, scope token or position. Neither decode nor binding returns a cryptographically verified or durably committed value. (REQ-5)
- [x] AC-5: Default build and legacy claim tests pass; the experimental feature tests and independent oracle are configured in CI. No mutation site or surface catalog row is added because all new library operations are pure. (REQ-1, REQ-6)

Local evidence, 2026-10-16:

- AC-1/2: `tests/evidence_contract.rs::independent_canonical_cid_and_signing_vectors`, `tests/evidence_contract.rs::malformed_known_records_never_fall_back_to_unsupported`, and `tests/evidence_contract.rs::byte_depth_and_allocation_bounds` pass. `python3 scripts/evidence_reference.py --check` reports 8 positive and 38 negative vectors and a passing corrupted-CID self-test. The Python decoder independently checks canonical-invalid vectors; schema-invalid vectors are rejected by Rust, not independently schema-validated by Python.
- AC-3: `tests/evidence_contract.rs::inventory_distinguishes_absence_withholding_and_incomplete_coverage` and `tests/evidence_contract.rs::retry_decisions_do_not_depend_on_view_trust_or_subject_existence` pass. These are decision-model tests, not the parent plan's end-to-end append witness; that still requires P3/P4.
- AC-4: `tests/evidence_contract.rs::receipts_bind_all_manifest_coordinates_but_do_not_prove_durability` passes. The API exposes structural records, no verified-signature or committed-receipt type.
- AC-5: `cargo test --lib --test surface_conformance --test claim_v2_codec` passes 51 library, 19 surface and 11 claim-codec tests without the feature. `cargo test --features evidence-contract --test evidence_contract` passes six tests. `.github/workflows/ci.yml` adds the independent oracle, feature test, feature lint and all-feature MSRV compilation; remote CI success is not inferred from this configuration.
- `cargo clippy --features evidence-contract --lib --test evidence_contract -- -D warnings`, formatting, citation self-tests and RFC/URI/Lexicon checks pass locally.

Day validation is run from the main checkout because day refuses a worktree without its own kan workspace. It reports six requirements and five criteria, with two path warnings because it resolves new worktree files against the main checkout; both files exist here. Recording still fails on the two unrelated excluded claims, so no claim CIDs or bridge completion are asserted. This serves the existing raw-data-first continuity target; it does not invent telos witnesses. The graph reports `atom/generative-build` after design.

## Architecture

The extension is proposed in `rfcs/4-evidence-contract.md`, separate from `rfcs/1-identity-system.md` and `rfcs/2-kan-uri-scheme.md`. It does not amend shipped formats by implication. `src/identity/authorship.rs` supplies author validation, `src/identity/scope_inception.rs` supplies scope validation, and `src/cid.rs` supplies the existing CID recipe. The new reference codec belongs in `src/evidence.rs`; its API accepts IPLD values so the normative schema remains explicit without installing an application model prematurely.

Private captures name observable events, source order, parent evidence, coverage and payload descriptors. Manifests carry opaque ciphertext references only; their author and timing/size exposure is allowed under the selected personal-instance metadata default. Receipt bodies name exactly one manifest. Each record has a distinct domain-separated signing preimage. Signatures and encryption wrappers are outside this slice: an `Author` is an attribution claim, not proof that its principal signed anything.

Inventory evaluation is a pure model over an authorized scope, a requested snapshot, an indexed snapshot and explicit completeness. Append admission is a separate pure model over authorization and an operation's existing commitment. P3 must supply transactions, a durable idempotency index, chain/frontier validation, object reachability and crash tests before these models describe a running store. P4 supplies authenticated authorization and private inventory projection. A caller-provided boolean is never a substitute for those checks.

The independent Python oracle uses only its standard library, encodes and decodes a restricted DAG-CBOR subset and derives CIDs directly from bytes. Checked-in fixtures are reviewed artifacts; normal verification never rewrites them. Rust compares against those exact bytes, including negative vectors. The 64 KiB record bound concerns metadata envelopes, not payloads: raw content is external chunked evidence and has no inherited 10 MB event cap.

## Resolved Questions

- This is a feature-gated experimental contract implementation, not acceptance of RFC 4 or completion of the storage MVP.
- Logical capture identity is separate from transport retry identity. Plaintext hashes and logical capture CIDs never appear in the blind manifest.
- Rich operational metadata remains the default. Stronger metadata obfuscation requires a later transport profile; this slice does not claim to implement it.
- The known day recorder partial-trust limitation must remain visible; it does not prevent versioned design work or authorize editing trust to bypass the recorder.

## Open Questions

The inherited key-custody, real harness/provider and generated-status trust choices remain open in `.design/kan-v2-server-first.md`. They first gate later slices. No additional product decision is required for these synthetic pure format fixtures. RFC 4 remains subject to review; implementation does not settle its acceptance.

## Out of Scope

- Durable storage, ingress API, actual signatures, encryption, key recovery, network forwarding, backup, erasure, migration execution and process extraction.
- Production URI or Lexicon registration and changes to legacy claims or the fold.
- A claim that pure inventory tests reproduce an authenticated, persisted end-to-end service.
