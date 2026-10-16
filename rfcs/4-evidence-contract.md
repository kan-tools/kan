# RFC 4: Experimental evidence records and blind storage commitments

- Status: Draft
- Authors: kan contributors
- Created: 2026-10-16
- Discussion: https://github.com/kan-tools/kan/pull/266 (Draft; review has not started)
- Review-period-ends: Not started (Draft)
- Review-override: None
- Supersedes: None
- Superseded-by: None

## Summary

Propose version 1 of a new evidence protocol for the kan v2 service architecture. Define private capture records, public-to-storage ciphertext manifests, receipt statements, signing preimages, inventory states and append decision semantics. The reference implementation is experimental and disabled by default. Protocol version 1 is unrelated to product version 1 and to the existing `kan-claim-v2` codec. No existing format, URI or Lexicon changes.

## Motivation

Raw interaction evidence must survive independently of later interpretation. Blind storage must acknowledge exact ciphertext without learning payload hashes or private provenance. Reader trust filtering must not turn unrelated excluded claims into an inability to append. Stable byte vectors are needed before writing a new storage core; a codec round trip alone cannot prove conformance.

## Terminology

- **Capture**: an observer's private statement about one event, not a provider's attestation.
- **Manifest**: a writer's ordered batch of opaque slots and ciphertext objects for one storage scope token.
- **Receipt**: a service's statement that one manifest was committed remotely; parsing it does not prove this statement.
- **Slot**: random 32-byte transport identity allocated and durably saved by the client before upload. Retry preserves it; re-encryption uses a new slot and operation.
- **Snapshot**: a commitment identifying the complete requested journal frontier and its archive/scope context across all writers. A single per-writer manifest CID is insufficient. The pure model treats its CID argument as an opaque snapshot commitment; it does not construct or authenticate one. P3 supplies a global journal sequence and tip bound to an archive instance; P4 must bind that frontier and authorized scope to a portable snapshot before exposing semantic absence.
- **Complete index**: all evidence through that frontier was inspected by an authorized reader under a supported interpretation. A blind storage index alone cannot establish semantic subject absence.

## Detailed design

### Canonical envelope and primitive types

Every record is exactly `{v, kind, body}`: `v` is a positive safe integer, `kind` is a lowercase ASCII token of 1–64 bytes, and `body` is a map. Version 1 recognizes `capture`, `manifest`, `receipt`. All maps below are closed; every named field is required, including explicit nulls. Maximum encoded record size is 65,536 bytes; maximum container nesting is 32. Within the envelope, only null, booleans, safe integers, byte strings, UTF-8 strings, lists, string-key maps and CID links are allowed. Floats are forbidden even for unsupported records. Safe integers range from zero to 9,007,199,254,740,991. Protocol tokens match `[a-z][a-z0-9.-]*`.

`record-link` is CIDv1, DAG-CBOR codec 0x71, SHA2-256 multihash 0x12 with a 32-byte digest. `ciphertext-link` differs only in raw codec 0x55. CID links use DAG-CBOR tag 42 and its leading zero byte. Text spelling uses base32lower when displayed. The protocol imposes no Unicode normalization; differing strings are differing bytes. `Author` is exactly RFC 1's validated principal, verificationMethod and identityVersion value. `ScopeId` is exactly RFC 1's 34-byte SHA2-256 multihash. Identity-state links inside Author follow RFC 1, not the evidence link constraint. General links (including in unsupported records) permit canonical CIDv0 SHA2-256 or CIDv1 with minimal unsigned 64-bit varints and multihash digests of at most 64 bytes. No trailing bytes are permitted inside a CID. Accepting a general link conveys no support for its codec or hash algorithm. Ordinary CBOR byte strings remain bytes regardless of their contents.

### Private capture body

| Field | Shape and meaning |
|---|---|
| observer | RFC 1 Author |
| scope | RFC 1 ScopeId as bytes |
| stream | 16 random bytes; stable observer session identity |
| sequence | Safe integer; starts at zero per observer principal, scope and stream |
| previous | Null at sequence zero; record-link otherwise |
| occurredAt | Safe integer, observer wall-clock Unix milliseconds; neither trusted nor ordering authority |
| eventType | Protocol token; extensible event vocabulary, unknown tokens remain readable |
| payloads | Ordered list of 0–128 descriptors `{sha256, length, mediaType}`; sha256 is 32 private bytes, length safe integer, mediaType nonempty UTF-8 up to 256 bytes |
| parents | Ordered, duplicate-free list of 0–128 record-links; never fabricate causal edges |
| coverage | Exactly `{complete, missing}`; boolean complete and sorted unique list of up to 128 protocol tokens. Complete requires empty missing; incomplete requires at least one reason |

Occurrence identity is `(observer.principal, scope, stream, sequence)`, independent of content equality. The private record CID commits to the entire statement. A predecessor must match the tuple and sequence minus one; this requires retrieval and is not established by local shape validation. Payload hashes refer to original observed bytes, including unknown binary payloads. Ordered descriptors permit independently stored chunks without limiting the total event to a record envelope. Chunk selection and mapping to encrypted objects live inside the later encryption wrapper, never this blind manifest. Capture records and their signatures are encrypted before storage.

### Blind-storage manifest body

| Field | Shape and meaning |
|---|---|
| writer | RFC 1 Author; exposes writer identity in the personal-instance profile |
| scopeToken | 32 random bytes; opaque namespace, not a hash of a private ScopeId |
| operation | 16 random bytes; persisted retry token |
| position | Safe integer; writer's batch sequence within this scopeToken, starts at zero |
| previous | Null at position zero; record-link otherwise |
| entries | 1–128 `{slot, ciphertext, length}` entries sorted by unique 32-byte slot; ciphertext is ciphertext-link; length is positive safe integer |

`(scopeToken, writer.principal, operation)` is an operation key. Its commitment is the complete manifest CID. Same key and same commitment is a duplicate; same key and different commitment is a conflict. `(scopeToken, writer.principal, slot)` likewise cannot bind different ciphertext or length. A slot may be referenced identically in another batch. Storage verifies that every ciphertext CID hashes the actual object and its length matches. Per-writer frontier validation is a compare-and-append transaction; different writers have distinct frontiers. Receipts refer to this writer position, not a globally allocated server sequence. A storage service may assign its own internal journal order without changing these bytes.

No capture CID, payload hash, event type, subject, private scope or parent evidence link is allowed in the manifest. A manifest can still reveal identity, size, object reuse, batch position and arrival timing. Metadata-hiding transport is a separate profile; this format does not promise it. Signed writers can always leak information in arbitrary bytes, so the closed schema is an honest-client boundary, not covert-channel prevention.

### Receipt body and signatures

Receipt body is exactly `{issuer, manifest, scopeToken, operation, position, durability, issuedAt}`. `issuer` is Author; `manifest` is record-link; scopeToken/operation/position equal the referenced manifest fields; `durability` is the literal `remote-durable`; `issuedAt` is safe Unix milliseconds. The receipt asserts that the complete manifest and all referenced ciphertext survive the service's declared crash durability contract. P3 must define and test this storage contract before issuing real receipts. It does not assert backup completion, decryptability, source authenticity or a complete conversation.

All three kinds sign canonical DAG-CBOR of `{domain: "tools.kan.evidence.v1", kind: record.kind, record: recordCID}`. The record already binds the signer through observer/writer/issuer. These bytes are deliberately distinct from claim signing inputs. This RFC fixes only the preimage, not the signature envelope, verification purpose, delegation/admission rules or encryption profile. P4 must specify them before a real service accepts evidence. A parser's validated Author is not a verified signature. Unsupported records have no version-1 signing preimage.

## Canonicalization and equivalence

Use [DAG-CBOR](https://ipld.io/specs/codecs/dag-cbor/spec/): definite lengths, shortest integer/length encodings, text map keys ordered by encoded length then bytes, tag 42 only for CIDs, and one object without trailing bytes. The restricted scalar set above is additionally enforced. Record CID is CIDv1/DAG-CBOR/SHA2-256 over those exact bytes. No normalization or re-encoding of noncanonical input is accepted. Re-encoding must reproduce input byte for byte. Sorted-set fields reject duplicates and unsorted input rather than rewriting it; ordered fields retain order. Unknown positive versions or kinds are retained byte-exactly as unsupported after envelope/canonical/bounds validation. A malformed known kind is invalid, never relabeled unsupported.

## Resolution or processing algorithm

### Decoding and receipt binding

1. Enforce byte and depth bounds, decode one strict DAG-CBOR object, enforce scalar/envelope rules and canonical equality.
2. For an unknown version or kind, preserve bytes and CID as unsupported; do not project, sign with v1, or admit as a v1 record.
3. For a known kind, validate all closed fields, bounds, identity syntax and local chain shape. Compute CID only from canonical bytes.
4. To bind a receipt, require receipt/manifest kinds and match manifest CID, scopeToken, operation and position. This is structural binding only.
5. Cryptographic verification, admission, full predecessor/slot/object validation and transactional commit are independent later stages; never infer them from step 3 or 4.

### Inventory state table

Inputs are an authenticated reader's access result, requested frontier, covered frontier, index completeness, unsupported-record count and matching private record CIDs. The prototype accepts these as caller assertions; it implements no authentication or indexing.

| Condition, evaluated in order | Result |
|---|---|
| Access not granted | access-limited, with no matches exposed |
| Covered frontier differs from requested, or is unknown | incomplete, with no matches attributed to requested snapshot |
| Matching evidence exists at that frontier | present; complete flag requires full coverage and zero unsupported records |
| No match and full coverage and zero unsupported records | absent-at-snapshot |
| No match and any coverage/interpretation gap | incomplete |

An empty store uses an explicit genesis snapshot supplied by the later storage profile; null coverage always means unknown. Present is positive evidence, not a complete listing unless its flag says so. Signature and consumer-trust projections apply after raw authorized inventory. Trust exclusion counts are intentionally absent from this algorithm.

### Append state table

| Condition, evaluated in order | Decision |
|---|---|
| Writer not admitted | unauthorized, revealing no prior operation commitment |
| Existing operation key, equal commitment | duplicate; retrieve the original durable result, never repeat provider inference |
| Existing operation key, unequal commitment | conflict |
| New key, malformed/unsupported envelope, invalid proof or out-of-scope capability | reject with that distinct cause |
| New key, missing objects, mismatched object bytes, slot conflict, invalid predecessor or stale frontier | reject with that distinct cause; no acknowledgment |
| New key and all checks pass | eligible for atomic commit |
| Commit interrupted before durable boundary | no receipt; retry same operation and reconcile |
| Commit durable, receipt delivery interrupted | same-operation retry recovers original result |

The pure reference helper covers only the first three rows and reports `new-operation` otherwise, never `committed` or `eligible`. Authentication and commitment parsing precede lookup. A duplicate still requires currently valid admission; it need not rerun stale-frontier checks that its own previous commit advanced. Server transactions and receipt recovery belong to P3. No branch asks whether a subject is absent in a trust-filtered view.

## Authority and trust model

The observer, admitted writer and receipt issuer are separate principals. Identity syntax, cryptographic validity, scope capability, index completeness and interpretation trust are separate results. Blind storage knows only manifests, ciphertext and receipt metadata. An authorized decrypting reader supplies semantic inventory. No self-declared writer or issuer is trusted by decoding. The eventual forwarding kernel is a separate plaintext principal and is not implemented here.

## Security considerations

Bounds protect metadata parsing; payload limits, upload quotas and transactional resource accounting belong to ingress. Record links prove content identity, not availability or provenance. Receipt verification must check issuer authority at the pinned identity state and the declared durability profile. Retrying an upload must never trigger an inference request. Hashes of plaintext can expose low-entropy content and must remain private. Even complete source capture can include malicious text: future extraction must treat it as evidence, not operational instructions. Erasure removes accessible payload/key material under the owner's chosen policy while retaining explicit unavailable-evidence records; no deletion mechanism is introduced here.

## Compatibility

RFCs 1–3, existing signed claims, published history and URI resolution remain unchanged. Capture can later reference preserved legacy evidence; this codec does not rewrite or import it. Feature activation is experimental, not a migration. Unknown records survive without false interpretation. The max metadata record size is not the legacy 10 MB whole-store cap and places no fixed upper bound on external event content.

## Alternatives considered

- Put plaintext CIDs into storage manifests: rejected because blind storage then sees guessable content commitments.
- Use display trust filtering for inventory: rejected because unrelated exclusions cannot prove subject absence or justify denying an authorized append.
- One identifier for occurrence, content and retries: rejected because repeated identical events and retransmission have different semantics.
- Prove format correctness only by Rust round trips: rejected because both directions can share an error.
- Issue signed receipts in this slice: deferred until identity purpose, admission and crash durability are executable.

Invalid input exposes two stable codec error classes: `canonical` for framing, resource bounds, scalar restrictions or malformed CID encoding; `schema` for envelope and supported-kind field constraints. These do not stand in for later admission, authorization, storage or transport errors. Python independently checks the canonical class; supported-kind schema validation is Rust-only in this slice.

## Reference test vectors

`tests/fixtures/evidence-v1/vectors.json` pins canonical records, CIDs, signing bytes and invalid inputs. `scripts/evidence_reference.py` independently encodes, decodes and hashes the fixtures using Python's standard library. `tests/evidence_contract.rs` runs the Rust reference against them. Normal checks do not regenerate golden vectors. Explicit regeneration requires review of their diff and both implementations.

## Unresolved questions

RFC review has not accepted the version, bounds or envelope names. These remain experimental until review completes. The number is reserved by the introducing proposal PR; no accepted protocol is claimed by a draft branch.

## Deferred questions

P3: crash/durability profile, journal and genesis/frontier representation, receipt persistence and atomic inventory snapshots. P4: exact signature envelope and verification purpose, capability delegation, encryption algorithms and key custody/recovery, HTTP and RPC encodings, opaque-token lifecycle, optional metadata-hiding profile. P6: real capture adapter coverage and event vocabulary. These do not prevent synthetic codec conformance but prevent production service claims.

## Implementation status

Experimental pure reference codec and decision models are introduced with this draft under `evidence-contract`. No production path invokes them. No storage engine, signature verifier, encryption scheme, network service or migration has been implemented by this RFC.
