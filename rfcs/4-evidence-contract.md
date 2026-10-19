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

### Experimental SQLite durability profile (P3)

The local reference storage engine uses a distinct `archive.sqlite` database with application ID `0x4b563201`, schema version 1, WAL, synchronous FULL, fullfsync and checkpoint_fullfsync. It is authoritative encrypted evidence storage, not the disposable v1 query index. SQLite and its WAL must remain together on a local filesystem; remote clients do not open that file directly. The [SQLite WAL documentation](https://www.sqlite.org/wal.html) specifies commit synchronization under FULL and the local-host constraint. Device/filesystem durability still depends on honoring synchronization; the tests exercise process death, not physical power loss.

The object table maps raw ciphertext CID to exact BLOB (1–4,194,304 bytes). The commits table retains global local sequence, canonical manifest and canonical receipt bytes, plus indexed manifest CID, scope token, writer principal, operation, writer position and previous manifest. Unique constraints bind operation and position within scope/writer. Bindings retain scoped writer/slot to ciphertext, length and first referencing manifest. Those indexed coordinates are checked against canonical records during explicit verification. There is no update/delete API for committed evidence. Unreferenced staged objects are retained.

An immediate transaction validates object bytes and length, slot consistency and the exact current writer frontier before inserting a manifest, its receipt and bindings. Receipt delivery follows successful transaction commit. A lost delivery returns the originally stored receipt on an identical retry; changed operation content conflicts. The implementation is a lower layer: it accepts structurally bound receipt statements and provides no signature/admission claim until P4 supplies the proof profile.

The local snapshot coordinate is `(through, tip)`: the global journal sequence and its exact manifest CID; `(0, null)` is genesis. Bounded pages exclude every sequence above the pinned frontier. This is an internal storage API, not a newly frozen remote encoding. Independent actors still have their own manifest positions.

Backups use the [SQLite online backup API](https://www.sqlite.org/backup.html), finish into a self-contained owner-only destination, and verify hashes, closure, chain, receipt bindings and indexed coordinates. Copying an active main database without its WAL is not backup. A failed or interrupted backup is incomplete, never overwritten or certified by file existence. A local verified backup is not evidence of independent off-machine recovery.

### Payload-independent admission attestation (codec implemented; runtime integration pending)

This extension is a proposal for `.design/kan-v2-evidence-availability.md`.
Schema-1 receipts and manifests remain byte-identical and unsigned as defined
above. No existing binary, endpoint or archive advertises this profile.

An attestation statement is canonical DAG-CBOR exactly
`{v: 1, kind: "service-attestation", body}`. Its closed body contains:

| Field | Value |
|---|---|
| issuer | Static Author with canonical base58btc P-256 did:key, compressed SEC1 public key, exact `principal#fingerprint` method, static/null identity version |
| archiveId | Exactly 32 bytes; immutable destination archive identity |
| scopeToken | Exactly 32 bytes |
| sequence | Global local sequence in 1…2^53−1 |
| manifest, receipt | Exact canonical record CIDs, CIDv1/DAG-CBOR/SHA2-256 |
| previousSequence | sequence − 1 |
| previousManifest | Null at sequence 1; otherwise the immediately preceding manifest CID |
| previousAttestation | Null at sequence 1; otherwise the immediately preceding **statement CID** |
| purpose | Exactly `admitted` or `retained-verified` |
| issuedAt | Unsigned safe Unix milliseconds; no historical/backdated inference |

The complete envelope is canonical DAG-CBOR exactly
`{statement: <canonical statement bytes>, signature: <64 bytes>}`, at most
16,384 bytes including framing. Both nested statement and outer envelope must
pass strict decoding; duplicate/unknown fields, nonminimal integers, trailing
bytes and unsupported versions are errors, not an automatic fallback. Existing
restricted scalar and depth bounds apply. Do not deserialize CID-shaped byte
strings as links. Require the P-256 public key to be a valid curve point and its
DID to reproduce exactly under canonical formatting before signature verification.

The signature input is canonical DAG-CBOR
`{domain: "tools.kan.service.attestation.v1", statement: <statement CID>}`.
Use ECDSA P-256 with SHA-256 and fixed-width big-endian r||s; require 0 < r < n
and 0 < s ≤ n/2. DER, high-S and other algorithms are refused. A valid signature
is not a capability grant: verify against the separately configured issuer and
scope, never a principal selected by the untrusted envelope.

The statement CID is the attestation identity used by the chain. Using it rather
than a signature/envelope hash keeps the identity independent of ECDSA nonce
choice. Preserve exact stored envelope bytes on retries regardless. Verification
requires contiguous sequence and exact preceding manifest **and** statement
commitments, matching configured issuer/archive/scope, and structural binding of the exact receipt
to its manifest. New admission requires the current receipt issuer; an explicit
upgrade preserves the historical receipt issuer and distinguishes the present
verification issuer using `retained-verified`. No signature proves unavailable
original writer bytes independently of the attesting service's prior verification.

The proposed inventory snapshot is `(archiveId, through, tip, attestation)`: through is the
local sequence, tip its manifest CID and attestation its statement CID. Genesis
is `(archiveId, 0, null, null)` only. The attestation coordinate prevents substitution of another
valid receipt/purpose/time statement for an unchanged manifest at the same height.
Pin all four in signed InventorySnapshot/InventoryPage replies and independently
verify metadata chain linkage before exposing rows. Legacy Snapshot/Page/Read
remain unchanged. A reader explicitly configured for `proof-inventory-v1` must
refuse unknown/unsupported profile responses; it must never fall back silently.

The new SQLite profile and atomic proof insertion, upgrade plan, proof-preserving
backup/recovery, RPC framing and reader wiring remain to be implemented and
qualified together. In particular, these vectors do not authorize removing
legacy payload/admission checks. Initial damaged-archive browsing is explicitly
read-only; strict writable store verification remains unchanged. Read-only here
means no authoritative evidence/schema/index mutation. As with RecoveryReader,
SQLite coordination WAL/SHM initialization must be explicitly surface-declared;
no hidden checkpoint or immutable-mode bypass of a live WAL is permitted. Hot
rollback journals or unusable sidecars fail closed; recovery uses a separate copy.

For `admitted`, the exact receipt issuer must equal the configured current service
issuer. For `retained-verified`, the original receipt issuer may differ and is
preserved; the current service issuer signs the upgrade verification on its own
host after verifying the pinned legacy partition and request. One configured
current issuer signs the entire destination chain. The proof does not turn the
historical unsigned receipt into a historical signature.

Fresh copy destinations receive new archiveIds; backup/resume preserve them.
An archiveId does not prevent same-key forks after backup restore. Readers pin
an exact statement tip; the first profile promises neither across-reader
non-equivocation nor persisted monotonicity across refresh/restart.

Inventory pages descend from the authenticated pin. Each first/current statement
CID and manifest match the expected frontier; verifying its metadata/signature
reveals the predecessor that must match the next row. The reader returns bounded
MAC-authenticated continuation/occurrence tokens tied to the original pin,
archive, scope and process instance, only after verification. Restart invalidates
them. They are disposable verification shortcuts, never grants: every page or
source reauthorizes against the service. No unsigned cursor, forward-page splice,
same-height alternate statement or unbounded prefix scan is accepted. Detailed
RPC and cursor framing must receive implementation fixtures before release.

Proposal byte fixtures are in `.design/fixtures/service-attestation-v1.json`,
with `.design/tools/attestation_vectors.py --check` as an independent Python
DAG-CBOR/OpenSSL oracle. The correction includes re-signed, labelled negatives;
public scalars 1 and 2 are synthetic fixture identities only. Rust parity and
runtime admission/availability qualification are separate gates. The original
blocking protocol review is retained in the design review directory.

For proof-profile source reads only, after verifying the current issuer's proof,
retained-verified original request.audience must equal the historical receipt
issuer; admitted still requires the current issuer. Live Read/Append authentication
always checks the current audience. A separate current-audience RetryImported
command may confirm an exact already copied operation: require current writer
append grant, same inner/outer writer, exact stored manifest/proof binding and
retained-verified purpose. It cannot insert or stage data or mint a new proof.
Normal Append never accepts another audience. Its detailed signed framing and
failure fixtures are implementation gates; the legacy profile remains unchanged.

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

P3 fixes the experimental local profile above; physical-power-loss qualification and deployment capacity remain operational work. P4: exact signature envelope and verification purpose, capability delegation, encryption algorithms and key custody/recovery, HTTP and RPC encodings, opaque-token lifecycle, optional metadata-hiding profile. P6: real capture adapter coverage and event vocabulary. These do not prevent synthetic codec conformance but prevent production service claims.

## Implementation status

Experimental pure reference codec and decision models are introduced with this draft under `evidence-contract`. No production path invokes them. The `v2-storage` feature adds an experimental opaque storage engine and local backup verifier. No signature verifier, encryption scheme, network service or migration is implied by that implementation.

## Experimental service request profile

The `v2-service` feature exposes an experimental request profile described in
`.design/kan-v2-service-boundary.md`. It does not change the canonical records
above or claim production payload encryption. Static did:key credentials sign
compact ordered JSON requests under `tools.kan.service.request.v1` followed by
NUL and the SHA-256 of the unsigned request's exact compact JSON bytes. Unknown
or duplicate fields and alternate whitespace/field ordering are rejected. Byte
strings use lowercase hex. The maximum opaque payload is 1 MiB; maximum request
size is twice that plus 4096 bytes. Canonical signed append requests are the
referenced raw objects, including their public routing/authentication metadata.

An append binds scope token, principal, operation ID, writer position,
predecessor and opaque payload. Its one-entry manifest is reconstructed from
those fields and the signed-request object's raw SHA-256 CID. The slot is the
SHA-256 of the 16-byte operation ID. A service-generated receipt uses the existing
receipt record contract. Exact request retransmission reaches the existing
idempotency owner. A new signature serialization is different retained evidence;
clients retain the original signed bytes for retries.

Read requests carry an expiry no more than 300 seconds ahead of service time.
Append requests have null expiry so offline immutable evidence can resume, but
current append authorization is always required. Grants independently allow
append and inventory within one routing partition. Current grants are not
historical admission proofs. No trust-filter argument participates in ingress.

Replies sign `tools.kan.service.reply.v1`, NUL and the SHA-256 of the unsigned
reply's ordered compact JSON. The reply binds the request-byte SHA-256 and the
serving identity; clients pin that identity. This signature is a current serving
assertion, not a retained signature from the original receipt issuer. Receipt
records and original client signatures remain retained. Imported identities and
RFC 1 control histories are not renamed into this service-credential profile.

The built-in HTTP/1 listener is loopback-only and receives POST /v1/rpc with a
bounded body. Client transport permits HTTPS or literal-loopback HTTP, forbids
redirects and ambient proxies, and checks the reply signature. Remote TLS
termination, production custody, signed grant history and provider forwarding
remain outside this experimental profile's qualification.

Requests additionally bind the destination service did:key in an `audience`
field (between scope and principal). Admission compares it with the serving
identity before accessing storage. Retained request verification binds that
same audience to the original receipt issuer. This prevents a signed request
from being redirected to another service identity even if its routing scope and
grants were copied. Restores that must drain old spools retain the service key;
key rotation and audience transition are not implemented by this profile.

## Experimental recipient-encrypted chunk profile

The optional `v2-crypto` implementation uses RFC 9180 base-mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305 through `hpke` 0.14.1. Its KANE v1 framing authenticates the header and routing scope. Recipient public encodings must be canonical field elements; noncanonical equivalents are refused before encryption because HPKE binds the encoded recipient key. Chunks fit the service's 1 MiB payload boundary; this is not a total archive cap.

See `.design/kan-v2-payload-encryption.md` and `src/evidence_crypto.rs` for exact framing, limits and key-compromise implications. This experimental explicit-key profile settles an interoperability slice of P4 only. It does not choose production custody, implement grant history, key rotation or erasure, or enable forwarding/capture. The service stores opaque objects and cannot attest that clients encrypted them. The public-key hash in the header permits cross-scope recipient linkage; metadata obfuscation remains a separate non-default profile.
