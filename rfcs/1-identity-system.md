# RFC 1: Principal, repository, and delegated identity

- Status: Draft
- Authors: kan maintainers
- Created: 2026-08-14
- Discussion: To be assigned when the proposal pull request opens
- Review-period-ends: Not started
- Review-override: None
- Supersedes: Identity architecture in ADRs 4, 24, 25, 55, 58, 61, 65-68, 75, 77, 83, 84, and 86-88 where this RFC conflicts
- Superseded-by: None

## Summary

This RFC separates stable principals from their verification methods,
repositories from speaking actors, authentic speech from repository admission,
and repository admission from consumer trust. It defines an offline-capable
`did:kan` method, content-addressed repository inception, disposable session
agents, purpose-bound verification methods, and attenuating capability
delegation.

The governing posture is **permissive speech, restrictive reach**. Anyone may
submit a cryptographically authentic claim. Repository governance determines
whether that claim was authorized to act within a repository. A consumer then
chooses whether and how the claim participates in a view. These are three
separate results and MUST remain separately visible.

This RFC is the identity input to the later kan URI RFC. It deliberately does
not define URI authorities, repository routing, or acting-user syntax.

## Motivation

kan currently identifies a repository with a signing key and often treats the
key, author, local role, and repository as one operational object. That was a
useful local-first bootstrap, but it cannot cleanly express a human rotating a
device key, one human governing several repositories, a fresh agent identity
per harness session, attenuated subagent authority, external DID principals, or
the difference between an unknown authorization chain and a denied action.

Issue #30 has tracked the need for a real per-agent cryptographic identity
system since the repository-local approach was introduced. The identity system
grew through concrete fixes: repository-local `did:key`
creation, role keys, adoption, keychain protection, seed rooting, and trust
selectors. Those mechanisms preserve released workspaces and remain valuable
compatibility inputs. They are not a sufficient ontology for multi-actor or
multi-substrate operation.

This RFC therefore makes a structural break while preserving historical bytes:
new records use stable principals and explicit verification methods;
repositories become governed scopes; agent lineage, role naming, and authority
become independent signed records; and legacy authorship remains readable
without being rewritten.

## Terminology

- **Principal:** A stable entity identified by a DID and capable of controlling
  verification methods. A person, organization, or session agent may be a
  principal.
- **Verification method:** A named public key, external signer, or equivalent
  method authorized by a principal for one or more purposes.
- **Verification purpose:** One of `recovery`, `administration`,
  `authentication`, `assertion`, `capabilityInvocation`, or
  `capabilityDelegation`.
- **Identity event:** A content-addressed `did:kan` genesis, administration, or
  recovery event. It is a lower-level sibling of a claim, not a claim.
- **Repository scope:** A content-addressed repository inception identifier and
  its governance history. A repository is not a principal.
- **Governance root:** A principal authorized by repository inception or a
  later governance event to administer repository authority.
- **Capability:** An authorization for a principal to perform named operations
  within constrained repository, subject, and time scopes.
- **Delegation:** A signed record transferring a strict subset of a capability
  to another principal.
- **Session agent:** A normally disposable principal created for one harness
  session, usually represented by a fresh `did:key`.
- **Lineage:** A signed assertion that one principal created or invoked another.
  Lineage conveys provenance, not authority.
- **Role:** A repository-local human-readable name or relationship. A role is
  neither a principal nor an implicit capability.
- **Cryptographic validity:** Whether signed bytes, the named verification
  method, and its authorization at the relevant identity state are valid.
- **Repository admission:** Whether governance and capability evidence
  authorized the act within the repository.
- **View trust:** A consumer's fold-time decision to include, exclude, or weight
  authentic material.
- **Known history:** The identity, governance, and delegation events available
  to a resolver. Missing history is distinct from negative evidence.

Normative integer and byte-string notation below describes the DAG-CBOR data
model. Diagnostic JSON in reference vectors is not a wire encoding.

## Detailed design

### Common event envelope

Identity and repository-control events reuse kan's append-only storage, CID,
and canonical DAG-CBOR machinery but have dedicated bootstrap validators. Every
event is encoded as this map:

```text
ControlEvent {
  "v":       unsigned integer,             // exactly 1
  "domain":  text,
  "type":    text,
  "payload": map,
  "proofs":  [Proof, ...]                  // non-empty
}

Proof {
  "method": text,                          // verification-method DID URL
  "alg":    text,                          // algorithm identifier
  "sig":    bytes
}
```

The signed message is the canonical DAG-CBOR encoding of:

```text
SigningInput {
  "v":       1,
  "domain":  ControlEvent.domain,
  "type":    ControlEvent.type,
  "payload": ControlEvent.payload
}
```

Proofs are detached from the signing input. The domain string is mandatory
domain separation; a signature valid for one event family MUST NOT authorize
another. Proofs MUST be sorted lexicographically by their canonical `method`
bytes, then `alg`, then `sig`. Duplicate `(method, alg)` pairs are invalid.

Initial algorithm identifiers are:

- `Ed25519`: a 32-byte public key and 64-byte signature;
- `P256`: a compressed SEC1 public key and fixed-width 64-byte `r || s`
  signature, with low-S normalization required.

Implementations MUST reject unknown algorithms for verification while
preserving the event bytes and reporting `unsupported`, not `invalid`.

### Principal and method references

A principal reference is a canonical DID string. Implementations MUST initially
resolve `did:key`, `did:kan`, `did:plc`, and `did:web`. Unknown DID methods MUST
round-trip unchanged.

A verification-method reference is an absolute DID URL with a non-empty
fragment. Relative fragments are forbidden on the wire. A method entry is:

```text
VerificationMethod {
  "id":         text,                       // absolute DID URL
  "controller": text,                       // canonical DID
  "alg":        text,
  "publicKey":  bytes,
  "purposes":   [text, ...]
}
```

Purposes MUST be unique and sorted by UTF-8 byte order. Methods MUST be unique
by `id` and sorted by `id`. A key MAY occupy several purposes, but authorization
checks MUST test the requested purpose rather than infer one purpose from
another.

### `did:kan` genesis and identifier

The unsigned genesis payload is:

```text
DidKanGenesis {
  "v":                         1,
  "nonce":                     bytes,        // exactly 32 bytes
  "recoveryControllers":       [text, ...],
  "administrationControllers": [text, ...],
  "verificationMethods":       [VerificationMethod, ...],
  "services":                  [Service, ...]
}

Service {
  "id":       text,                         // absolute DID URL
  "type":     text,
  "endpoint": text
}
```

The payload domain is `kan.did.genesis.v1` and event type is `genesis`.
Controller lists MUST be non-empty, duplicate-free, and sorted by canonical DID
bytes. Services MUST be unique by `id` and sorted by `id`.

Genesis recovery controllers MUST be `did:key` principals whose public keys are
self-certifying. At least one genesis proof MUST be produced by a recovery
controller and use a method committed by that controller's DID. This provides
offline bootstrap without requiring another DID resolver.

Let `G` be the canonical DAG-CBOR bytes of the unsigned `DidKanGenesis` payload.
Let `H` be the SHA-256 multihash of `G`, including multihash code `0x12` and
length `0x20`. The identifier is:

```text
did:kan:<base32-lower-no-pad-multibase(H)>
```

The multibase prefix is `b`. Uppercase encodings, padding, shortened hashes,
and alternate multibases are non-canonical and MUST be rejected rather than
normalized. Proofs do not contribute to `G`; changing only a proof therefore
does not change the DID.

The complete proved event is encoded as `ControlEvent` with domain
`kan.did.genesis.v1`. Its CID is CIDv1 with codec `dag-cbor` and SHA-256 over the
complete canonical event bytes. The DID and genesis event CID are distinct.

### `did:kan` update events

Every non-genesis identity payload contains:

```text
DidKanUpdate {
  "v":          1,
  "did":        text,
  "previous":   CID,
  "sequence":   unsigned integer,
  "operations": [IdentityOperation, ...],
  "supersedes": [CID, ...]
}
```

The domain is `kan.did.update.v1`. `previous` names the exact event being
continued. `sequence` MUST equal the predecessor sequence plus one, with
genesis treated as sequence zero. Operations are applied in listed order and
MUST NOT produce duplicate method or service identifiers.

Administration proofs authorize ordinary changes to administration
controllers, verification methods, purposes, and services. They may extend
only the unique uncontested current head. Recovery proofs may continue from any
recognized historical event, repair controller state, and name one or more
heads in `supersedes`. Recovery authorization is evaluated at the selected
historical event, not at a possibly hostile descendant.

Two valid sibling updates form a fork. A resolver MUST retain both and return
`contested`; it MUST NOT choose by timestamp, sequence tie-breaking,
lexicographic CID order, first observation, or storage order. An authorized
recovery update resolves a fork only when its `supersedes` set includes every
known competing head it intends to retire. Superseded branches remain part of
history.

Profile data—including names, handles, avatars, biographies, repository roles,
and human identity assertions—is forbidden in identity operations. It belongs
in ordinary signed claims.

### System identity state

The platform configuration directory MUST separate:

```text
identity/ledger/   authoritative public histories controlled by this installation
identity/cache/    disposable verified histories fetched for other principals
identity profiles local aliases, defaults, resolver and credential references
credentials        private material or references to credential providers
repositories       repository routing and substrate connections
```

`identity/ledger/` MAY itself contain a `.kan/` append-only substrate. It MUST
NOT contain private keys. Removing `identity/cache/` MUST NOT remove locally
authoritative history, profiles, or credentials.

Initial setup creates or imports a system-level human principal, enrolls a
daily device method, stores its secret in an explicit credential provider, and
selects a default actor. Credential providers include OS keychains, owner-only
files, hardware keys, agent sockets, and external signers. A profile points to
a provider; it does not require key export.

### Repository inception and governance

A repository is identified by this unsigned payload:

```text
RepositoryInception {
  "v":               1,
  "nonce":           bytes,                 // exactly 32 bytes
  "names":           [text, ...],
  "governanceRoots": [text, ...],           // principal DIDs
  "anchors":         [SubstrateAnchor, ...]
}

SubstrateAnchor {
  "type":  text,
  "value": bytes or text
}
```

The domain is `kan.repository.inception.v1`. Lists are duplicate-free and
sorted by canonical encoded value. At least one governance root is required.
The repository identifier is the base32-lower-no-pad multibase SHA-256
multihash of the canonical unsigned payload, prefixed `kan-repo:`. It is not a
DID and cannot author claims.

`kan init` deliberately creates inception. It defaults the governance root and
current actor to the configured system principal but permits explicit
alternatives. Git genesis may be an anchor; it is not the repository identity.
Changing the current actor does not change inception or governance.

Governance changes are signed control records rooted in inception. Governance
and required delegations MUST be publishable over every claim substrate. If a
reader lacks history needed to decide admission, it MUST report `unknown`; it
MUST NOT infer `unadmitted` from absence.

### Session agents, lineage, roles, and delegation

A harness SHOULD create a fresh `did:key` for every agent session because the
session context individuates the actor. It MAY use another DID method when
persistence or rotation is intended.

The following are separate signed records:

1. lineage: principal X created or invoked principal Y;
2. role naming: repository R names Y with local role A;
3. delegation: X grants Y capability C.

Neither lineage nor role naming grants authority. A parent may create or name a
child without possessing authority to delegate. The child's authentic claims
are admitted only through a valid capability path.

A capability contains:

```text
Capability {
  "repository":    text,                    // kan-repo identifier
  "subjectPrefix": text or null,
  "operations":    [text, ...],
  "notBefore":     signed integer or null,  // Unix microseconds
  "notAfter":      signed integer or null,
  "delegable":     boolean
}
```

A delegation names its parent capability or repository governance root,
delegate, capability, issuance event, and revocation identifier. Every child
capability MUST be a subset of its parent:

- repository is identical;
- subject prefix is equal or more specific;
- operations are a subset;
- time interval is equal or narrower;
- delegation is permitted by the parent.

No union of several parent capabilities may create authority that no single
valid path grants. Revocation and expiry prevent later admission but do not
erase signer identity, signature validity, or the historical evidence under
which an earlier claim was admitted.

Day may package roles, process atoms, harnesses, models, and capabilities. kan
owns the signed principal, lineage, role, delegation, and evaluation primitives.

### Claim authorship

New claims identify both:

```text
Author {
  "principal":          text,               // canonical DID
  "verificationMethod": text                // absolute DID URL
}
```

Verification establishes that the method signature is valid and that the
principal authorized the method for `assertion` at the identity event relevant
to the claim. The repository identifier is a separate scope field. A role name
MUST NOT appear in `Author`.

### Three independent judgments

Every structured read of a claim MUST disclose:

```text
cryptographicValidity = valid | invalid | unsupported | unknown
repositoryAdmission   = admitted | unadmitted | unknown | not-applicable
viewTrust              = included | excluded | weighted
```

An invalid signature is not authentic speech. An authentic but unadmitted or
view-excluded claim remains inspectable. Storage policy may refuse an object
operationally but MUST NOT redefine these semantic results.

## Canonicalization and equivalence

All control payloads and events use deterministic DAG-CBOR. Text MUST be valid
Unicode and MUST NOT be normalized implicitly; producers SHOULD emit NFC, and
distinct UTF-8 strings remain distinct identifiers unless their defining
scheme says otherwise. Map keys are exactly the strings specified here; unknown
fields are preserved but make a version-1 control event unsupported for state
transition until understood.

Sets represented as arrays have the sorting and uniqueness rules stated above.
Order-sensitive operation arrays are not sets and are never reordered.

DIDs are canonical according to their DID method. A `did:kan` has exactly one
canonical textual representation. Repository identifiers likewise have one
canonical representation. Equality of principals is DID equality after
method-specific canonicalization; repository-local roles, profile aliases, and
`SameAs` claims do not change cryptographic principal equality.

CID computation uses the exact canonical bytes. A decoder that accepts a
non-canonical representation MUST re-encode and compare before treating those
bytes as a canonical control event.

## Resolution or processing algorithm

To verify and evaluate a claim:

1. Decode without discarding unknown bytes or fields. Reject malformed or
   non-canonical encoding as cryptographically invalid input.
2. Resolve the author's principal history and exact verification method at the
   claim's cited identity state. Missing history yields validity `unknown`;
   unsupported DID methods or algorithms yield `unsupported`.
3. Verify the signature and the method's `assertion` purpose. Failure yields
   `invalid`; success yields `valid`.
4. Resolve repository inception and governance. Missing required evidence
   yields admission `unknown`.
5. Find a governance-rooted capability path covering the author, operation,
   repository, subject, and evaluation time. Check every edge for signature,
   purpose, attenuation, expiry, and revocation. No valid path yields
   `unadmitted`; a valid path yields `admitted`.
6. Apply the consumer's trust frame independently to authentic material and
   report `included`, `excluded`, or its explicit weight.
7. Preserve the claim and all evidence regardless of admission or view result.

To resolve `did:kan`, verify genesis derivation and proof, collect every valid
reachable update, retain forks, apply unique-head administrative histories,
and apply an authorized recovery selection when present. Return the resolved
document, `contested`, `unknown-history`, `unsupported`, or `invalid` without
collapsing those states.

Default identity resolution is read-only. It MUST NOT select a signing key,
mint a key, update a profile, change governance, grant admission, or alter the
view trust frame.

## Authority and trust model

Authoritative inputs are deliberately plural:

- identity genesis and authorized identity events establish principal control;
- repository inception and governance events establish repository authority;
- delegation and revocation records establish admitted reach;
- claim bytes and proofs establish authentic speech;
- the consumer supplies view trust at fold time;
- system configuration selects local profiles, credential providers,
  repository routing, and substrate connections without becoming shared truth.

The local append-only log and published GitTree claims are both authoritative
kan claim substrates with different configured connections. Git data unrelated
to kan is authoritative external input. Caches, indexes, resolved views, and
externally enriched appraisal data are derived or auxiliary and MUST NOT become
silent authorities.

No substrate is trusted merely because it delivered bytes. Every object is
verified from its content address, proof, and applicable authority history.

## Security considerations

- **Key confusion:** Principal and exact verification method are both signed;
  purpose checks prevent an authentication-only key from asserting claims.
- **Repository impersonation:** Randomized content-addressed inception prevents
  a path, Git remote, or mutable name from defining repository identity.
- **Fork choice attacks:** Observation order and timestamps never select a
  `did:kan` branch. Unresolved forks are visible as contested.
- **Recovery capture:** Recovery authorization is checked at the selected
  historical state, allowing repair after administrative compromise while
  keeping all branches auditable.
- **Delegation amplification:** Every edge is checked for strict attenuation;
  roles and lineage grant nothing.
- **Revocation rewriting history:** Revocation affects admission at defined
  boundaries and never changes historical signature validity.
- **Cache authority:** Deleting or corrupting `identity/cache/` may reduce
  availability to `unknown`; it cannot change authoritative local history or
  silently produce denial.
- **Secret leakage:** Identity ledgers and control events contain no private
  keys or profile PII. Credential providers are separate local state.
- **Identifier ambiguity:** `did:kan` and `kan-repo:` reject alternate textual
  encodings. Unknown DID methods remain unsupported rather than misclassified.
- **Implicit action:** Dereferencing and resolution are read-only. Signing and
  trust selection require explicit inputs outside an identifier.

## Compatibility

Existing repository-local `did:key` values remain valid static principals.
Existing claim bytes, CIDs, signatures, and `AuthorId.agent` values MUST NOT be
rewritten. Readers retain a compatibility projection that displays and verifies
historical composite authorship. New writes MUST use principal plus
verification method and MUST NOT emit `AuthorId.agent`.

Existing `RoleDeclaration` claims remain naming evidence and do not become
retroactive capabilities. `KAN_IDENTITY_FILE`, `.kan/seed`, keychain pointers,
and registered role keys become legacy credential/profile inputs; none defines
the repository or human principal under this RFC.

Migration may record a witnessed continuity assertion between a chosen stable
human principal and a legacy repository DID, then establish that principal as a
repository governance root. It MUST NOT fabricate new authorship for old
claims. A mixed workspace may contain legacy and RFC-1 records indefinitely.

## Alternatives considered

- **Repository as principal:** Rejected because one signing key cannot cleanly
  represent governance, human continuity, device rotation, and session agents.
- **Require ATProto identity:** Rejected because offline bootstrap and users
  without ATProto accounts are first-class requirements.
- **Use only `did:key`:** Rejected because static self-certifying keys lack
  rotation, recovery, and contested-history semantics.
- **Make identity events ordinary claims:** Rejected because claim validation
  already requires the author and assertion authority that genesis establishes.
- **Treat roles as principals or capabilities:** Rejected because names,
  provenance, and reach have different authorities and lifecycles.
- **Select forks by time or CID:** Rejected because neither is evidence of
  authorized control.
- **Combine validity, admission, and trust:** Rejected because absence of
  governance evidence, lack of authorization, and consumer exclusion are
  materially different facts.
- **Choose UCAN as the wire format now:** Deferred. UCAN is relevant prior art,
  but this RFC fixes kan's required capability semantics before selecting or
  profiling a transport format.

## Reference test vectors

Normative vectors will live under `tests/fixtures/identity-v1/`. The manifest is
created only when every entry contains complete input bytes and expected
outputs; an empty or placeholder manifest would falsely satisfy the identity
telos witness.

The vector set MUST cover:

1. repository inception and single-field identifier changes;
2. `did:kan` genesis bytes, multihash DID, proof, and event CID;
3. proof-only mutation changing event CID but not DID;
4. linear administration, sibling fork, contested resolution, and recovery;
5. verification-purpose acceptance and rejection;
6. valid attenuation and attempted repository, subject, operation, and time
   amplification;
7. revocation and historical admission boundaries;
8. all four initially supported DID methods plus an unsupported method;
9. legacy authorship compatibility without byte rewriting;
10. read-only resolution with no credential, governance, admission, or trust
    side effects.

Each valid vector MUST include diagnostic input, canonical DAG-CBOR hex,
relevant multihash/CID strings, signature bytes, and the expected resolved
state. Invalid vectors MUST identify the exact rule and failure classification.

## Unresolved questions

None.

## Deferred questions

- The final capability wire format or UCAN profile.
- URI syntax, authority matching, repository routing, Git transport inference,
  and identity-resource paths; these belong to RFC 2.
- Hosted-kan, ATProto PDS, relay, archive, and replica protocols.
- Day's packaging of roles, atoms, harnesses, models, and capabilities.
- A graphical or TUI identity-management flow.

## Implementation status

Not implemented. The current implementation remains the compatibility source
described above. Acceptance of this RFC authorizes staged implementation; it
does not mark any behavior shipped.
