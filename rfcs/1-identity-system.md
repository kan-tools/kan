# RFC 1: Principal, repository, and delegated identity

- Status: Review
- Authors: kan maintainers
- Created: 2026-08-14
- Discussion: https://github.com/kan-tools/kan/pull/229
- Review-period-ends: 2026-08-17T07:33:00Z
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
  "method":          text,                 // verification-method DID URL
  "controllerState": IdentityVersion,
  "alg":             text,                 // algorithm identifier
  "sig":             bytes
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
bytes, then canonical `controllerState`, `alg`, and `sig`. Duplicate
`(method, controllerState, alg)` pairs are invalid.
The **logical event identifier** is the CIDv1 (`dag-cbor`, SHA-256) of the
canonical `SigningInput`; the **proved-event CID** is the CIDv1 of the complete
`ControlEvent`. Predecessor, supersession, delegation-parent, and revocation
references name logical event identifiers. Multiple valid proof sets for one
logical event are evidence for the same event, not sibling events and not a
fork. A resolver unions their valid proofs by
`(method, controllerState, alg, sig)`.

Initial algorithm identifiers are:

- `Ed25519`: RFC 8032 pure Ed25519 with a canonical 32-byte public key and
  canonical 64-byte signature; verification MUST reject non-canonical scalar
  encodings and small-order public keys;
- `P256`: a compressed SEC1 public key and fixed-width 64-byte `r || s`
  signature using ECDSA with SHA-256, with low-S normalization required.

Both algorithms sign the exact canonical `SigningInput` bytes; no additional
prehash is applied for Ed25519, while P-256 applies its specified SHA-256 hash.

Implementations MUST reject unknown algorithms for verification while
preserving the event bytes and reporting `unsupported`, not `invalid`.

### Principal and method references

A principal reference is a canonical DID string. Implementations MUST initially
resolve `did:key`, `did:kan`, `did:plc`, and `did:web`. Unknown DID methods MUST
round-trip unchanged.

For v1 `did:key`, only the Ed25519 and P-256 multicodec forms are supported. The
single implicit verification method is the DID plus `#` plus the DID's complete
multibase fingerprint and is authorized for every kan verification purpose.
For any DID controller, a control-event proof is authorized only when
`Proof.method` is controlled by that DID and carries the required purpose in
the controller's resolved state cited by the event. Controller resolution is
recursive; a missing or contested controller state yields `unknown`, and a
cycle with no self-certifying base yields `invalid`.

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

Exact historical state is named without assuming every DID method uses kan
event CIDs:

```text
IdentityVersion {
  "kind":  "static" | "event" | "versionId" | "documentCid",
  "value": CID or text or null
}
```

`did:key` uses `static` with null. `did:kan` uses `event` with a logical event
CID. `did:plc` uses its canonical operation/version identifier. `did:web` uses
`documentCid`, the CIDv1 (`raw`, SHA-256) of the exact resolved DID document
after RFC 8785 JCS canonical JSON encoding; the document bytes or an archive connection
must be available to verify it. A DID method's resolver profile MUST define one
of these stable forms before kan treats the method as historically resolvable.
Otherwise current resolution may be displayed, but historical authorization is
`unsupported` rather than guessed.

### `did:kan` genesis and identifier

The unsigned genesis payload is:

```text
DidKanGenesis {
  "v":                         1,
  "nonce":                     bytes,        // exactly 32 random bytes
  "recoveryEpoch":             0,
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
Every service endpoint is inert text at this layer; resolution MUST NOT
dereference it without a separate explicit operation and transport policy.

Genesis recovery controllers MUST be `did:key` principals whose public keys are
self-certifying. At least one genesis proof MUST be produced by a recovery
controller and use a method committed by that controller's DID. This provides
offline bootstrap without requiring another DID resolver.
Version 1 controller lists use explicit 1-of-N authorization: one valid proof
from any listed controller is sufficient. Threshold policies require a later
protocol version because changing this rule changes event validity.

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
`kan.did.genesis.v1`. Its logical event identifier and proved-event CID are
computed as defined above. The DID, logical genesis event identifier, and each
proved-event CID are distinct values.

### `did:kan` update events

Every non-genesis identity payload contains:

```text
DidKanUpdate {
  "v":              1,
  "did":            text,
  "mode":           "administration" or "recovery",
  "previous":       CID,
  "sequence":       unsigned integer,
  "recoveryParent": CID or null,
  "recoveryEpoch":  unsigned integer,
  "operations":     [IdentityOperation, ...],
  "supersedes":     [CID, ...]
}
```

The domain is `kan.did.update.v1` and event type is `update`. `previous` names the exact event being
continued. `sequence` MUST equal the predecessor sequence plus one, with
genesis treated as sequence zero. `operations` is non-empty and applied in
listed order; it MUST NOT produce duplicate method or service identifiers.
`supersedes` is always present, sorted, and duplicate-free.

An administration event has `recoveryParent: null`, preserves its predecessor's
`recoveryEpoch`, has an empty `supersedes`, and is authorized by a method with
`administration` purpose at `previous`. It may extend any intrinsically valid
parent. Learning about a sibling never changes the event's validity.
Administration may change administration controllers, verification methods,
purposes, and services. It cannot change recovery controllers or epoch.

A recovery event may select any intrinsically valid `previous` in the evidence
graph as its state base. It names as `recoveryParent` either genesis or one
recovery event, sets `recoveryEpoch` to that parent's epoch plus one, and is
authorized by recovery controllers in the resolved state of `recoveryParent`.
It may replace recovery and administration controllers, methods, purposes, and
services. This separates the state being repaired from current recovery
authority: a controller removed by a later recovery epoch cannot regain power
by choosing an older administrative state. Genesis recovery keys remain
auditable but not permanently authoritative.

Event validity is intrinsic to its canonical payload, cited parents, and
proofs. Resolution is a pure function of an evidence set. For that set:

1. verify every reachable event intrinsically;
2. collapse proof variants by logical event identifier;
3. mark every non-recovery logical event named in a valid recovery's
   `supersedes`, and every non-recovery descendant of it, as retired;
4. compute active leaves among non-retired events;
5. return `active` only for one active leaf, `contested` for several, and
   `unknown-history` when a cited parent is absent.

Distinct canonical update payloads with one `previous` are siblings and form a
fork. Two recovery events with the same `recoveryParent` are likewise competing
recovery branches. Neither wins by timestamp, sequence, CID order, observation
order, or proof count; if both survive, resolution is `contested`. A later
recovery can advance only one recovery branch and cannot silently erase a
competing recovery branch. Compromise or equivocation of recovery authority can
therefore produce a permanently contested identity; this is preferable to an
unauthorized deterministic winner. `supersedes` retires exactly the named
logical heads and their non-recovery descendants, not an observer-relative set.
All retired branches remain in history.
`supersedes` MUST NOT name a recovery event; competing recovery branches cannot
be retired by unilateral authority from either branch.

An event is a recognized historical event exactly when it is intrinsically
valid and reachable from genesis through cited logical parents, even if retired.

Identity operations are closed in v1:

```text
addMethod(VerificationMethod) | removeMethod(id)
setMethodPurposes(id, purposes)
addAdministrationController(did) | removeAdministrationController(did)
addRecoveryController(did) | removeRecoveryController(did)  // recovery only
addService(Service) | removeService(id)
```

An event that uses an unknown operation is preserved but is `unsupported` for
state transition. An administration event containing a recovery-controller
operation is `invalid`.

Profile data—including names, handles, avatars, biographies, repository roles,
and human identity assertions—is forbidden in identity operations. It belongs
in ordinary signed claims.

### System identity state

The platform configuration directory MUST separate:

```text
identity/ledger/   authoritative public histories controlled by this installation
identity/cache/    disposable verified histories fetched for other principals
identity/profiles/ local aliases, defaults, resolver and credential references
credentials/       private material or references to credential providers
repositories/      repository routing and substrate connections
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
  "nonce":           bytes,                 // exactly 32 random bytes
  "names":           [text, ...],
  "governanceRoots": [text, ...],           // principal DIDs
  "anchors":         [SubstrateAnchor, ...]
}

SubstrateAnchor {
  "type":  text,
  "value": bytes or text
}
```

The domain is `kan.repository.inception.v1` and event type is `inception`.
Lists are duplicate-free and
sorted by canonical encoded value. At least one governance root is required.
The repository identifier is the base32-lower-no-pad multibase SHA-256
multihash of the canonical unsigned payload, prefixed `kan-repo:`. It is not a
DID and cannot author claims.

Repository inception is carried in a `ControlEvent` and MUST contain at least
one proof from a listed governance root. Its method MUST be authorized for
`capabilityDelegation` at `Proof.controllerState`; `did:key` uses its implicit
method. Version 1 governance is 1-of-N: one valid listed-root proof is sufficient
for inception and an ordinary governance update.

`kan init` deliberately creates inception. It defaults the governance root and
current actor to the configured system principal but permits explicit
alternatives. Git genesis may be an anchor; it is not the repository identity.
Changing the current actor does not change inception or governance.

`names` are immutable inception-time discovery hints, not mutable identity.
Renaming a project does not mint a new repository identifier; current names are
ordinary signed repository claims. Substrate anchors record inception context
and do not imply that every later clone or remote is a different repository.

Governance evolves through:

```text
GovernanceEvent {
  "v":               1,
  "repository":      text,
  "mode":            "update" or "reconcile",
  "parents":         [CID, ...],
  "sequence":        unsigned integer,
  "governanceRoots": [text, ...]
}
```

The domain is `kan.repository.governance.v1`, event type is `governance`, and
`parents` contains logical event
identifiers, is non-empty, sorted, and duplicate-free. `sequence` is one plus
the maximum parent sequence, with inception at zero. `governanceRoots` is
non-empty, sorted, and duplicate-free.

An `update` has exactly one parent and requires one valid
`capabilityDelegation` proof by a governance root at that parent. A `reconcile`
has two or more intrinsically valid governance states as parents and requires at
least one valid proof authorized at every parent state; one proof may satisfy
several parents when its principal remains a root in each. Its declared root
set becomes the merged result. Events are intrinsically valid; distinct
children of one parent are a governance fork. Resolution computes active
leaves from the evidence set. One leaf is active governance; several leaves are
`contested`; a missing parent is `unknown-history`. No timestamp, CID, proof
count, or observation order chooses a branch.

Every governance root holds an implicit full repository capability covering
all subject paths, all v1 repository operations, unbounded time, and delegation.
The zero-length path admits a root's own covered action. Governance and required
delegations MUST be publishable over every claim substrate. Missing required
history yields admission `unknown`; contested governance yields admission
`contested`; neither is `unadmitted`.

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
Lineage and role naming are ordinary claims. Delegations and revocations are
canonical control events because admission depends on their exact bytes and
authorization rules.

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

`subjectPrefix: null` covers every subject. Otherwise it covers the exact
subject and descendants separated by `/`; `bug` does not cover `bugfix`.
Operations are sorted and duplicate-free. Version 1 defines:

```text
claim.write | lineage.attest | role.name | capability.delegate |
capability.revoke | governance.update
```

Every claim creation maps to `claim.write`; the claim kind does not create an
implicit new operation. Governance events map to `governance.update`.
Delegation and revocation map to their corresponding operations. Lineage and
role claims map to `lineage.attest` and `role.name`. Unknown operations are
preserved but unsupported until a later version defines their admission rule.

Delegation and revocation payloads are:

```text
Delegation {
  "v":                    1,
  "repository":           text,
  "grantor":              text,
  "grantorIdentityVersion": IdentityVersion,
  "governanceEvent":      CID,
  "delegate":             text,
  "parent":               CID or null,
  "capability":           Capability
}

Revocation {
  "v":                    1,
  "repository":           text,
  "delegation":           CID,
  "revoker":              text,
  "revokerIdentityVersion": IdentityVersion,
  "governanceEvent":      CID,
  "effectiveAt":          signed integer or null
}
```

Their domains are `kan.capability.delegation.v1` and
`kan.capability.revocation.v1`; types are `delegation` and `revocation`.
Principal identity-version fields follow the method-specific rules above. A
delegation's logical event identifier is its capability identity.
`governanceEvent` names the exact governance state under which the path is
evaluated. `parent: null` is valid only when `grantor` is a governance root at
that event and means the implicit full root capability. Otherwise `parent`
names exactly one delegation. Cycles and missing parents yield admission
`unknown`, never a partial grant.

A delegation MUST contain a proof from `grantor` authorized for
`capabilityDelegation` at `grantorIdentityVersion`. A revocation MUST contain such
a proof from either the original grantor or a governance root at the named
governance event in the same repository. Every child capability MUST be a
subset of its parent:

- repository is identical;
- subject prefix is equal or more specific;
- operations are a subset;
- time interval is equal or narrower;
- delegation is permitted by the parent.

No union of several parent capabilities may create authority that no single
valid path grants. Each claim names at most one delegation path head; a consumer
MUST NOT splice edges from different paths. A valid revocation present in the
evidence set disables the named delegation and every descendant for current
admission. `effectiveAt` permits a revoker to set a trusted-time boundary; null
means every evaluation containing the revocation treats it as effective.

Capability time is evaluated against an explicit `evaluationInstant` supplied
by the admission caller or a named trusted substrate/time witness, never against
the claim's author-asserted timestamp. If a capability has a temporal bound and
no trusted evaluation instant is available, admission is `unknown`. A claim
author therefore cannot evade expiry or revocation by backdating. Historical
admission is a recomputation under a stated evidence set and trusted instant,
not a fact stored on the claim. Revocation and expiry never change signer
identity or signature validity.

Day may package roles, process atoms, harnesses, models, and capabilities. kan
owns the signed principal, lineage, role, delegation, and evaluation primitives.

### Claim authorship

New claims identify both:

```text
Author {
  "principal":          text,               // canonical DID
  "verificationMethod": text,               // absolute DID URL
  "identityVersion":    IdentityVersion
}
```

Verification establishes that the method signature is valid and that the
principal authorized the method for `assertion` at `identityVersion`. A
rotatable DID without an exact supported identity-version citation is invalid
for new writes; legacy records use the
compatibility rule below. The claim separately carries repository scope and an
optional delegation logical event identifier. A role name MUST NOT appear in
`Author`.
When the claim requests a repository-scoped operation, the same method MUST
also carry `capabilityInvocation`; `assertion` authenticates speech while
`capabilityInvocation` permits exercising delegated reach.

For supersession, retraction, and same-author authorization, the author is the
stable `principal`, not the verification method. Key rotation therefore does
not prevent a principal from retracting its own earlier claim. A fresh session
agent is a different principal and cannot retract its predecessor session's
claim without an explicit repository-authorized mechanism such as `Rejects`.

### Three independent judgments

Every structured read of a claim MUST disclose:

```text
cryptographicValidity = valid | invalid | unsupported | unknown
identityStateStanding = active | superseded | contested | unknown | static
repositoryAdmission   = admitted | unadmitted | contested | unknown | not-applicable
viewTrust              = included | excluded | weighted
```

An invalid signature is not authentic speech. An authentic but unadmitted or
view-excluded claim remains inspectable. Storage policy may refuse an object
operationally but MUST NOT redefine these semantic results.
`identityStateStanding` reports the standing of the cited identity event without
changing intrinsic signature validity. `static` applies to `did:key`.
`repositoryAdmission: not-applicable` applies only when the object requests no
repository-scoped operation. Contested identity standing does not make a valid
signature invalid; it MUST make repository admission `contested` for an action
depending on that identity branch.

## Canonicalization and equivalence

All control payloads and events use the
[IPLD DAG-CBOR specification](https://ipld.io/specs/codecs/dag-cbor/spec/), not
an independently selected RFC 8949 deterministic profile. Map keys are text
and sort by their complete encoded bytes—encoded length first, then bytewise.
Integers, lengths, and CID tag 42 use their shortest encoding; collections are
definite-length; CID links include the required binary identity-multibase prefix;
no other tags, undefined values, special floats, or trailing objects are valid.
The v1 schemas use no floats.

Text MUST be valid Unicode and MUST NOT be normalized implicitly; producers
SHOULD emit NFC, and distinct UTF-8 strings remain distinct identifiers unless
their defining scheme says otherwise. Map keys are exactly the strings
specified here. Every field shown in a v1 schema is required, including nulls
and empty arrays. Unknown fields are preserved, contribute to the logical event
identifier and signatures, and make that event `unsupported` for state
transition. An unknown field in genesis therefore derives a distinct DID whose
history is preservable but not resolvable by a v1 implementation.

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
   `invalid`; success yields `valid`. Separately report the cited identity
   state's standing in the complete evidence set. For a repository-scoped
   action, also require `capabilityInvocation`; its absence leaves the speech
   valid but makes admission `unadmitted`.
4. Resolve repository inception and governance. Missing required evidence
   yields admission `unknown`; multiple active governance leaves yield
   `contested`.
5. Find a governance-rooted capability path covering the author, operation,
   repository, subject, and explicit trusted evaluation instant. Check every
   edge for signature, purpose, attenuation, expiry, and revocation. Missing
   parents, time evidence, or identity history yield `unknown`; no covering
   path in complete uncontested evidence yields `unadmitted`; a valid path
   yields `admitted`.
6. Apply the consumer's trust frame independently to authentic material and
   report `included`, `excluded`, or its explicit weight.
7. Preserve the claim and all evidence regardless of admission or view result.

To resolve `did:kan`, verify genesis derivation and proof, collect every
intrinsically valid reachable update, collapse proof variants, apply explicit
recovery retirements, and compute active leaves. Return one
`ResolvedDidKanState`, or `contested`, `unknown-history`, `unsupported`, or
`invalid` without collapsing those states:

```text
ResolvedDidKanState {
  "did":                         text,
  "standing":                    "active",
  "activeEvent":                 CID,
  "recoveryParent":              CID,
  "recoveryEpoch":               unsigned integer,
  "recoveryControllers":         [text, ...],
  "administrationControllers":   [text, ...],
  "verificationMethods":         [VerificationMethod, ...],
  "services":                    [Service, ...],
  "retiredHeads":                [CID, ...]
}
```

The full resolved state is the normative kan output. A DID Core document is a
lossy projection: verification methods and services map directly; kan recovery
and administration controller sets remain method-specific metadata and MUST NOT
be represented as DID Core verification relationships with stronger semantics.

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
  recovery parent, not the repaired state. Recovery epochs revoke stale
  recovery authority while keeping all branches auditable. Competing valid
  recoveries remain contested rather than selecting an attacker-controlled
  winner.
- **Proof malleability:** Logical event identity excludes proofs, so alternate
  valid signatures over one payload cannot manufacture a state fork.
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
- **Backdating:** Author timestamps never determine capability validity.
  Time-bounded admission requires a caller-supplied trusted instant; without
  one, the result is `unknown`.
- **Withholding and eclipse:** A resolver cannot detect evidence a substrate
  completely withholds. Deployments SHOULD consult independent configured
  substrates for identity, governance, and revocation witnesses and disclose
  which connections contributed to a result. One apparently complete source is
  not proof that no competing branch exists.

## Compatibility

Existing repository-local `did:key` values remain valid static principals.
Existing claim bytes, CIDs, signatures, and `AuthorId.agent` values MUST NOT be
rewritten. Readers retain a compatibility projection that displays and verifies
historical composite authorship. New writes MUST use principal plus
verification method and MUST NOT emit `AuthorId.agent`.

Legacy claims without `identityVersion` are checked using the static principal
encoded by their original `AuthorId`; the reader MUST NOT invent a historical
rotatable-DID state. Their existing sign-the-CID scheme remains structurally
distinct from RFC-1 control-event domains and is not retroactively re-signed.

Existing `RoleDeclaration` claims remain naming evidence and do not become
retroactive capabilities. `KAN_IDENTITY_FILE`, `.kan/seed`, keychain pointers,
and registered role keys become legacy credential/profile inputs; none defines
the repository or human principal under this RFC.

Migration may record a witnessed continuity assertion between a chosen stable
human principal and a legacy repository DID, then establish that principal as a
repository governance root. It MUST NOT fabricate new authorship for old
claims. A mixed workspace may contain legacy and RFC-1 records indefinitely.
This RFC amends the existing fold rule that keyed same-author supersession on
the complete legacy `AuthorId`: for RFC-1 claims, same-author authorization keys
on stable principal DID. The compatibility projection retains the legacy rule
for legacy bytes, including the historical `agent` component.

Prior identity ADRs have these dispositions:

- ADR 4's repository-local `did:key` remains a supported legacy static
  principal; its repository-as-identity interpretation is superseded.
- ADRs 24, 58, 61, and 75 remain historical role/agent evidence; RFC 1
  supersedes composite authorship and any implication that a role grants reach.
- ADRs 25, 55, and 65-68 remain compatibility guidance for existing secrets;
  RFC 1 supersedes their use as the shared principal or repository model.
- ADR 77's rule that escape hatches cannot bypass safety guards remains in
  force.
- ADRs 83 and 84 become view-trust compatibility behavior and do not determine
  repository admission.
- ADRs 86-88 describe the legacy identity surface; their read-only and
  single-question resolver disciplines remain requirements where compatible.

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
- **Use UCAN as the v1 wire format:** Rejected for v1. The minimal canonical
  delegation and revocation events above are the interoperable floor. A future
  version may define a semantics-preserving UCAN profile, but cannot reinterpret
  v1 bytes or attenuation.

## Reference test vectors

Normative vectors will live under `tests/fixtures/identity-v1/`. The manifest is
created only when every entry contains complete input bytes and expected
outputs; an empty or placeholder manifest would falsely satisfy the identity
telos witness.

The vector set MUST cover:

1. repository inception and single-field identifier changes;
2. `did:kan` genesis bytes, multihash DID, proof, and event CID;
3. proof-only mutation changing event CID but not DID;
4. linear administration, sibling fork, proof-set malleability, contested
   resolution, recovery epochs, and competing recoveries;
5. verification-purpose acceptance and rejection;
6. governance update, fork, contested admission, and multi-parent reconciliation;
7. valid attenuation and attempted repository, subject, operation, and time
   amplification;
8. root zero-length admission, revocation, trusted-time expiry, and unknown-time
   boundaries;
9. all four initially supported DID methods, their `IdentityVersion` forms, and
   an unsupported method;
10. active, superseded, contested, unknown, and static identity standing;
11. legacy authorship and principal-keyed modern supersession without byte rewriting;
12. read-only resolution with no credential, governance, admission, or trust
    side effects.

Each valid vector MUST include diagnostic input, canonical DAG-CBOR hex,
relevant multihash/CID strings, signature bytes, and the expected resolved
state. Invalid vectors MUST identify the exact rule and failure classification.

## Unresolved questions

None.

## Deferred questions

- A future UCAN capability profile that is provably equivalent to the v1 wire
  records and attenuation rules.
- Controller and governance thresholds beyond v1's explicit 1-of-N rule.
- URI syntax, authority matching, repository routing, Git transport inference,
  and identity-resource paths; these belong to RFC 2.
- Hosted-kan, ATProto PDS, relay, archive, and replica protocols.
- Day's packaging of roles, atoms, harnesses, models, and capabilities.
- A graphical or TUI identity-management flow.

## Implementation status

Not implemented. The current implementation remains the compatibility source
described above. Acceptance of this RFC authorizes staged implementation; it
does not mark any behavior shipped.
