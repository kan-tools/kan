# Feature: current claims, `kan-claim-v2`, and the identity cutover

## Status

Interactive design. The domain envelope, codec support boundary, scope and
delegation identity, recording time, signing input, subject/reference ontology,
mixed collection, initialization, authorship continuity, and product cutover
are settled. The design is ready for structural checking; #245 remains an
explicit prerequisite to freezing vectors and implementing the cutover.

## Summary

Define the unversioned current Rust `Claim` model and its `kan-claim-v2`
transport/storage codec without rewriting historical claims. Historical claims
remain `v1` at the codec and compatibility boundaries. Current domain code does
not use `modern`, `current`, or `v2` qualifiers: version names belong at the
transport/storage boundary.

Decoding follows an ATProto-style open-union model. Supported current and v1
claims are explicitly distinguished from canonically preserved unsupported
records. Malformed records fail decoding and never masquerade as unsupported
but preservable data.

The current claim model replaces v1's workspace-local identity assumptions
with exact authorship, cryptographic scope identity, an optional delegation
logical-event identifier, and mandatory attested recording time. Its signature
uses a codec-bound claim-signing input structurally distinct from both v1's raw
CID signature and RFC 1 control-event signing inputs.

Issue #245 tracks replacement of the misleading `kan-repo:` textual identifier
and repository-oriented current terminology before those bytes freeze. This
design uses `ScopeId` and `scope`. A current `ScopeId` serializes as validated
multihash bytes; base32-lower multibase `b...` is its canonical display form,
not part of its signed identity. RFC 2 distinguishes a human-readable
`ScopeLocator` from a direct scope selector with `@id:`, and distinguishes a
normal subject path from a content-addressed compatibility selector with
`@cid:`. These are position-specific URI selectors, not prefixes embedded in
the domain identities.

## Settled decisions

### Domain and compatibility naming

- `Claim` and `Author` are the current domain types.
- Historical types live under a `v1` compatibility boundary.
- `kan-claim-v1` and `kan-claim-v2` are codec identifiers and may appear in
  transport/storage code.
- Current domain code does not use `ModernClaim`, `CurrentClaim`, `ClaimV2`, or
  corresponding qualifiers.

### Decode boundary

```rust
pub enum DecodedClaim {
    Supported(SupportedClaim),
    Unsupported(PreservedClaim),
}

pub enum SupportedClaim {
    Claim(Claim),
    V1(v1::Claim),
}
```

Invalid bytes return `DecodeError`. `PreservedClaim` retains the codec,
content type, and canonical source bytes. Only the codec decoder constructs
the supported arms, so downstream code cannot pair an arbitrary codec with an
unrelated content type. Fold and semantic interpretation accept supported
claims, never a `PreservedClaim`.

### Current claim content

The settled core is:

```rust
pub struct ClaimContent {
    pub author: Author,
    pub scope: ScopeId,
    pub delegation: Option<DelegationId>,
    pub subject: SubjectPath,
    pub referents: Vec<ResourceRef>,
    pub body: ClaimBody,
    pub cites: Vec<ClaimId>,
    pub artifacts: Vec<ArtifactRef>,
    pub recorded_at: RecordedAt,
}
```

`ScopeId`, `DelegationId`, `ClaimId`, and `RecordedAt` are distinct validated
types. A generic CID is not accepted where a delegation logical-event CID or
claim CID is required.

The public identity triplet used by both claim authorship and local actor
selection has one validation kernel with contextual wrappers:

```rust
pub struct SigningIdentity {
    principal: Did,
    method: VerificationMethodId,
    version: IdentityVersion,
}

pub struct Author(SigningIdentity);
pub struct ActorReference(SigningIdentity);
```

`SigningIdentity::new` validates the supported principal DID, verification
method DID URL, exact method controller, DID-method-specific identity-version
variant, and static `did:key` method spelling. `Author` is the signed
claim-domain type; `ActorReference` is the local profile/configuration type.
They do not become aliases and cannot be interchanged implicitly. The relevant
verification purpose remains contextual: claim verification requires
`assertion`, delegation use requires `capabilityInvocation`, and control
authorization requires `capabilityDelegation` or the event-specific purpose.
Purpose is not embedded in `SigningIdentity`, because one resolved method may
be authorized for more than one operation at the same identity version.

`Author` is serde-transparent over `SigningIdentity`, whose canonical domain
fields are `principal`, `verificationMethod`, and `identityVersion`. Its serde
implementation therefore determines the exact signed claim CBOR, including
DAG-CBOR links inside identity-version variants. `ActorReference` does not
derive protocol serde. A local `IdentityProfileDto` parses the convenient JSON
profile representation, including textual CID values, and explicitly
constructs the validated wrapper. Local configuration encoding can evolve
without changing author bytes. Proofs retain the distinct field name
`controllerState`, because it identifies the controller state against which a
particular proof is authorized rather than naming the whole signing identity.

### Scope identity and routing

`scope: ScopeId` is mandatory signed content. `ScopeId` is the self-certifying
identity derived from canonical inception evidence. It is distinct from:

- `ScopeLocator`, an authority-local human-readable route such as
  `kan-tools:kan`;
- `ResolverAuthority`, the local or hosted authority interpreting that route;
- immutable descriptive inception names; and
- local display labels.

Claims contain only `ScopeId`. Routing accepts a direct `ScopeId` or an
authority plus `ScopeLocator`, retrieves inception evidence, derives the
cryptographic identifier, and produces a verified scope. Governance,
admission, and folding consume the verified identifier, never the locator.

RFC 2 represents that distinction explicitly at the parse boundary:

```rust
pub enum ScopeSelector {
    Locator(ScopeLocator),
    Id(ScopeId),
}

pub enum SubjectSelector {
    Path(SubjectPath),
    Cid(SubjectCidSelector),
}
```

The `@` sigil means that the path segment is a typed literal selector rather
than the ordinary human-readable form accepted in that URI position. Although
RFC 3986 permits `@` in a path segment, RFC 2 reserves decoded ASCII `@`
completely from regular `ScopeLocator` and `SubjectPath` values. The selector
keyword states the supplied representation:

```text
kan://local/kan-tools:kan/subject/design/rfc-3
kan://local/@id:b.../subject/design/rfc-3
kan://local/kan-tools:kan/subject/@cid:bafy...
```

`@id:` supplies an exact `ScopeId` in the scope-selector position. `@cid:`
supplies a canonical CID selector in the subject-selector position. Parsing
constructs only `SubjectCidSelector`; it does not yet claim that the CID names
a valid or scope-bound legacy subject. Neither spelling introduces an `@kan`
namespace or changes the identity of a current subject. Resolution returns the
exact `ScopeId` and a typed resolved resource while retaining the selector and
compatibility diagnostics.

A typed selector occupies the complete selector value: `@cid:<cid>/child` is
invalid rather than a nested path. A literal `@` is required in canonical URI
syntax. Percent-encoded `%40` is decoded for semantic validation and cannot
smuggle `@` into a regular locator or path. Any other decoded `@...` form is
reserved and returns `unsupported-selector` or `invalid-selector`; it never
falls back to ordinary path interpretation. This reservation is confined to
scope and subject selector positions. Query values, DID syntax, and permitted
`kan+git` userinfo retain their independently specified RFC uses of `@`.

The domain representation is a private validated multihash newtype:

```rust
pub struct ScopeId(Multihash);
```

For the current inception method it accepts the exact SHA-256 multihash bytes
`0x12 0x20 <32-byte digest>` and serde emits those bytes directly into
canonical DAG-CBOR. Parsing rejects unsupported algorithms, lengths, and
noncanonical encodings before construction. `Display` emits the unique
base32-lower multibase form `b...`; RFC 2 renders a direct selector as
`@id:b...`. The `@id:` marker and multibase text are presentation-layer syntax
and never appear inside signed current claims or control payloads. The
unreleased `kan-repo:b...` spelling is replaced in place before wire freeze; it
is not promoted into a historical protocol alongside released claim v1.

The ATProto boundary preserves the difference between routing input and
verified identity. XRPC request parameters retain `scope: string` so callers
can supply either a human-readable locator or `@id:b...`. Current claim and
control DTOs carry `scope` as bytes, and verified result/provenance DTOs expose
`scopeId` as bytes. Lexicon `bytes` schemas bound the field to at most 34 bytes;
the adapter requires exactly the supported 34-byte SHA-256 multihash before it
constructs `ScopeId`. Signed records never duplicate a textual spelling beside
the bytes. Responses may separately render a direct URI for navigation, but
that presentation does not participate in scope equality.

Resolution responses likewise keep syntactic canonicalization, target
identity, and evidence source separate:

```rust
pub struct ResolutionResult<T> {
    pub request: CanonicalRequestUri,
    pub target: T,
    pub sources: SuccessfulResolutionSources,
    pub immutable_replay: ImmutableReplayUri,
    pub direct_uri: Option<DirectTargetUri>,
}

pub struct SuccessfulResolutionSources(NonEmptyVec<SourceResult>);

pub struct SourceResult {
    pub requested: SourceSelector,
    pub outcome: SourceOutcome,
    pub diagnostics: Vec<SourceDiagnostic>,
}

pub enum SourceOutcome {
    Contributed {
        source: VerifiedSource,
        snapshot: SourceSnapshot,
        completeness: Completeness,
    },
    ResourceAbsent {
        source: VerifiedSource,
        snapshot: SourceSnapshot,
        completeness: Completeness,
    },
    Denied {
        source: KnownSource,
    },
    NotFound,
    Rejected {
        reason: SourceRejection,
    },
    SnapshotUnavailable {
        source: VerifiedSource,
        requested: SnapshotSelector,
    },
}

pub struct SnapshotSet {
    entries: CanonicalSet<SupportedSourceSnapshotRef>,
}

pub struct SupportedSourceSnapshotRef {
    pub source: VerifiedSourceId,
    pub snapshot: SupportedSourceSnapshot,
}

pub struct SnapshotSetId(Cid);

pub enum DecodedSnapshotSet {
    Supported(SnapshotSetView),
    Unsupported(PreservedSnapshotSet),
}

pub struct SnapshotSetView {
    id: SnapshotSetId,
    bytes: CanonicalSnapshotSetBytes,
    entries: Vec<DecodedSourceSnapshotRef>,
}

pub struct DecodedSourceSnapshotRef {
    pub source: VerifiedSourceId,
    pub snapshot: DecodedSourceSnapshot,
}

pub enum DecodedSourceSnapshot {
    Supported(SupportedSourceSnapshot),
    Unsupported(PreservedSourceSnapshot),
}

pub enum SupportedSourceSnapshot {
    KanLog { commit: KanLogCommitId },
    GitTree { commit: GitObjectId },
    AtRepository { commit: Cid },
    AppViewSelection { manifest: Cid },
}

pub struct AppViewSelectionManifest {
    pub v: u64,
    pub target: TargetKey,
    pub accounts: CanonicalSet<AccountSnapshot>,
    pub evidence: CanonicalSet<EvidenceBlockId>,
}

pub struct AccountSnapshot {
    pub account: Did,
    pub commit: Cid,
}

pub struct EvidenceBlockId(Cid);

pub struct ScopedTarget {
    pub scope: ScopeId,
    pub resource: ScopedResourceKey,
}

pub enum ScopedResourceKey {
    Claim(ClaimId),
    Subject(ResolvedSubjectKey),
    ScopeIdentity,
    Principal(PrincipalIdentityKey),
}

pub enum ResolvedSubjectKey {
    Path(SubjectPath),
    LegacyCid(LegacySubjectRefId),
}

pub struct PrincipalTarget {
    pub principal: Did,
    pub version: ResolvedIdentityVersion,
}

pub struct AuthorityTarget {
    pub authority: VerifiedAuthorityIdentity,
}
```

`request` is the syntactically canonical URI the caller supplied; producing it
performs no resolution. `target` is the typed equality key established by
evidence. `sources` preserves the RFC 2 requirement to report each selected
source independently, and `immutable_replay` pins every source snapshot that
contributed to the result. `direct_uri` is an optional convenience rendering
introduced by this design that substitutes `@id:` under the same resolver
authority; RFC 2 does not require that field. It is not named `canonicalUri`,
is not a global identity, and does not replace either the canonical request or
immutable replay: named and direct requests remain different canonical
requests that may resolve to the same target.

Transport DTOs carry an ordinary source array. Conversion into a successful
domain result constructs `SuccessfulResolutionSources` only when the array is
nonempty and at least one available source actually contributed the returned
resource. Denied or incomplete additional sources remain present. This is a
domain success invariant inferred from the RFC algorithm, not a claim that the
existing Lexicon already declares a nonempty lower bound.

This closed `SourceOutcome` also repairs a representational gap in RFC 2. Its
algorithm requires every selected, inaccessible, missing, or rejected source
to be reported independently, while the existing prose `SourceResult` exposes
only `access: available | denied`. The typed outcome additionally distinguishes
an available snapshot that lacks the requested resource and an unavailable
requested snapshot. It is an RFC 2 schema amendment to track as a focused
follow-up, not a change to URI routing or scope identity.

Hosted `kan://` immutable replay uses one canonical `SnapshotSet` because the
request may select several sources while RFC 2's `snapshot` parameter is
singleton. The set is sorted and duplicate-free by canonical encoded entry;
its canonical DAG-CBOR CID is `SnapshotSetId`. A replay URI carries the exact
canonical set bytes as a multibase base64url `snapshot=u...` value rather than
only its CID. The resolution response also exposes `SnapshotSetId`, allowing a
client to recompute a compact equality key and archive the block normally.
The URI is therefore self-contained and neither local nor hosted resolution
must persist a hidden snapshot-set block during a read. Every snapshot actually
observed during resolution is included, whether its source contributed the resource or returned
`ResourceAbsent`, because bounded absence may affect the result. `Denied`,
`NotFound`, `Rejected`, and `SnapshotUnavailable` outcomes contribute no set
entry because no source snapshot was observed. A one-source hosted result uses
a one-entry set. Native `kan+git` and `kan+at` keep their existing direct
single-substrate `commit` selectors.

Self-contained replay has fixed protocol ceilings:

```rust
pub const MAX_SELECTED_SOURCES: usize = 16;
pub const MAX_SOURCE_ID_BYTES: usize = 128;
pub const MAX_SOURCE_SNAPSHOT_BYTES: usize = 512;
pub const MAX_SNAPSHOT_SET_CBOR_BYTES: usize = 12_288;
pub const MAX_CANONICAL_URI_BYTES: usize = 32_768;
```

URI parsing rejects the total encoded size before percent decoding or large
allocation. Snapshot parsing checks the base64url decoded upper bound before
decoding, then requires canonical DAG-CBOR, at most sixteen unique entries,
and all component bounds. The existing 4096-byte decoded `SubjectPath` ceiling
is independent. Snapshot tokens are never compressed: compression would add a
second versioned canonicalization surface and decompression resource risk.

Each snapshot entry carries an immutable snapshot-codec identifier. The
supported union arm binds substrate semantics to the typed snapshot value, so
a Git snapshot cannot contain an ATProto commit and no independent
`SubstrateKind` can contradict the variant. Unknown future codecs become
`PreservedSourceSnapshot` with their exact canonical bytes. Older readers can
therefore recompute and disclose the enclosing `SnapshotSetId`, but replay
returns `unsupported-snapshot-codec` rather than dropping or guessing at the
entry. `AppViewSelection` requires a content-addressed selection manifest; an
index timestamp or mutable cursor is provenance but never an immutable
snapshot.

Replay uses these immutable codec identifiers under the same protocol
namespace as control-event domains:

```text
tools.kan.snapshot.set.v1
tools.kan.snapshot.kan-log.v1
tools.kan.snapshot.git-tree.v1
tools.kan.snapshot.at-repository.v1
tools.kan.snapshot.appview-selection.v1
```

The self-contained token declares `tools.kan.snapshot.set.v1`; every entry
declares exactly one of the four supported entry codecs or a preserved unknown
future codec. These identifiers are transport protocol names. They do not add
version qualifiers to the unversioned Rust domain types.

Constructed `SnapshotSet` values admit only supported typed entries. Decoding
a replay token produces `DecodedSnapshotSet::Supported` only when every entry
is understood. Its view retains the exact canonical bytes and computes
`SnapshotSetId` from those bytes, never from reserialization. If any bounded,
canonical entry uses an unknown codec, the whole set becomes
`DecodedSnapshotSet::Unsupported(PreservedSnapshotSet)` and retains the
original token; replay never drops the unknown entry and proceeds with a
smaller evidence set. Re-emission returns the preserved token, not serde output
reconstructed from entry views.

Malformed or noncanonical CBOR, duplicate or misordered entries, exceeded
bounds, a known codec with an invalid payload, and a known codec paired with
another codec's payload arm all return `DecodeError` and construct no semantic
set. Unknown codecs do not relax outer source-ID, ordering, uniqueness, or size
invariants. The request-diagnostics layer may retain invalid input bytes for
disclosure, but only a fully supported set can enter replay.

An `AppViewSelection` manifest commits to the exact resolved target, every
ATProto account commit from which evidence was selected, and every returned
claim, identity, governance, delegation, revocation, and proof block CID. The
response supplies those blocks plus the MST/CAR proof material required to
verify membership in each named account commit. Trust frames and trusted
evaluation time are excluded because they apply after evidence selection.
Mutable index timestamps and cursors are also excluded. AppView completeness
is always `selection`, never `committed`. Pagination ranges over one complete
manifest and every cursor is bound to its manifest CID; an AppView that cannot
commit to its complete selected evidence set cannot advertise immutable replay
for that query. The outer `SourceSnapshotRef` supplies verified AppView source
identity, so the manifest does not duplicate mutable endpoint routing.

The three RFC 2 result families instantiate this envelope as
`ResolutionResult<ScopedTarget>`, `ResolutionResult<PrincipalTarget>`, or
`ResolutionResult<AuthorityTarget>`. A scoped principal lookup carries its
scope separately as evaluation context and provenance; that context does not
become part of `PrincipalTarget` identity. This avoids `Option<ScopeId>`,
stringly resource kinds, and target unions whose arms admit inapplicable
fields.

Issue #245 must apply this replacement for `kan-repo:` across RFC 1, RFC 2,
canonical vectors, signed control payloads, URI grammar, and prerelease
migration behavior. Current binary identity has one byte representation and
one display spelling. Current constructors accept no `kan-repo:` alias.

All unreleased signed control-event domain separators move under kan's
`tools.kan.*` protocol namespace before their vectors freeze:

```text
tools.kan.did.genesis.v1
tools.kan.did.update.v1
tools.kan.scope.inception.v1
tools.kan.scope.governance.v1
tools.kan.capability.delegation.v1
tools.kan.capability.revocation.v1
tools.kan.scope.authorship-continuity.v1
```

The existing `kan.did.*`, `kan.repository.*`, and `kan.capability.*` domain
strings are pre-release implementation artifacts, not released compatibility
formats. They are renamed in place and receive no parallel decoder arms.
Released `kan-claim-v1` data remains the actual historical compatibility
boundary. A workspace containing pre-release `.kan/repository` control state is
detected explicitly and receives a remediation diagnostic; it is never
silently interpreted, migrated, or deleted. `kan-claim-v2` remains the settled
claim codec identifier rather than a control-event domain separator.

### Delegation

`delegation: Option<DelegationId>` names the logical event CID of the
capability-chain head invoked by the author. The resolver walks its parent
chain to a governance root and checks scope, delegate principal, subject
coverage, `claim.write`, time bounds, attenuation, revocation, governance
standing, and the author's capability-invocation verification purpose.

Absence remains representable. Governance roots have implicit full authority
and need no delegation. Authentic non-root speech without a delegation remains
inspectable and is unadmitted when evidence is complete and uncontested;
missing or contested evidence produces the corresponding non-final judgment.
Admission is computed and never stored on the claim.

### Recording time

`recorded_at: RecordedAt` is required, signed Unix-microsecond content within
the ATProto interoperable integer range. Current claims cannot be timeless.
The value is an author attestation and never substitutes for the
caller-supplied trusted instant used for capability expiry and revocation.

`v1::ClaimContent` permanently retains `Option<u64>`. A timeless v1 claim
remains v1; migration does not invent a timestamp or rewrite its CID. A
v1-to-v2 lens is therefore not total over all historical claims.

### Signature input

The current signature covers canonical DAG-CBOR of:

```text
ClaimSigningInput {
  "codec": "kan-claim-v2",
  "claim": CID
}
```

The claim CID covers canonical DAG-CBOR of `ClaimContent`. This envelope is
structurally distinct from v1, which signs raw CID bytes, and from control
events, whose signing input is `{ domain, type, payload }`. Binding the codec
also binds the signature to the interpretation that defines the content.

The existing authorship kernel currently signs raw claim CID bytes. It is a
pre-storage implementation defect against this settled requirement and must be
corrected before any v2 claim is emitted.

## Requirements

- REQ-1: Current domain names are unversioned; historical claim types are
  explicitly v1; codec/version names remain at compatibility,
  transport/storage, and signing-protocol boundaries.
- REQ-2: Decoding distinguishes supported, canonically preserved unsupported,
  and invalid records without lossy reserialization.
- REQ-3: A current claim signs exact `Author`, `ScopeId`, optional
  `DelegationId`, path subject, structured referents, body, citations,
  artifacts, and mandatory
  `RecordedAt` content.
- REQ-4: Locators and resolver authorities never become claim identity. RFC 2
  parses human-readable locators and `@id:` direct selectors into distinct
  arms, reserves decoded `@` from regular locators, and every named resolution
  verifies inception evidence and derives the exact `ScopeId` before claims
  are evaluated.
- REQ-5: CID categories that have different semantics use distinct Rust
  newtypes.
- REQ-6: Current claim signatures use the codec-bound signing input above;
  raw-CID signing remains v1-only.
- REQ-7: Existing v1 claim bytes, CIDs, signatures, optional recording times,
  and composite-author compatibility semantics are never rewritten.
- REQ-8: New installs, upgraded installs, mixed stores, rollback attempts, and
  unsupported future codecs receive explicit behavior before v2 becomes the
  default writer.
- REQ-9: #245's scope-identifier change makes validated multihash bytes the
  current signed representation, `b...` the canonical display form, and
  `@id:b...` the direct URI selector before canonical v2 vectors or migration
  fixtures are frozen.
- REQ-10: Successful explicit `kan init` is the only transition from v1 write
  compatibility to v2 writes, and its system-identity preflight mutates no
  workspace when identity setup is required.
- REQ-11: Current subjects are scoped paths only. RFC 2 parses normal subject
  paths and legacy `@cid:` compatibility selectors into distinct arms and
  reserves decoded `@` from ordinary subject paths. Structured aboutness uses
  a closed `ResourceRef` set distinct from citations and artifacts.
- REQ-12: `kan-claim-v2` has the closed body inventory and canonical serde
  discriminators in this design; semantic extensions require another codec.
- REQ-13: Canonical sets, unique sequences, bounded strings, typed Git object
  IDs, byte paths, and line ranges make the agreed collection/value invariants
  unrepresentable after construction.
- REQ-14: Only exact signing and verified decoding boundaries construct
  current `Claim`; bounded signature bytes alone do not imply validity.
- REQ-15: Legacy authorship continuity is optional, scope-local, one-way, and
  dual-proved; legacy subject binding is a separate signed inception fact.
- REQ-16: Mixed folds consume borrowed `ClaimView` projections that always
  retain original claim ID, codec, bytes, and compatibility diagnostics.
- REQ-17: Publication intent uses a constrained canonical subject URI and
  asserts intended visibility without credentials or a delivery claim.
- REQ-18: The write-policy transition is `1.0.0-beta.1`; current binaries read
  v1 indefinitely but never expose an ordinary v1 writer.
- REQ-19: `Author` and local `ActorReference` wrap one validated
  `SigningIdentity` representation without becoming implicitly interchangeable
  or carrying operation-specific authority.
- REQ-20: `Author` transparently serializes the canonical `SigningIdentity`
  domain map, while local profile JSON converts through a separate DTO and
  cannot define or alter signed author bytes.
- REQ-21: ATProto request `scope` strings remain routing selectors, while
  current signed DTOs and verified result/provenance DTOs carry exact binary
  `ScopeId`; no signed record duplicates its textual display form.
- REQ-22: Resolution results separately expose the canonical request, typed
  resolved target, per-source provenance, and optional same-authority direct URI;
  no single URI string conflates canonicalization, identity, and source.
- REQ-23: Parsing `@cid:` constructs only a canonical `SubjectCidSelector`;
  `LegacySubjectRefId` requires exact v1 subject-byte recomputation, claim
  verification, and signed workspace-to-scope binding during resolution.
- REQ-24: Resolution uses one generic envelope instantiated with distinct
  closed scoped, principal, and authority target types; freestanding identity
  targets never require or carry a meaningless optional scope.
- REQ-25: Successful resolution preserves plural per-source provenance and an
  immutable replay URI covering every contributing snapshot. DTO arrays become
  `SuccessfulResolutionSources` only after proving that at least one available
  source contributed the resource; optional `directUri` remains a distinct
  non-normative navigation convenience.
- REQ-26: Per-source results use a closed outcome that represents contributed,
  resource-absent, denied, not-found, rejected, and snapshot-unavailable states
  required by the RFC 2 algorithm without inapplicable nullable fields.
- REQ-27: Hosted multi-source immutable replay identifies a canonical
  content-addressed `SnapshotSet` containing every observed source snapshot,
  including resource-absent observations; failures without an observed
  snapshot remain only in per-source provenance. Its URI selector contains the
  canonical set bytes directly, while the response exposes their CID.
- REQ-28: URI and replay parsing enforce the fixed source-count, source-ID,
  native-snapshot, decoded-snapshot-set, and total canonical-URI ceilings in
  this design before unbounded decoding or allocation; replay tokens are never
  compressed.
- REQ-29: Source snapshots use an immutable codec-bound supported/unsupported
  union whose supported variants make substrate/value mismatches
  unrepresentable; AppView immutable replay requires a content-addressed
  selection manifest.
- REQ-30: Constructed snapshot sets contain supported entries only; decoded
  sets retain authoritative whole-token bytes and per-entry classification,
  compute identity without reserialization, and forbid partial replay when any
  entry is unsupported.
- REQ-31: AppView immutable replay uses a content-addressed manifest bound to
  the exact target, contributing account commits, and returned evidence block
  CIDs; it excludes evaluation and mutable index state, reports selection
  completeness, and binds every page cursor to the complete manifest CID.
- REQ-32: Snapshot-set decoding distinguishes fully supported, canonically
  preserved unsupported, and invalid input. Unknown codecs preserve the whole
  bounded canonical token; malformed known or outer structure constructs no
  semantic set, and only fully supported sets can replay.
- REQ-33: Every unreleased control-event signing domain is renamed in place
  under `tools.kan.*`; no compatibility decoder preserves `kan.did.*`,
  `kan.repository.*`, or `kan.capability.*`, while released claim v1 remains
  readable and pre-release repository control state receives explicit
  remediation.

## Subject and structured-reference ontology

RFC 2 has one subject resource grammar: a hierarchical subject path within a
scope. Current claims therefore use `SubjectPath`, never v1's `Local`/`Anchor`
union. Subject identity is exactly `(ScopeId, SubjectPath)`. Relation targets
are absolute scoped paths:

```rust
pub struct ScopedSubjectRef {
    pub scope: ScopeId,
    pub subject: SubjectPath,
}
```

A claim in scope A may assert a relation to a subject in scope B, but that
assertion exercises authority only in A. Principals remain identity resources,
not subject variants; commits, blobs, files, and ranges remain typed resources
or artifacts, not subjects. V1 anchor subjects stay byte-exact behind the v1
compatibility boundary.

The URI-only `SubjectSelector::Cid` arm does not assert that current subjects
have intrinsic CIDs. Today it identifies the canonical v1 `SubjectRef` used to
derive a deterministic compatibility projection. A future codec may define a
first-class canonical `SubjectId` and generalize content-addressed selection,
but no current claim CID is treated as a subject CID: a path subject may have
many claims and none of their CIDs uniquely identifies the subject.

URI parsing and semantic resolution are deliberately separate:

```rust
pub struct SubjectCidSelector(Cid);
pub struct LegacySubjectRefId(Cid);
```

The parser accepts only canonical CID syntax and renders the selector in the
unique base32-lower form. The resolver finds candidate v1 evidence, recomputes
the CID from the exact canonical v1 `SubjectRef` bytes, verifies the claim and
its signed `kanV1Workspace` binding to the requested scope, and only then
constructs `LegacySubjectRefId`. A syntactically valid selector with no
supported resolved target is `resource-not-found`, not a fabricated legacy
identity. A future codec may resolve the same syntactic selector into a future
canonical subject-ID arm without changing RFC 2 parsing.

Compatibility reads and folds use a view-layer subject key rather than
inventing a current path:

```rust
pub enum ResolvedSubject {
    Path {
        scope: ScopeId,
        path: SubjectPath,
    },
    LegacyCid {
        scope: ScopeId,
        id: LegacySubjectRefId,
    },
}
```

Claims with the same canonical v1 `SubjectRef` CID form one coherent legacy
subject history addressable through `subject/@cid:<cid>`. That history is
read-only to the current codec: v2 claims and `ScopedSubjectRef` relations
remain path-only and cannot silently confer current subject semantics on it.
Current claims may still cite its individual claims or refer to the structured
resources disclosed by its compatibility view. A later codec may introduce a
first-class canonical `SubjectId` while reusing the already typed `@cid:` URI
selector.

The useful strict-identity idea formerly placed in `IdentifiedSubject` instead
becomes structured aboutness:

```rust
pub enum ResourceRef {
    Scope(ScopeId),
    Subject(ScopedSubjectRef),
    Claim(ClaimId),
    Principal(Did),
    Control(ControlRef),
    Artifact(ArtifactRef),
}

pub enum ControlRef {
    IdentityEvent(IdentityEventId),
    GovernanceEvent(GovernanceEventId),
    Delegation(DelegationId),
    Revocation(RevocationId),
}
```

`referents` says which structured resources the assertion concerns. `cites`
says which claims support it. `artifacts` says which concrete outputs or
evidence accompany it. The same underlying identifier can appear in different
roles without collapsing their semantics. Merely referring to a resource
grants no authority, establishes no identity equivalence, and affects no fold
unless a defined body or projection consumes it.

Referent order is semantically irrelevant. Construction sorts by canonical
bytes and rejects duplicates; the required array may be empty. Kan may index,
resolve, and disclose referents automatically, including unavailable or
unsupported referenced resources.

## Canonical domain and ATProto representations

Canonical v2 claim-content bytes are produced directly by serde over the
domain types. Struct fields use lower-camel-case wire names and deny unknown
fields. Closed domain enums use an explicit `kind` discriminator with
kebab-case variant values and lower-camel-case fields.

ATProto DTOs are separate transport types. Their Lexicon unions use `$type` as
required by ATProto. The v2 adapter maps between `$type` DTO arms and domain
`kind` arms, removes all transport-only metadata before CID computation, and
accepts a record only when inverse conversion reproduces the exact canonical
domain bytes.

`kan-claim-v2` is an immutable closed semantic schema. It has no domain
`ClaimBody::Unknown`. A semantic extension uses a new codec and a new open-union
payload arm. Unknown future codec/arm pairs are preserved as an unsupported
whole payload. A known codec with the wrong arm, an unknown nested variant in a
purported v2 payload, or an unknown v2 field is invalid rather than silently
interpreted. The codec registry never rebinds `kan-claim-v2` to new schema
bytes.

## Mixed codec collection

V1 and v2 records coexist in the single `tools.kan.claim` collection, keyed by
claim CID. Its common envelope carries claim CID, codec, open-union content,
signature, and storage `rev`. The open content union has explicit v1 and v2 DTO
arms plus raw unknown ATProto data. At this transport/storage boundary,
versioned DTO arm names are intentional.

The decoder validates the immutable codec-registry pairing before domain
conversion: `kan-claim-v1` maps only to the v1 content arm and
`kan-claim-v2` only to the v2 arm. An unknown codec with an unknown arm is
preserved unsupported; a known codec with the wrong arm is invalid. Writers do
not dual-write. `dev.kan.claim` remains only an older collection-migration
concern, never the permanent home of v1.

## Workspace activation

Verified scope inception is the sole v2 activation boundary. There is no
separate mutable workspace-format marker and no hidden first-write migration:

```rust
pub enum WorkspaceClaimMode {
    Uninitialized,
    V1 { evidence: LegacyWorkspaceEvidence },
    Claim { scope: VerifiedScope },
    Incomplete { diagnostics: Vec<InitializationDiagnostic> },
}
```

Absence of state is uninitialized, not v1. Only verified historical workspace
or claim evidence selects v1 compatibility. Verified inception means the new
binary emits only `kan-claim-v2`. Partial, unsupported, or conflicting scope
state is incomplete and refuses writes. Old binaries may append v1 after
rollback; mixed readers continue to disclose and interpret both codecs.

Activation is explicit and composes the existing setup commands:

1. `kan identity init` establishes the installation-level human principal and
   daily actor without opening a workspace.
2. `kan init` establishes and verifies this workspace's scope under that actor.

`kan init` preflights the system identity before writing any workspace scope
nonce, temporary file, inception evidence, or activation state. In an
interactive terminal it may, with explicit consent, invoke the same underlying
identity-enrollment action as `kan identity init`, verify the profile, and
resume. It never duplicates enrollment logic. Decline leaves the workspace
untouched. Non-interactive CLI, MCP, and automation receive a structured
`SystemIdentityRequired` refusal containing the ordered remedies. An existing
invalid or inaccessible identity is reported and never silently replaced.

Installation and reads create nothing. A first write in an uninitialized
workspace returns `ScopeInitializationRequired`; it does not silently run init.
The log/MST may be created lazily by the first post-init claim. A fresh
workspace never emits v1.

### Legacy authorship continuity

Migration may optionally install a scope-specific, one-way authorship
continuity control event:

```rust
pub struct AuthorshipContinuity {
    pub scope: ScopeId,
    pub legacy_principal: Did,
    pub principal: Did,
}
```

It requires valid proofs from the legacy workspace `did:key` and the selected
current principal at its exact identity version. It does not rewrite or
reattribute v1 claims, assert global DID equality, or grant governance or
capabilities. It permits the current principal to exercise same-author
correction semantics over that legacy principal's claims in this scope. The
relationship never works in reverse. If the key is unavailable or the user
declines, activation may proceed with explicit disclosure that old claims stay
authorship-distinct. Automation must supply explicit continuity inputs; machine
ownership, names, and possession of only one key prove nothing.

Legacy subject binding is separate. When v1 claims are present, `kan init`
offers to include one typed `kanV1Workspace` substrate anchor per explicitly
selected canonical v1 `Anchor::Workspace` value in scope inception. The
existing `gitGenesis` anchor locates Git history and never silently doubles as
migration consent. A v1 claim receives scoped subject projection only when its
exact workspace value is named by valid governed inception and its original CID
and signature verify. Distinct anchors are listed; none is guessed. Unmatched
or non-workspace v1 claims remain preserved, readable, and diagnostically
unbound.

### Product release boundary

The write-policy transition is kan `1.0.0-beta.1`. That release and later read
v1 indefinitely but do not expose an ordinary v1 writer. Fresh and activated
workspaces write v2; legacy workspaces refuse writes with the guided init flow.
Stable 1.0 follows migration fixtures, unsupported-codec tests, GUI/TUI
onboarding, and the planned thorough adversarial review. Product semver and
claim codec versions are independent: `kan-claim-v1` is historical and
`kan-claim-v2` is the initial current codec of kan 1.x.

## Current identity-related claim bodies

RFC 1's `IdentityOperation` name remains reserved for the closed ordered
`did:kan` administration/recovery program fixed by issue #244. Ordinary claims
use flat body arms instead:

```rust
Lineage { child: Did, relationship: LineageRelationship }
RoleNaming { principal: Did, name: RoleName }
```

For lineage, `author.principal` is the creator or invoker; lineage conveys
provenance only. Role naming conveys a scope-local name only. Their principal
operands remain explicit because identities are not subjects. Admission checks
the applicable `lineage.attest` or `role.name` operation independently.

V2 retains the attributable decision to share a subject, but names it
`PublicationIntent` because the claim is appended before transport and cannot
prove delivery:

```rust
PublicationIntent { target: PublicationTarget }
```

Actual source resolution evidences whether records are present. Historical v1
`Publication { layer: GitTree }` remains unchanged.

`PublicationTarget` is a validated canonical subject URI under RFC 2. Its
scheme is `kan`, `kan+git`, or `kan+at`; its resolved scope and subject must
equal the containing claim; it contains no trust/evaluation input and no
immutable commit/snapshot selector pretending to be writable. Source/service
selection may identify the intended publication surface. The URI records an
intended visibility route and never conveys credentials or write authority.

The complete closed body inventory is:

```rust
pub enum ClaimBody {
    Subject { title: Title, subject_kind: SubjectKind },
    Observation { text: NarrativeText },
    Plan { text: NarrativeText },
    Decision { text: NarrativeText },
    Blocker { text: NarrativeText },
    Resolution { text: NarrativeText },
    Result { text: NarrativeText },
    Status { value: StatusValue },
    Relation { relation: RelationKind, target: ScopedSubjectRef },
    Retraction { claim: ClaimId },
    Rejection { claim: ClaimId },
    PublicationIntent { target: PublicationTarget },
    Lineage { child: Did, relationship: LineageRelationship },
    RoleNaming { principal: Did, name: RoleName },
}
```

Its kebab-case `kind` values are respectively `subject`, `observation`, `plan`,
`decision`, `blocker`, `resolution`, `result`, `status`, `relation`,
`retraction`, `rejection`, `publication-intent`, `lineage`, and `role-naming`.
There is no `Layer` or `Unknown` arm. `Relation.relation` avoids colliding with
the body's `kind` discriminator; `Retraction.claim` replaces v1's misleading
`supersedes` field.

## Canonical collections and values

Reference collections make their semantics visible in their types:

```rust
pub referents: CanonicalSet<ResourceRef>,
pub cites: CanonicalSet<ClaimId>,
pub artifacts: UniqueSequence<ArtifactRef>,
```

`CanonicalSet` sorts by canonical DAG-CBOR bytes, rejects duplicates, and
rejects noncanonical encoded order. Artifact order is signed presentation
meaning and is preserved, while exact duplicates are rejected.

Semantic strings are private validated newtypes measured in UTF-8 bytes with
no trimming or Unicode normalization: `SubjectPath` is 1..=4096 bytes under
RFC 2 decoded-path rules, `Title` 1..=8192, `NarrativeText` 1..=900000, and
path-safe `RoleName` 1..=128. The complete ATProto record still has a one-MB
ceiling.

Git identity and paths are platform-independent:

```rust
pub enum GitObjectId {
    Sha1(Sha1Digest),       // exactly 20 bytes
    Sha256(Sha256Digest),   // exactly 32 bytes
}

pub struct GitPath(Vec<u8>);

pub struct LineRange {
    pub first: NonZeroU32,
    pub last: NonZeroU32,
}
```

Git object IDs serialize as `{ kind, digest }` with digest bytes. `GitPath`
serializes as repository-relative Git bytes, rejects NUL, leading/trailing or
empty segments, and `.`/`..`, treats `/` as the sole separator, and never
normalizes platform or Unicode spelling. Display uses lossless escaping.
`LineRange` is one-based inclusive with `first <= last`; lines split on LF
bytes, with CR retained as content. Resolution, not structural construction,
reports a range beyond the selected blob.

```rust
pub enum ArtifactRef {
    GitCommit { commit: GitObjectId },
    Blob { cid: Cid },
    FileAt { path: GitPath, commit: GitObjectId },
    LineRangeAt { path: GitPath, commit: GitObjectId, lines: LineRange },
    ToolOutput { cid: Cid },
}
```

## Claim construction boundary

`Claim` fields are private. `ClaimSignature` preserves a nonempty byte string
of at most 256 bytes but makes no validity claim. Production construction is
limited to a signer that exactly matches `content.author` or the verified v2
codec decoder. Signing computes the content CID, constructs the codec-bound
signing input, signs it, and returns the closed value. A claim ID is computed,
not redundantly stored in domain content. Unchecked constructors are test-only.

## Architecture

**Domain model.** Existing `src/claim.rs` is split so the `claim` module owns
unversioned current types and private constructors while historical structs
move behind `claim::v1` without changing their derives or bytes. Newtype modules
own validation and canonical collection ordering. `$type`, Lexicon records,
storage `rev`, codec strings, and record CIDs do not enter domain content.

**ATProto boundary.** The publishable `kan-atproto` crate owns the common
`tools.kan.claim` record, its open v1/v2/unknown payload union, generated
Lexicon DTOs, record ceilings, and raw unknown preservation. A thin kan adapter
checks registry codec/payload binding, performs the exact `$type`↔`kind`
conversion, reconstructs canonical domain bytes, verifies CID and signature,
and produces `DecodedClaim`. XRPC inputs keep the textual `scope` selector;
current content and verified provenance use Lexicon `bytes` for `scopeId`, with
the adapter enforcing the exact multihash algorithm and length.

**Identity and signing.** `src/identity/authorship.rs` drops `modern` wording
and owns `Author` around the shared validated `SigningIdentity`; local profiles
in `src/identity/system.rs` wrap the same kernel as `ActorReference` rather
than duplicating its validation. `Author` is serde-transparent over the
canonical identity map, while profile JSON uses an explicit local DTO and
checked conversion. The signer constructs the codec-bound claim signing input
and returns `Claim` only after exact author/profile agreement.
Identity control retains the issue-#244
`IdentityOperation`; a separately domain-separated continuity control event
implements dual-proof migration semantics. #245 renames current repository
domain types and canonical identifier bytes to scope terminology before vector
freeze.

**Storage.** `src/store/log.rs` keeps one `tools.kan.claim` collection. Appends
select v2 only for verified scope mode. Reads preserve and classify every
record, including unknown future arms and invalid pairs. Historical CAR blocks
and `dev.kan.claim` commits remain reachable; no migration rewrites them.

**Compatibility projection.** `ClaimView<'a>` borrows either a current claim or
a `V1ClaimView<'a>` and exposes common reasoning inputs without serializing.
For a v1 claim bound by `kanV1Workspace`, a valid local rkey maps directly to
the current subject path; otherwise its RFC 2 address uses
`subject/@cid:<CID-of-canonical-v1-SubjectRef>`. This is a typed URI selector,
not a user-creatable reserved `SubjectPath`. Compatibility folds key these
claims by `ResolvedSubject::LegacyCid`; current writers and relation bodies
accept only the path arm. Anchor structure also becomes `ResourceRef`.
V1 role declarations can expose role-naming semantics; v1 GitTree publication
remains a disclosed target-unresolved legacy intent; unknown bodies remain
fold-inert. Every output retains original codec and claim ID.

**Workspace and CLI.** Workspace opening classifies `Uninitialized`, verified
`V1`, verified `Claim`, or `Incomplete` before choosing any writer. `kan init`
shares the identity enrollment action, collects explicit v1 binding and
continuity choices, installs inception atomically, and activates v2 only after
verified readback. CLI, MCP, GUI, and TUI expose structured initialization and
migration results rather than duplicating policy.

**Folds and views.** Fold, status, context, GUI, and TUI accept `ClaimView`.
Signing and mutation accept only current `ClaimContent`/`Claim`. Unbound,
unsupported, invalid, and admission-excluded material remains inspectable with
separate diagnostics and never silently influences a fold.

## Acceptance Criteria

- AC-1: Compile-time examples prove that unsupported records cannot enter a
  fold without an explicit unsupported-handling branch. (REQ-2, REQ-16)
- AC-2: Canonical vectors cover current, v1, unknown codec/union arm,
  codec-content mismatch, malformed input, and non-canonical input. (REQ-2,
  REQ-7, REQ-12)
- AC-3: A v2 signature verifies only over the exact codec-bound signing input;
  the same signature fails over raw CID bytes, another codec, and a control
  signing input. (REQ-6, REQ-14)
- AC-4: A claim resolved through two distinct locators and through its `@id:`
  selector derives the same `ScopeId`; locator or authority changes do not
  change claim identity. Literal and percent-encoded `@` in a purported regular
  locator are rejected rather than reinterpreted. (REQ-4)
- AC-5: A locator whose evidence derives a different `ScopeId` fails with an
  explicit identity-mismatch result. (REQ-4)
- AC-6: Claim, delegation, governance-event, and generic CIDs cannot be
  interchanged without explicit checked conversion. (REQ-5, REQ-13)
- AC-7: Current construction refuses a missing or out-of-range recording time;
  v1 decoding preserves historical absence byte-for-byte. (REQ-3, REQ-7)
- AC-21: Property tests feed the same malformed principal, method, controller,
  version-kind, and static-method combinations through `Author` and
  `ActorReference`; both reject identically through `SigningIdentity`, while
  compile-time examples show that neither wrapper is implicitly accepted as
  the other and purpose checks remain operation-specific. (REQ-19)
- AC-22: Canonical author vectors encode `principal`, `verificationMethod`, and
  `identityVersion` directly under `author`, including CID links where
  applicable. Profile JSON round-trips through `IdentityProfileDto`, but no
  profile serializer is callable as a claim-author serializer and changing
  its textual CID representation leaves canonical author bytes unchanged.
  (REQ-20)
- AC-23: Hosted fixtures accept both a named `scope` locator and an
  `@id:b...` selector, return the same 34-byte verified `scopeId`, and reject
  malformed length, algorithm, or encoding before domain construction. V2
  record vectors contain one binary scope value and no duplicate multibase
  text; v1 string scope fields remain byte-exact compatibility data. (REQ-21)
- AC-24: Two syntactically distinct named and `@id:` requests remain distinct
  `CanonicalRequestUri` values while resolving to equal `ResolvedTarget`
  values. Changing authority or snapshot changes the source results without
  changing target equality, and `directUri` is labeled optional navigation
  output rather than canonical identity. (REQ-22)
- AC-25: `@cid:` parser vectors cover canonical and noncanonical CID spellings
  without reading evidence. Resolution fixtures construct
  `LegacySubjectRefId` only for an exact canonical v1 `SubjectRef` with valid
  claim verification and scope binding; missing, mismatched, and unbound
  candidates return the specified non-success result without constructing the
  semantic ID. (REQ-23)
- AC-26: Compile-time API tests prove that scoped resources, freestanding
  principals, and authority identities return distinct
  `ResolutionResult<T>` instantiations. JSON/DTO fixtures reject a scope on a
  freestanding target, reject scoped resource fields on identity targets, and
  keep scoped-principal evaluation context outside `PrincipalTarget` equality.
  (REQ-24)
- AC-27: Multi-source fixtures retain available, denied, and incomplete source
  results independently and produce an immutable replay selector for every
  contributing snapshot. Successful-domain conversion rejects empty arrays
  and arrays with no contributing available source; changing `directUri`
  leaves request, target, source provenance, and replay equality unchanged.
  (REQ-25)
- AC-28: Multi-source response vectors exercise every `SourceOutcome` arm and
  reject impossible field combinations. A successful result with one
  contributing source retains independently denied, missing, rejected,
  resource-absent, and snapshot-unavailable selections rather than collapsing
  them into diagnostics or one global access bit. (REQ-26)
- AC-29: Snapshot-set vectors canonicalize source entries, reject duplicates,
  decode self-contained multibase base64url replay values, and recompute the
  returned `SnapshotSetId` without resolver-side storage. Multi-source,
  one-source, contributed, and resource-absent cases include exactly the
  observed snapshots; denied, missing, rejected, and unavailable cases add no
  entry. Native Git and AT replay vectors retain their direct commit selector.
  (REQ-27)
- AC-30: Boundary vectors accept every declared maximum and reject each
  maximum plus one, including encoded inputs whose decoded upper bound is too
  large. Fuzz tests allocate within a fixed bound for malformed percent,
  base64url, and DAG-CBOR input, and no compressed token is accepted. (REQ-28)
- AC-31: Snapshot codec vectors round-trip every supported substrate, reject
  cross-substrate values, preserve an unknown codec byte-exactly while
  refusing replay, and reject an AppView timestamp or cursor where a selection
  manifest CID is required. Emitted vectors use only the five declared
  `tools.kan.snapshot.*.v1` identifiers. (REQ-29)
- AC-32: An unknown snapshot codec remains byte-exact inside
  `DecodedSnapshotSet`, whose ID equals the CID of the original canonical
  token. Re-emission reproduces that token, typed construction rejects the
  unknown arm, and replay refuses the whole set rather than contacting only
  supported entries. (REQ-30)
- AC-33: AppView manifest fixtures verify every evidence block against the
  declared account commit and manifest CID, reject target/account/evidence
  mutation, exclude trust, `at`, index time, and cursor values from manifest
  content, and reject pagination cursors bound to another manifest. An
  uncommitted or partial selection cannot emit immutable replay. (REQ-31)
- AC-34: Decoder vectors distinguish unknown canonical codec content from
  malformed CBOR, noncanonical encoding, duplicate/misordered entries, limit
  violations, invalid known payloads, and codec/payload mismatches. Only the
  unknown canonical case preserves and re-emits the original whole token; all
  invalid cases construct no semantic set and no case permits partial replay.
  (REQ-32)
- AC-35: Regenerated control vectors use only the seven declared
  `tools.kan.*` signing domains. Searches and negative vectors prove that old
  pre-release domains are neither emitted nor accepted; released claim-v1
  fixtures remain readable, and detected `.kan/repository` development state
  produces a non-destructive remediation diagnostic. (REQ-33)
- AC-8: Released-workspace fixtures retain every v1 claim and continue to
  expose its original CID and signature in a mixed v1/v2 store. (REQ-7, REQ-8,
  REQ-16)
- AC-9: No current domain source identifier contains `modern`, `current`, or
  `v2`; boundary scans permit `v1`/`v2` only in the declared compatibility and
  protocol modules. (REQ-1)
- AC-10: `kan init` with no system identity reports `kan identity init` then
  `kan init`, leaves the workspace byte-identical, and succeeds on retry after
  identity initialization. (REQ-10)
- AC-11: An empty directory, a valid v1 workspace, a verified current scope,
  and partial current initialization classify into four distinct modes; none
  silently falls through to another writer. (REQ-8, REQ-10, REQ-18)
- AC-12: A continuity event requires both exact principals' proofs, changes no
  historical bytes, authorizes only the current-to-v1 correction direction,
  and grants no governance or capability. (REQ-15)
- AC-13: Referents canonicalize to one order, reject duplicates, and remain
  distinct from citations and artifacts in projections and reasoning. (REQ-11,
  REQ-13)
- AC-14: Every body arm has a canonical domain vector and ATProto inverse
  vector; mutations of `kind`, fields, or codec/content pairing fail in the
  declared invalid/unsupported class. (REQ-12)
- AC-15: SHA-1/SHA-256 object IDs, non-UTF-8 Git paths, and one-based line
  ranges round-trip byte-exactly across domain CBOR and the v2 DTO. (REQ-13)
- AC-16: Production APIs cannot construct a `Claim` from arbitrary signature
  bytes; signer mismatch and verification failure never yield a domain claim.
  (REQ-14)
- AC-17: Publication intent rejects a target with a different scope/subject,
  evaluation inputs, or immutable write target, and never supplies transport
  credentials. (REQ-17)
- AC-18: `1.0.0-beta.1` migration fixtures cover uninitialized, v1, activated,
  incomplete, continuity accepted/declined/unavailable, old-binary rollback,
  and mixed-codec histories without rewriting one historical block. (REQ-8,
  REQ-15, REQ-18)
- AC-19: V1 subject projection maps valid locals directly, addresses every
  incompatible bound reference through `subject/@cid:<cid>`, retains anchor
  referents and the original selector, and refuses to bind a workspace value
  absent from signed inception. Claims with the same canonical v1 subject CID
  fold into one read-only legacy history; parsing `@cid:` never produces an
  ordinary user-authored `SubjectPath`, and a v2 writer cannot target the
  legacy arm. Ordinary paths containing literal or decoded `%40` are rejected,
  selector suffixes are rejected, and unknown `@...` forms never fall back to
  paths. (REQ-11, REQ-15, REQ-16)
- AC-20: #245's scope identifier round-trips exact multihash bytes through
  current Rust types, claim and control CBOR, canonical `b...` display, and
  RFC 2 `@id:b...` parsing/rendering. Current constructors reject historical
  `kan-repo:` text, alternate multibase spellings, wrong algorithms, and wrong
  digest lengths before any v2 vector is frozen. (REQ-9)

## Open questions

None within this design. Issue #245 must apply the settled binary, display, and
URI scope-identifier representations before v2 schemas, signing vectors, or
migration fixtures are frozen.

## Out of scope

- Rewriting or re-signing any historical claim.
- Treating locators, Git remotes, ATProto repositories, or hosted accounts as
  scope identity.
- Implementing source changes before this design passes its interactive and
  adversarial review gates.
