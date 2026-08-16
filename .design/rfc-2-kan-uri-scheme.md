# Feature: RFC 2 — kan URI scheme

## Summary

Define interoperable `kan`, `kan+git`, and `kan+at` URI schemes for addressing
claims, subjects, and identities within RFC 1 kan scopes. The design separates
logical scope identity, authority-local routing, source selection, immutable
snapshots, repository admission, source access, and consumer trust so that a
URI never silently conflates where evidence came from with what that evidence
means.

## Requirements

- REQ-1: Every v1 URI identifies exactly one resource kind—`claim`, `subject`,
  or `identity`. Claims and subjects are always within a kan scope whose stable
  identifier is the RFC 1 `kan-repo:` identifier derived from
  `RepositoryInception` in `rfcs/1-identity-system.md`. Identity resources may
  instead identify a resolver authority or a freestanding principal without
  inventing a scope.
- REQ-2: `kan://` uses the hierarchical shape
  `kan://<authority>/<scope-locator>/<resource-kind>/<resource-key>`. A named
  scope locator is exactly one path segment made from non-empty,
  colon-separated lowercase ASCII labels and is resolved by exact match. The
  `kan-repo:` prefix is reserved for direct stable scope identifiers.
- REQ-3: Resolution distinguishes five concepts: a **scope** is the logical
  governance and admission namespace; a **locator** is an authority-local name
  for a scope; a **source** is a scope-specific body of evidence available to a
  resolver; a **snapshot** is an immutable observation of a source; and a
  **substrate** is the physical or protocol system from which a source is
  derived.
- REQ-4: A resolver maps a locator or stable scope identifier to one or more
  available sources, verifies source inception evidence against the resulting
  `kan-repo:` identifier, selects or combines sources under explicit
  evidence-selection inputs, and reports source and snapshot provenance.
- REQ-5: The complete URI is a resolution-request identifier. Its target key
  consists of resource kind and resource key plus a scope identifier when the
  resource is scoped. Query parameters are typed as evidence-selection or
  evaluation inputs; parameters in the two classes MUST NOT be interpreted
  interchangeably.
- REQ-6: Source access is independent of RFC 1 repository admission and
  consumer trust. Public and private characterize sources, not scopes.
  Resolution distinguishes inaccessible sources, absent sources, and resources
  absent from a selected snapshot, and never silently substitutes a less
  privileged source as an equivalent result.
- REQ-7: `kan://` and `kan+at://` forbid userinfo. `kan+git://` permits userinfo
  only as a transport username; its presence selects SSH and never denotes an
  actor, credential, trust frame, repository authority, or claim author.
- REQ-8: Subject resource keys preserve RFC 1 subject-prefix semantics. Literal
  `/` separates hierarchy; canonical output percent-encodes non-ASCII UTF-8
  with uppercase hex; Unicode is not normalized; and empty, trailing, dot,
  dot-dot, encoded-slash, NUL, invalid UTF-8, and multiply decoded forms are
  rejected.
- REQ-9: Mutable source selection is allowed for convenience, but every
  successful resolution reports the immutable snapshot used and an immutable
  replay URI. Immutable selectors never fall forward to a current snapshot;
  mutable Git refs and immutable commits are mutually exclusive, and Git
  commits use full object identifiers.
- REQ-10: Resolution is read-only as required by
  `rfcs/1-identity-system.md`: parsing or resolving a URI never selects an
  acting principal, signs an operation, changes admission, changes the trust
  frame, or silently authorizes credential use.
- REQ-11: The RFC follows the lifecycle, authority, security review, and
  machine-checkable vector requirements in `rfcs/0-rfc-and-adr-process.md` and
  uses the required sections in `rfcs/template.md`.
- REQ-12: Scheme-specific resolution defines deterministic behavior for kan
  manifests, Git transport inference and repository boundaries, and ATProto
  handle/DID/PDS/AppView traversal without treating a Git repository or an
  ATProto repository as the kan scope itself.
- REQ-13: Identity resources distinguish scope identity, resolver-authority
  identity, scoped principal resolution, and freestanding DID resolution.
  Scoped principal resolution uses the scope's selected evidence; freestanding
  resolution uses configured DID sources. Neither selects an acting identity.
- REQ-14: `tools.kan.claim` is the canonical claim collection on every
  substrate, including the local MST in `src/store/log.rs`. One signed kan
  claim occupies one immutable record keyed by its kan content CID. Migration
  from the early `dev.kan.claim` collection converts every claim supported by
  the current kan decoder into the typed `tools.kan.claim` representation. The
  specified inverse conversion reproduces the original canonical signed
  `ClaimContent` bytes, preserving claim CIDs, signatures, and append-only
  reachability; migration neither dual-writes nor treats an ATProto record CID
  as the claim's identity. Unsupported codecs and unknown body kinds fail as
  `UnsupportedClaimCodec` rather than publishing opaque data.
- REQ-15: The canonical AppView exposes three typed XRPC queries:
  `tools.kan.getClaim`, `tools.kan.getSubject`, and
  `tools.kan.getIdentity`. They reference shared provenance and snapshot
  definitions, and only collection-valued results use the standard opaque
  `cursor` pagination contract.
- REQ-16: For `kan+at`, an omitted `commit` selects current account-repository
  state and discloses its verified commit CID. A supplied `commit` succeeds
  only from that exact verified repository state, whether retained by an
  AppView, returned as current by a PDS, or present in a verified local cache;
  otherwise resolution returns `snapshot-unavailable` and never falls forward.
  RFC 2 imposes no historical-retention minimum.
- REQ-17: The canonical kan AppView is discovered from the authority for the
  `tools.kan.*` Lexicons. The DID published through `_lexicon.kan.tools` is
  also the canonical service DID; its DID document supplies the
  `#kan_appview` service entry and HTTPS origin. Alternate AppViews require an
  explicit complete DID-plus-fragment `service` selector.
- REQ-18: The canonical source repository for the ATProto schema surface is
  `kan-tools/kan-lexicon`. Its `lexicons/tools/kan/` tree owns and releases
  `claim.json`, `defs.json`, `getClaim.json`, `getSubject.json`, and
  `getIdentity.json`. This repository pins an immutable `kan-lexicon` revision
  and vendors byte-identical RFC validation snapshots under
  `.design/rfc-2-lexicons/`; those snapshots are not a second publication
  source. The schemas parse and lint with
  an implementation independent of kan, use closed unions for the current
  supported claim and identity variants, and define the exact query
  parameters, typed outputs, pagination fields, and stable XRPC error names.
  Narrative fields retain enough capacity for current valid kan claims within
  ATProto's record-size limit; the independent style linter's resulting six
  `large-string` warnings are an explicit compatibility exception rather than
  a reason to move signed content into non-invertible blob references.

## Acceptance Criteria

- [ ] AC-1: A normative data model and ABNF parse every mandatory vector into
      authority, one-segment scope locator or stable scope identifier, one of
      the three v1 resource kinds, resource key, evidence-selection inputs,
      and evaluation inputs. (REQ-1, REQ-2, REQ-5)
- [ ] AC-2: Vectors prove exact named-locator matching, rejection of empty
      colon labels and reserved `kan-repo:` aliases, and equivalence of named
      and stable locators only after both verify the same inception-derived
      scope identifier. (REQ-1, REQ-2, REQ-4)
- [ ] AC-3: Resolution-result vectors report scope, locator, every consulted or
      inaccessible source, each source substrate, immutable snapshot, admission
      result, and trust result as separate fields. (REQ-3, REQ-4, REQ-6)
- [ ] AC-4: Query vectors classify every v1 parameter as evidence selection or
      evaluation, reject forbidden combinations and duplicate singleton
      parameters, and produce one canonical query ordering. (REQ-5)
- [ ] AC-5: Access vectors distinguish `access-denied`, `source-not-found`, and
      `resource-not-found-at-snapshot`, and prove that denial does not silently
      fall back to a public source. (REQ-6)
- [ ] AC-6: Authority vectors reject userinfo for `kan` and `kan+at`, accept a
      username without password material for `kan+git`, select SSH when it is
      present, and prove that it never changes actor, admission, or trust.
      (REQ-7, REQ-10)
- [ ] AC-7: Subject vectors cover slash hierarchy, UTF-8 percent encoding,
      uppercase canonical escapes, non-canonical encoded unreserved bytes,
      distinct NFC and NFD subjects, and rejection of empty, dot, dot-dot,
      encoded-slash, NUL, invalid UTF-8, and double-decoding inputs. (REQ-8)
- [ ] AC-8: Snapshot vectors resolve an omitted selector and a mutable ref to a
      disclosed immutable snapshot and replay URI, reject abbreviated Git
      hashes and simultaneous `commit` plus `ref`, and fail rather than drift
      when an immutable snapshot is unavailable. (REQ-9)
- [ ] AC-9: Read-only negative controls prove that resolution does not select a
      signing identity, invoke an operation, grant source access, alter
      repository admission, or mutate the consumer trust frame. (REQ-10)
- [ ] AC-10: Scheme matrices exercise local and hosted `kan` authorities, Git
      SSH and deterministic non-userinfo transport inference, ATProto handle
      and reserved DID authority forms, direct and mediated ATProto sources,
      and the failure classes at every resolution step. (REQ-11, REQ-12)
- [ ] AC-11: `scripts/check-rfcs-adrs.sh` accepts
      `rfcs/2-kan-uri-scheme.md`, and the RFC contains no unresolved blocking
      question when it enters Accepted status. (REQ-11)
- [ ] AC-12: Identity vectors distinguish `identity/scope`,
      `identity/authority`, scoped `identity/principal/did/<method>/<id>`, bare
      authority `/identity`, and freestanding
      `kan://did/<method>/<id>/identity`; prove that scoped and freestanding
      resolution can see different evidence while returning the same canonical
      principal DID; and exercise historical `version` selection. (REQ-5,
      REQ-10, REQ-13)
- [x] AC-13: Migration fixtures containing only `dev.kan.claim`, only
      `tools.kan.claim`, and both collections prove that migration verifies
      every claim, converts legacy records through the current typed schema,
      reconstructs the original canonical `ClaimContent` bytes byte-for-byte,
      preserves claim CIDs and signatures, rejects non-identical key
      collisions, produces one canonical `tools.kan.claim` entry per claim,
      and remains readable after reopening. Negative controls for an unknown
      body kind, unsupported codec, non-invertible conversion, and substitution
      of the enclosing ATProto record CID for the claim CID all fail. (REQ-14)
- [ ] AC-14: Lexicons published from `kan-tools/kan-lexicon` for
      `tools.kan.claim`,
      `tools.kan.defs`, `tools.kan.getClaim`, `tools.kan.getSubject`, and
      `tools.kan.getIdentity` validate with an independent Lexicon toolchain.
      Generated clients from two implementations issue byte-equivalent query
      parameters for every RFC vector and decode the same typed result. Only
      collection-valued results accept `limit` and opaque `cursor`, and every
      later page is bound to the first page's repository commit. (REQ-15)
- [ ] AC-15: ATProto snapshot vectors prove that an omitted `commit` returns a
      verified current commit and immutable replay URI; an exact current or
      retained commit succeeds; an unavailable commit returns
      `snapshot-unavailable`; and neither AppView nor direct-PDS resolution
      substitutes current state. The same logical query at the same retained
      commit produces equivalent evidence through both sources. (REQ-16)
- [ ] AC-16: Service-discovery vectors resolve `_lexicon.kan.tools`, verify the
      returned namespace DID, select its exact `#kan_appview` DID service
      entry, reject missing, duplicate, mismatched-fragment, non-HTTPS, and
      path-bearing endpoints, and construct the same direct XRPC origin and
      `atproto-proxy` service reference in two implementations. Explicit
      alternate service selection never changes Lexicon authority. (REQ-17)
- [ ] AC-17: `kan` pins an immutable `kan-tools/kan-lexicon` revision; a sync
      gate proves its five vendored snapshots are byte-identical to that
      revision. `goat lex parse .design/rfc-2-lexicons/*.json` passes all five
      schemas. `goat lex lint .design/rfc-2-lexicons` reports exactly the six
      declared `large-string` warnings on narrative claim bodies and no other
      finding. A second generated client implementation agrees on each mandatory
      request, response, union discriminator, and error name. Mutation checks
      reject a removed required field, an open claim-body union, pagination on
      `getClaim`, and an error spelling not declared by its endpoint. (REQ-18)

## Architecture

### Core model

RFC 1's “repository scope” is called a **kan scope** in RFC 2 so that it is not
confused with either a Git repository or an ATProto repository. The accepted
`RepositoryInception`, `repository` fields, and `kan-repo:` wire identifier are
unchanged. The governing definitions are in `rfcs/1-identity-system.md`; the
current source/substrate boundary is represented by `src/transport/mod.rs`,
`src/transport/git_tree.rs`, and the workspace aggregation in
`src/workspace.rs`.

A scope is the logical namespace in which governance, capabilities, subject
prefixes, and admission are evaluated. A locator is a resolver-authority-local
route to that scope. A source is a pre-fold, pre-trust body of evidence about
exactly one scope; it may contain valid, invalid, admitted, unadmitted,
contested, or incomplete material. A snapshot is an immutable observation of
that source. A substrate is the local log, Git tree, ATProto repository,
AppView, hosted store, or other physical/protocol carrier from which a source
is derived.

An ATProto repository may carry records for several kan scopes. The
scope-specific source projected from those records is not the ATProto
repository itself. Likewise, two authorities can expose different evidence
for one `kan-repo:` scope without contradiction: they are distinct sources and
snapshots for the same logical admission namespace.

Resolution proceeds in layers:

1. parse scheme, authority, locator, resource, and typed query inputs;
2. resolve the named locator or stable `kan-repo:` identifier through the
   authority;
3. discover available scope-specific source descriptors;
4. apply evidence-selection inputs and source-access policy;
5. select immutable snapshots and verify inception evidence against the scope
   identifier;
6. collect and cryptographically verify resource and supporting evidence;
7. evaluate RFC 1 repository admission;
8. apply the explicitly selected or disclosed-default consumer trust frame;
9. report target, provenance, access, validity, admission, and trust
   independently.

### `kan://` routing

The `kan` authority owns a manifest that maps exact, one-segment scope locators
to source descriptors and verified scope identifiers. `local` is reserved for
system kan configuration; a DNS authority such as `kan.maxine.science` obtains
the authority's manifest through the hosted-kan resolution contract.

`backup:kan-tools:day` is a structured locator but not a prefix route. Its
complete spelling is matched exactly. Adding or removing another locator cannot
move the repository/resource parsing boundary or cause fallback to a broader
locator. The next segment after the locator is always `claim`, `subject`, or
`identity`.

### Query inputs

The complete URI names a resolution request, while the target key is resource
kind and resource key plus a verified kan scope when the resource is scoped.
Query inputs are partitioned into evidence selection and evaluation. Git
commits and refs, ATProto source preferences, hosted source choices, snapshot
selectors, and exact RFC 1 identity versions are evidence selection. Trust
frames and trusted evaluation instants are evaluation. They share RFC 3986
query syntax but occupy disjoint registries and are emitted separately in
resolution results.

An omitted trust parameter uses the resolver's configured default only when
the result discloses the exact frame applied. It does not become an implicit
part of the target key.

### Source access

RFC 1 admission answers whether an actor was authorized to act in the kan
scope. Source access answers whether a resolver may disclose evidence. Trust
answers whether disclosed authentic evidence participates in a consumer's
view. None substitutes for another.

Different authenticated evidence sets are distinct sources or explicitly
named disclosure projections, not one source and snapshot that silently varies
by requester. Authentication may select or unlock a source, but never changes
scope identity. The result distinguishes denial from absence and identifies
every source that contributed evidence.

### Subject paths

Everything after `/subject/` reconstructs one subject by joining decoded
segments with literal `/`. Parsing separates components and segments before
one UTF-8 percent-decoding pass. Encoded `/`, complete dot segments, empty
segments, invalid UTF-8, and NUL are errors. Producers percent-encode all
non-ASCII UTF-8 octets, uppercase escape hex, and do not encode unreserved
ASCII. Unicode normalization is forbidden, preserving RFC 1 text identity.

### Snapshot discipline

A request may select a mutable current state or symbolic ref, but a successful
result always identifies the immutable snapshot used and supplies a replayable
immutable request. A snapshot commits only to the evidence exposed by that
source, not to universal completeness for the scope. Trust changes evaluation
without changing the source snapshot.

### Canonical claim collection and migration

The local log already stores one signed claim per MST record and keys it by the
claim content CID in `src/store/log.rs`; that granularity is retained. The
early collection name `dev.kan.claim` is replaced everywhere by the
authority-backed public Lexicon name `tools.kan.claim`. Its schema is
`.design/rfc-2-lexicons/tools.kan.claim.json`. The canonical record carries the
original claim CID, the closed codec token `kan-claim-v1`, a fully typed current
projection of `ClaimContent`, the original signature, and the storage revision
TID. Its record key is the kan claim CID. The enclosing ATProto record CID
authenticates the converted record but never replaces the claim CID used by
signatures and citations.

Migration walks every legacy record, decodes it with the current supported kan
decoder, checks its CID and signature, maps every known enum into the closed
`$type` unions in `.design/rfc-2-lexicons/tools.kan.defs.json`, and inserts the
converted record under `tools.kan.claim/<claim-cid>`. Verification performs the
normative inverse conversion for `kan-claim-v1` and requires the reconstructed
canonical DAG-CBOR bytes to hash to `claimCid` before checking the signature.
Absence of historical optional fields such as `recorded_at` remains absence in
the typed record, so the inverse does not invent bytes. Unknown body kinds and
unsupported codecs are refused as `UnsupportedClaimCodec`; they are not
silently dropped or published through an untyped escape hatch.

The `kan-claim-v1` conversion is closed and mechanical. Historical Serde enum
tags become the corresponding fully-qualified `$type` in `tools.kan.defs`:

| historical tag family | typed definitions |
|---|---|
| `Workspace`, `Commit`, `Blob`, `FileAt`, `LineRangeAt` | `#workspaceAnchor`, `#commitAnchor`, `#blobAnchor`, `#fileAtAnchor`, `#lineRangeAtAnchor` |
| `Local`, `Anchor` | `#localSubject`, `#anchorSubject` |
| `Commit`, `FileAt`, `LineRangeAt`, `ToolOutput` artifacts | `#commitArtifact`, `#fileAtArtifact`, `#lineRangeAtArtifact`, `#toolOutputArtifact` |
| `Subject`, `Observation`, `Plan`, `Decision`, `Blocker`, `Resolution`, `Result`, `Status`, `Relation`, `Retraction`, `Rejects`, `Publication`, `RoleDeclaration` | the same lower-camel stem plus `Body` |

Tuple fields become named object fields (`path`, `sha`, `span`); Rust field
names become lower camel case (`subject_kind` to `subjectKind`, `recorded_at`
to `recordedAt`); enum values become the closed kebab-case values declared in
the Lexicon (`InProgress` to `in-progress`, `SameAs` to `same-as`, `GitTree`
to `git-tree`). The inverse applies this table exactly. Optional
`recordedAt` is omitted if and only if historical `recorded_at` was absent.
`claimCid`, `codec`, `signature`, and `rev` are envelope fields and are never
inserted into the reconstructed `ClaimContent` map.

If both collections contain the same key, migration accepts the canonical
record only when its inverse reconstructs the exact legacy signed content and
signature; any mismatch is corruption and stops the migration. A new signed
repository commit makes the canonical MST reachable only after every record
passes. Readers may recognize the legacy collection during the bounded
migration window, but writers write only `tools.kan.claim`; there is no
dual-write state and no deletion of historical CAR blocks.

### ATProto Lexicons and XRPC queries

The five schemas are authored and released from the separate
`https://github.com/kan-tools/kan-lexicon` repository under
`lexicons/tools/kan/`. That repository owns schema evolution, code-generation
configuration, cross-language generated-client fixtures, and release tags.
The `kan` repository consumes an immutable revision and keeps byte-identical
snapshots under `.design/rfc-2-lexicons/` so RFC review and offline CI do not
depend on a network checkout. A sync gate MUST reject either local drift from
the pinned upstream revision or an unreviewed pin change. Runtime resolution
never fetches GitHub: NSID authority remains the DID obtained through
`_lexicon.kan.tools`, so source-code hosting and protocol authority stay
separate.

The five literal snapshot schemas under `.design/rfc-2-lexicons/` are the
`tools.kan.claim` record, `tools.kan.defs` shared claim/result/provenance
definitions, and three typed queries:
`tools.kan.getClaim`, `tools.kan.getSubject`, and
`tools.kan.getIdentity`. Resource-specific methods keep generated clients
precise and allow later resource kinds to arrive under new NSIDs instead of
widening a central union. Every result carries the same verified account DID,
kan scope, source kind, account-repository commit CID, AppView state when
applicable, completeness, canonical URI, and immutable replay URI.

`getClaim` returns one exact claim and is not paginated. `getSubject` returns a
collection of claim result objects and uses optional `limit` and opaque
`cursor`. `getIdentity` returns a typed identity result; when supporting
identity claims form a collection, that collection uses the same pagination
contract. Clients omit `cursor` initially, hold every other input fixed, and
continue only while a cursor is returned. A cursor is source-specific and
commit-bound; changing the account commit invalidates it rather than silently
continuing in newer state.

`getClaim` requires `repo`, `scope`, and `cid`; `getSubject` requires `repo`,
`scope`, and `subject`; `getIdentity` requires `repo` and the closed `kind`
selector, with scope, DID, and identity version constrained by that kind. All
three accept an optional account-repository `commit`. The two collection-valued
methods alone accept `limit` and `cursor`. Each method declares its resource-
specific not-found error plus `SnapshotUnavailable`, `InvalidClaim`,
`UnsupportedClaimCodec`, and `IndexNotReady`; paginated methods additionally
declare `InvalidCursor` and `CursorSnapshotMismatch`.

### ATProto snapshot availability

A normal PDS is a current repository host, not an archive. With no `commit`
selector, resolution obtains current state, verifies its signed repository
commit, and reports that CID plus a replay URI containing it. With `commit`, a
resolver must possess and verify exactly the selected repository state. A PDS
path therefore normally succeeds only when the requested CID is current,
unless the resolver has a previously verified snapshot; an AppView succeeds
only for commits it retained and indexed. Failure is `snapshot-unavailable`,
never a retry against current state. Immutable identity and durable
availability remain separate: RFC 2 defines the former and makes no archival
retention promise.

### Canonical AppView discovery

The `tools.kan` NSID authority resolves through the `_lexicon.kan.tools` DNS
TXT record. The DID named there both publishes the authoritative Lexicons and
identifies the canonical AppView service. Its DID document contains exactly
one applicable `#kan_appview` entry of kan AppView service type whose endpoint
is an HTTPS origin. Public queries call that origin directly. Authenticated
queries may pass the complete `<did>#kan_appview` reference in the standard
`atproto-proxy` header. An explicit `service` selector may name another
DID-plus-fragment AppView, but does not alter which authority defines the
`tools.kan.*` schemas. Results disclose the exact service reference, endpoint,
and index state used.

## Resolved Questions

- RQ-1: Query parameters are typed resolution inputs. Evidence selectors and
  evaluation inputs remain normatively separate even though both use the query
  component.
- RQ-2: Userinfo is forbidden in `kan` and `kan+at`. In `kan+git`, `user@` selects
  SSH and otherwise carries transport-username semantics only.
- RQ-3: `kan://` uses one exact-match, colon-structured scope-locator segment.
  `kan-repo:` is reserved for stable scope identifiers.
- RQ-4: A kan scope is distinct from authority-specific sources and their snapshots.
  A resolver may expose or combine several sources for one scope.
- RQ-5: Read access belongs at the source boundary; admission remains scope/action
  evaluation and trust remains consumer evaluation.
- RQ-6: Subject hierarchy uses literal slash and strict, single-pass UTF-8 percent
  encoding without Unicode normalization.
- RQ-7: Mutable requests are permitted, but immutable snapshot disclosure and replay
  are mandatory.
- RQ-8: `kan+git` uses the same one-segment, colon-structured scope locator as
  `kan`. Its labels map deterministically to Git remote path segments; an
  explicit `.git` suffix is preserved rather than inferred. Userinfo selects
  SSH, a DNS authority without userinfo selects HTTPS, and `local` selects the
  locally configured GitTree source. There is no transport or path probing.
- RQ-9: `kan+at` normally resolves a handle to an account DID and queries the
  canonical kan AppView implementing the `tools.kan.*` Lexicons. Scope and
  subject routing are derived from public records and returned with inception
  evidence; no stored manifest is required. Direct PDS retrieval is an
  explicitly selectable alternate source applying the same derivation. A
  `commit` selector names the underlying account-repository snapshot for both
  paths, and an unavailable historical snapshot is an explicit failure.
- RQ-10: The DID resolved as the `tools.kan.*` Lexicon namespace authority is
  also the canonical AppView service DID. Its DID document publishes the
  `#kan_appview` service entry. Public reads may call that HTTPS origin
  directly; authenticated future reads may use the complete
  `<did>#kan_appview` reference with standard PDS XRPC service proxying.
- RQ-11: The closed v1 query registry separates evidence selectors `source`,
  `service`, `commit`, `ref`, `snapshot`, and `version` from evaluation inputs
  `trust` and `at`. `source` is a sorted, duplicate-free set; the others are
  singletons. `version` encodes one RFC 1 `IdentityVersion` and applies only to
  principal identity resolution. Unknown parameters, duplicate singletons,
  empty values, and scheme-inapplicable combinations fail. `at` is an unsigned
  canonical base-10 Unix timestamp in microseconds. Canonical ordering emits
  evidence selectors before evaluation inputs.
- RQ-12: Identity resources are a typed family. `identity/scope` returns the verified
  `kan-repo:` identifier, inception evidence, governance standing, and source
  provenance. `identity/authority` identifies the resolver authority without
  implying governance. Scoped `identity/principal/did/<method>/<id>` resolves
  a principal against scope-selected evidence. Bare `/<authority>/identity`
  identifies that authority, and `kan://did/<method>/<id>/identity` performs
  freestanding DID resolution. `self` is forbidden.
- RQ-13: Outer URI fragments are forbidden in v1. Claims and identities are
  semantically atomic; subject operations are typed query semantics rather
  than an unspecified composition fragment. Semantic identity subresources
  use explicit paths, encoded `#` remains component data where allowed, and a
  parser never silently discards an unsupported fragment.
- RQ-14: One claim is one immutable `tools.kan.claim` record keyed by its kan
  content CID on local and ATProto substrates. The early local
  `dev.kan.claim` namespace is migrated through a fully typed current
  representation whose codec-specific inverse reconstructs the original
  canonical signed content bytes. Claim CIDs and signatures survive; unknown
  or unsupported claims fail explicitly; writers never dual-write.
- RQ-15: AppView resolution uses the three typed methods
  `tools.kan.getClaim`, `tools.kan.getSubject`, and
  `tools.kan.getIdentity`, backed by shared `tools.kan.defs` provenance and
  snapshot types, rather than one resource-neutral resolver method.
- RQ-16: ATProto `commit` always selects the exact account-repository commit.
  Current PDS state, retained AppView state, and a verified cache differ only
  in availability; an unavailable selection fails with `snapshot-unavailable`
  and RFC 2 promises no retention duration.
- RQ-17: Canonical AppView discovery follows the `tools.kan` namespace DID to
  its `#kan_appview` service entry. Alternative AppViews are explicit complete
  service references and never become alternate Lexicon authorities.
- RQ-18: `kan-tools/kan-lexicon` is the canonical schema and release repository;
  this repository carries pinned, byte-identical RFC snapshots rather than a
  competing publication source. Claim, anchor, subject, artifact, body, and
  identity variants are closed `$type` unions; XRPC outputs are typed; and the
  exact parameters, cursor fields, provenance, and stable errors are fixed by
  those schemas. The
  official Go ATProto parser and linter are the first independent schema check.
  Its six narrative-size warnings are accepted because the current kan format
  permits signed inline prose and this repository already contains a claim
  larger than the linter-preferred ceiling; blobs cannot reconstruct the
  signed canonical bytes without adding a second unavailable object.

## Open Questions

None.

## Out of Scope

- Implementing RFC 1 identities, governance, delegations, or reference bytes.
- Implementing hosted-kan, Git, PDS, AppView, relay, archive, or replica
  backends.
- Defining concrete authentication, credential exchange, or source ACL
  protocols.
- Treating day streams, worktrees, roles, agents, or harnesses as URI resource
  kinds.
- Adding v1 resource kinds beyond `claim`, `subject`, and `identity`.
- Defining issue #226's future terse references to canonical content already
  present in a Git tree.
- Claim-level read ACLs or encryption-recipient syntax.
- Assuming a source is complete for a scope merely because its snapshot is
  immutable and internally verifiable.
