# RFC 2: kan URI schemes and resolution

- Status: Accepted
- Authors: kan maintainers
- Created: 2026-08-15
- Discussion: https://github.com/kan-tools/kan/pull/230
- Review-period-ends: Not applicable; maintainer override
- Review-override: Maintainer 🚀 approval before merge of https://github.com/kan-tools/kan/pull/230 (2026-08-16; maintainer: @maxinelevesque)
- Supersedes: None
- Superseded-by: None

## Summary

This RFC defines the `kan`, `kan+git`, and `kan+at` URI schemes. They identify
claims, subjects, and identities through local or hosted kan resolvers, Git
trees, and AT Protocol sources without confusing the place evidence was found
with the kan scope in which it is evaluated.

The schemes share one model:

- a **scope** is the logical governance and admission namespace identified by
  the RFC 1 binary `ScopeId` and its canonical base32lower display;
- a **locator** is an authority-local name for a scope;
- a **source** is a scope-specific body of evidence available to a resolver;
- a **snapshot** is an immutable observation of a source; and
- a **substrate** is the physical or protocol system from which a source is
  derived.

Claims and subjects are always scoped. Identities may instead identify the
scope itself, the resolver authority, an explicit principal evaluated against
scoped evidence, or a freestanding DID. Query parameters select evidence and
evaluation inputs in separate namespaces. Resolution is read-only.

## Motivation

kan currently has content-addressed claims, hierarchical subjects, GitTree
publication, local trust frames, and an accepted identity architecture, but no
portable identifier for saying which resource to resolve through which source.
Paths, Git remotes, ATProto handles, DIDs, and scope identifiers answer
different questions. Treating any one of them as the others creates concrete
failure modes:

- a project rename appears to mint a new repository;
- two authorities' partial evidence sets appear falsely identical;
- a trust selector appears to grant repository authority;
- adding a longer route silently changes the repository/resource boundary;
- Git userinfo appears to name an acting kan principal;
- a mutable branch or AppView result is reported without the snapshot actually
  evaluated; or
- URI normalization changes a hierarchical subject and therefore changes
  capability coverage.

RFC 1 separates principal identity, governed scope, cryptographic validity,
scope admission, and consumer trust. This RFC carries that separation
through identifier and resolution syntax.

The design is intentionally uniform where its substrates are not. Git accepts
several incompatible remote syntaxes, and ATProto normally queries an AppView
rather than treating account repositories as application objects. kan URIs use
one scope-locator grammar and map it deterministically onto each substrate.

## Terminology

- **kan scope:** RFC 1's governed scope: the logical namespace in which
  governance, capabilities, subject prefixes, and admission are evaluated. A
  scope is identified by one canonical `ScopeId`. It is not a
  principal, Git repository, or ATProto repository.
- **Scope identifier:** The RFC 1 `ScopeId` derived from canonical scope
  inception bytes.
- **Scope locator:** An authority-local, human-meaningful route such as
  `personal` or `kan-tools:day`. A locator is mutable and is not scope identity.
- **Resolver authority:** The URI authority whose rules locate sources or an
  account. `local` and `did` are reserved authorities with rules below.
- **Source:** A concrete, scope-specific body of pre-fold evidence available to
  a resolver. A source may contain valid, invalid, admitted, unadmitted,
  contested, or incomplete material.
- **Source kind:** A protocol-defined class such as `appview` or `pds`, or a
  resolver-manifest name under `kan`.
- **Snapshot:** An immutable observation of one source. A snapshot commits only
  to evidence exposed by that source, not to all evidence that exists for the
  scope.
- **Substrate:** The physical or protocol carrier from which a source is
  derived, such as a local kan log, Git tree, ATProto repository, or AppView.
- **Target key:** The stable resource description after routing: resource kind
  and key, plus a scope identifier when scoped.
- **Resolution request:** The complete URI, including evidence-selection and
  evaluation query inputs.
- **Evidence selector:** A query input that selects sources, services, or
  snapshots before verification and evaluation.
- **Evaluation input:** A query input applied after evidence selection, such as
  a trust frame or trusted evaluation instant.
- **Canonical URI:** The single spelling emitted for one resolution request
  under this RFC. Two non-identical canonical requests may share a target key.
- **Immutable replay URI:** A canonical URI whose evidence selectors name every
  source snapshot used by a resolution.
- **Authority identity:** Identity evidence for the resolver authority. It does
  not imply governance of a selected scope.
- **Scope identity:** The scope identifier, inception evidence, and resolved
  governance standing. A scope identity is not a principal identity.
- **Scoped principal identity:** A principal resolved using evidence selected
  for a scope.
- **Freestanding principal identity:** A principal resolved through configured
  DID sources without a scope context.

Normative words such as MUST, SHOULD, and MAY have their RFC 2119 meanings.

## Detailed design

### Common URI data model

A conforming parser produces this abstract request before performing network or
storage access:

```text
ResolutionRequest {
  scheme:              "kan" | "kan+git" | "kan+at",
  authority:           Authority,
  scopeLocator:        ScopeLocator or null,
  requestedScope:      ScopeIdentifier or null,
  resource:            Resource,
  evidenceSelection:   EvidenceSelection,
  evaluation:          EvaluationInputs
}

Resource =
  ClaimResource { cid }
  | SubjectResource { subject }
  | ScopeIdentityResource
  | AuthorityIdentityResource
  | PrincipalIdentityResource { did, version? }

EvidenceSelection {
  sources:   [text, ...],
  service:   DID URL or null,
  commit:    text or null,
  ref:       text or null,
  snapshot:  text or null,
  version:   IdentityVersion or null
}

EvaluationInputs {
  trust: TrustSelection or null,
  at:    unsigned integer or null
}

TrustSelection =
  ConfiguredFrame { name }
  | PrincipalSelector { principal, weight }
  | InlineComposite { selectors: [TrustSelector, TrustSelector, ...] }

TrustSelector =
  ConfiguredFrame { name }
  | PrincipalSelector { principal, weight }

principal = DID | CurrentActor | NamedRole { name }
```

The target key is `(scopeIdentifier, resource)` for a scoped request and
`resource` for an unscoped identity request. The complete request, including
query inputs, is a distinct identifier for a resolution operation. Query
inputs do not become part of scope, claim, subject, or principal identity.

### Common ABNF

The grammar uses RFC 5234 ABNF and imports `ALPHA`, `DIGIT`, and `HEXDIG` from
its core rules and `host`, `port`, `pct-encoded`, `unreserved`, and `sub-delims`
from RFC 3986. Rules below are case-sensitive except for the URI scheme and DNS
host rules inherited from RFC 3986.

```abnf
kan-uri       = kan-scheme "://" kan-authority kan-path
                [ "?" kan-query ]
kan-git-uri   = "kan+git://" git-authority git-path
                [ "?" kan-query ]
kan-at-uri    = "kan+at://" at-authority at-path
                [ "?" kan-query ]

kan-scheme    = %s"kan"
kan-authority = %s"local" / %s"did" / host [ ":" port ]
git-authority = [ transport-user "@" ] (%s"local" / host) [ ":" port ]
at-authority  = %s"did" / at-handle

transport-user = 1*(unreserved / pct-encoded / sub-delims)
at-handle      = 1*(ALPHA / DIGIT / "." / "-")

scope-locator = direct-scope-selector / named-locator
direct-scope-selector = %s"@id:" scope-id
scope-id      = multibase-hash
multibase-hash = %s"b" 1*(%x61-7A / %x32-37)

named-locator = locator-label *( ":" locator-label )
locator-label = 1*(lower / DIGIT / "-" / "_" / "~")
git-locator   = git-label *( ":" git-label )
git-label     = 1*(lower / DIGIT / "-" / "_" / "~" / ".")
lower         = %x61-7A

claim-tail    = %s"claim/" cid
subject-tail  = %s"subject/" (subject-path / subject-cid-selector)
subject-cid-selector = %s"@cid:" cid
scope-id-tail = %s"identity/scope"
auth-id-tail  = %s"identity/authority"
principal-tail = %s"identity/principal/did/" did-method "/" did-msid

cid           = 1*(lower / DIGIT)
did-method    = 1*lower
did-msid      = segment-value
subject-path  = subject-segment *( "/" subject-segment )
subject-segment = 1*regular-segment-value
regular-segment-value = unreserved / pct-encoded / sub-delims / ":"
segment-value = regular-segment-value / "@"

kan-query     = query-pair *( "&" query-pair )
query-pair    = query-name "=" query-value
query-name    = %s"source" / %s"service" / %s"commit" /
                %s"ref" / %s"snapshot" / %s"version" /
                %s"trust" / %s"at"
query-value   = 1*(unreserved / pct-encoded / sub-delims / ":" / "@" / "/" / "?")
```

`segment-value` is written as a single-character alternative; repetitions are
supplied by the enclosing rules. A parser MUST apply the additional semantic
constraints below. ABNF acceptance alone is not validity.

Fragments are absent deliberately. A literal `#` after any URI above is
`fragment-not-supported`.

### Path families

The common scoped families are:

```text
//<authority>/<scope-locator>/claim/<cid>
//<authority>/<scope-locator>/subject/<subject-path>
//<authority>/<scope-locator>/identity/scope
//<authority>/<scope-locator>/identity/authority
//<authority>/<scope-locator>/identity/principal/did/<method>/<method-id>
```

Unscoped identity families are:

```text
kan://<authority>/identity
kan+at://<handle>/identity
kan+at://did/<method>/<method-id>/identity
kan://did/<method>/<method-id>/identity
```

For `kan+at://did`, a scoped request is:

```text
kan+at://did/<method>/<method-id>/<scope-locator>/<resource-tail>
```

The DID method-specific identifier occupies exactly one URI segment. Colons
that are part of the canonical method-specific identifier remain literal;
other non-unreserved bytes are UTF-8 percent-encoded.

`kan+git` has no freestanding identity authority. A bare Git authority may
return transport-authentication evidence, but it MUST NOT manufacture a kan
principal or DID. Bare `/identity` under `kan+git` therefore returns
`authority-identity-unsupported` in v1.

### Scope locator grammar

A named locator is exactly one path segment containing non-empty,
colon-separated lowercase ASCII labels. The complete decoded locator is matched
exactly. Prefix fallback is forbidden.

```text
personal
backup:kan-tools:day
work:client-a:api
```

Adding, removing, or renaming another locator MUST NOT change the parsing
boundary or cause fallback. A missing exact locator is `scope-not-found`.
Conflicting exact bindings are `ambiguous-scope-locator`.

`@` is reserved at the start of every decoded scope-locator and subject
segment, including when it arrived percent-encoded. A regular `ScopeLocator`
or `SubjectPath` therefore cannot contain such a segment. In scope-selector
position, `@id:<scope-id>` is the only supported selector and MUST validate as
RFC 1's exact 34-byte SHA-256 multihash with canonical base32lower display. An
unknown `@<keyword>:` is `unsupported-selector`; malformed syntax for a known
selector is `invalid-selector` or `non-canonical-identifier`. The authority
still locates sources for a stable identifier. The identifier does not encode
a network location.

Two authorities may expose different evidence sets for the same scope
identifier. That is not a scope-identity conflict. A single named locator whose
selected evidence verifies two different inception-derived identifiers is
`ambiguous-scope-locator`.

### Resources

#### Claims

A claim resource key is one canonical CID. Resolution returns the exact claim
bytes, verification result, source provenance, and RFC 1 admission and trust
results where applicable. A resolver MUST NOT replace an unavailable CID with
a claim about the same subject.

Claims are semantically atomic in v1. Subordinate claim paths and fragments are
forbidden.

#### Subjects

Everything after `/subject/` reconstructs one subject by decoding each segment
once and joining the decoded segments with literal `/`. Literal `/` therefore
has the same hierarchy semantics as RFC 1's `subjectPrefix`.

`subject/@cid:<cid>` is the sole current exception. It denotes a typed
`SubjectCidSelector` for a canonical preserved v1 `SubjectRef`; it is not a
regular subject path and does not assert that the CID is a future canonical
subject identity. The selector MUST occupy the complete subject value, so a
following `/child` is invalid. This leaves room for a distinct canonical
subject identifier in a later version without overloading legacy CIDs.

A subject resolution returns unfolded claims and supporting evidence, then
reports fold, admission, and trust results separately. Subject queries are
query operations, not fragment composition. No v1 fragment selects a field of
a folded subject.

#### Identities

`identity/scope` returns:

```text
ScopeIdentityResult {
  identifier:       ScopeIdentifier,
  inception:        InceptionEvidence,
  governance:       ResolvedGovernance,
  locator:          text or null,
  sourceProvenance: [SourceSnapshot, ...]
}
```

The identifier alone is stable identity. Inception proofs, governance standing,
and known evidence may change between snapshots without changing it. A scope is
not a principal and cannot author claims.

`identity/authority` and bare `/<authority>/identity` return a tagged authority
identity result. For `kan+at`, this is the verified account DID and handle/PDS
relationship. For hosted `kan`, it is the service identity declared and
verified by the authority manifest. `local` MUST distinguish installation,
configured human principal, and acting credentials; v1 authority identity is
the resolver installation identity only. If none is configured, the result is
`authority-identity-unknown`. Authority identity never implies governance.

`identity/principal/did/<method>/<method-id>` resolves the canonical DID using
the evidence selected for the surrounding scope. The result may report role,
lineage, governance-root, and capability relationships found in that evidence,
but MUST NOT classify a principal as globally admitted. Admission applies to a
specific action, operation, subject, capability path, and evaluation instant.

`kan://did/<method>/<method-id>/identity` resolves the same principal through
configured freestanding DID sources without a scope. Scoped and freestanding
requests may return different known-history standing while retaining the same
canonical DID. Both disclose their evidence sources.

`self` is forbidden. No identity URI selects an acting principal or credential.

An identity `version` selector has one of these canonical values:

```text
static
event:<logical-event-cid>
versionId:<method-specific-version-id>
documentCid:<cid>
```

These map exactly to RFC 1 `IdentityVersion`. `version` applies only to a
principal identity resource. Omission requests current resolution.

### Query registry

The v1 query registry is closed:

| Parameter | Class | Cardinality | Applicable schemes/resources |
|---|---|---:|---|
| `source` | evidence | set | all; values constrained by scheme |
| `service` | evidence | singleton | sources implemented by a named DID service |
| `commit` | evidence | singleton | `kan+git`, `kan+at` |
| `ref` | evidence | singleton | `kan+git` |
| `snapshot` | evidence | singleton | `kan` |
| `version` | evidence | singleton | principal identity |
| `trust` | evaluation | singleton | scoped resources |
| `at` | evaluation | singleton | RFC 1 time-dependent evaluation |

Unknown names are `unsupported-parameter`; they are never ignored. Empty
values and duplicate singleton parameters are errors even when the duplicate
values agree. `source` is a duplicate-free set and canonical output sorts its
encoded values by byte order.

`service` contains one canonical DID URL for a service, including its non-empty
fragment. The `#` is query data and MUST be encoded as `%23`; it is not the outer
URI fragment. `service` without a compatible `source` is
`inapplicable-parameter`.

`commit`, `ref`, and `snapshot` are source snapshot selectors:

- under `kan+git`, `commit` is a complete Git object identifier and `ref` is a
  full ref such as `refs/heads/main`; abbreviated hashes and short branch names
  are forbidden;
- under `kan+at`, `commit` is the underlying account-repository commit CID used
  by both AppView and direct-PDS resolution;
- under `kan`, `snapshot` is the canonical immutable commitment format declared
  by the selected source descriptor.

`commit` and `ref` are mutually exclusive. An immutable selector that is
unavailable returns `snapshot-unavailable`; it never falls forward to current.

`trust` selects a configured trust frame, a canonical weighted principal
selector, or an inline composite. It is a closed typed value after parsing,
never an opaque string. An omitted value uses the resolver's configured default
only when the result discloses the exact frame applied. Trust does not change
source access or scope admission.

The direct selector spellings are:

- a configured-frame name, including the local `local` and `roles` frames;
- a DID, optionally followed by `=` and a weight;
- the machine-relative current-actor selector `me`, optionally weighted;
- the machine-relative named-role selector `role:<name>`, optionally weighted.

A weight is a finite IEEE 754 binary64 value in `[0,1]`. Canonical output uses
its shortest round-tripping decimal spelling, writes zero and one as `0` and
`1`, and omits `=1`. A configured frame is set-valued and cannot carry a
weight. A selector beginning with `@` is reserved and is not a configured-frame
name.

An inline composite has decoded query value `@set:<members>`, where `<members>`
is a compact JSON array containing at least two canonical direct-selector
strings. It has no insignificant whitespace. JSON string escaping is the only
inner escaping; the complete decoded value is then percent-encoded once as an
ordinary query value. For example, the decoded value
`@set:["roles","did:key:zExample=0.5"]` canonicalizes in the outer URI as
`trust=@set:%5B%22roles%22,%22did:key:zExample=0.5%22%5D`.

Composite order is semantic and MUST be preserved. A later selector can replace
an earlier weight when both resolve to the same principal. Exact duplicate
typed selectors are `duplicate-parameter`; a composite with fewer than two
members or malformed member is `invalid-selector`. Current-actor, named-role,
and local configured-frame selectors are machine-relative. A resolver without
that local configuration MUST reject them as `unsupported-selector`; it MUST
NOT reinterpret them as portable principals. Principal-only composites are
portable.

`at` is an unsigned, shortest-form base-10 Unix timestamp in microseconds. Zero
is `0`; leading zeroes and signs are forbidden. It supplies RFC 1's trusted
evaluation instant. It is not an author timestamp or snapshot selector.

Canonical query order is:

```text
source (sorted), service, commit/ref/snapshot, version, trust, at
```

Exactly one of `commit`, `ref`, and `snapshot` can occupy its position. A query
encoder MUST use `&`, MUST NOT treat `+` as space, and MUST apply the common
percent-encoding rules below.

### Source access

Source access, scope admission, and consumer trust are independent:

| Plane | Question |
|---|---|
| source access | May this requester receive evidence from this source? |
| scope admission | Was this specific action authorized in the scope? |
| consumer trust | Does authentic evidence participate in this consumer's view? |

Public and private characterize sources, not scopes. One scope may have public,
team, personal, and encrypted-archive sources. Authentication may select or
unlock a source but never changes scope identity.

Two authenticated disclosures that return different bodies of evidence MUST be
distinct sources or explicitly named disclosure projections. They MUST NOT
claim one source and snapshot identity while silently varying contents by
requester.

Resolution distinguishes:

- `access-denied`: the source exists but the requester cannot access it;
- `source-not-found`: the selected source does not exist;
- `resource-not-found-at-snapshot`: the selected source and snapshot were read
  successfully but do not contain the requested resource; and
- `snapshot-unavailable`: the source exists but cannot serve the selected
  immutable snapshot.

A resolver MUST NOT silently fall back from an inaccessible private source to
a public source and present the result as equivalent. Copying a claim into a
more public source is a disclosure act that later ACL changes cannot undo.
Concrete authentication and ACL protocols are outside this RFC.

### Resolution result

Every successful resolution returns or makes available this provenance before
any folded presentation:

```text
ResolutionResult {
  canonicalRequest:   URI,
  immutableReplay:    URI,
  target:             TargetKey,
  authorityIdentity:  tagged identity result or null,
  scopeIdentity:      ScopeIdentityResult or null,
  sources:            [SourceResult, ...],
  validity:           result,
  admission:          result or null,
  trust:              result or null,
  resource:           typed resource result,
  diagnostics:        [stable failure or warning identifiers, ...]
}

SourceResult {
  kind:         text,
  identity:     text,
  substrate:    text,
  access:       available | denied,
  snapshot:     text or null,
  completeness: committed | selection | unknown,
  diagnostics:  [text, ...]
}
```

An immutable snapshot does not imply network-wide completeness. A Git commit
can commit to its tree; an ATProto account commit can commit to that account's
MST; an AppView's cross-account selection cannot prove that no other account
contains relevant evidence.

### `kan` authority and sources

`kan://local` reads system kan configuration. A hosted DNS authority retrieves
and verifies that authority's kan source manifest. The manifest maps exact scope
locators and scope identifiers to source descriptors. It also declares the
hosted resolver's service identity, supported snapshot formats, source-access
requirements, and canonical defaults.

Manifest syntax and transport will be defined with hosted-kan, but the
resolution contract here is fixed: exact locator lookup, inception verification,
source disclosure, no prefix fallback, and explicit errors. A hosted resolver
that cannot provide this contract is not a conforming `kan` authority.

`kan://did` is not a hosted source authority. It invokes configured RFC 1 DID
resolvers for the freestanding identity path and accepts no scoped claim or
subject paths.

### `kan+git` source

`kan+git` uses the common one-segment, colon-structured locator. Each locator
label maps byte-for-byte to one Git remote path segment:

```text
kan-tools:day       -> /kan-tools/day
kan-tools:day.git   -> /kan-tools/day.git
group:subgroup:repo -> /group/subgroup/repo
```

The `.git` suffix is preserved only when written. It is never added, removed, or
probed. `.` and `..` labels are forbidden. The Git source is `.claims/` at the
selected commit, interpreted through kan's versioned GitTree record contract.

Transport inference is deterministic:

| URI authority | Git transport |
|---|---|
| `user@host` | SSH to `host` as transport username `user` |
| `user@host:port` | SSH at explicit port |
| `host` | HTTPS |
| `host:port` | HTTPS at explicit port |
| `local` | locally configured GitTree for the exact scope locator |

Userinfo containing `:` is forbidden; passwords and other credential material
never appear in the URI. Userinfo denotes only a Git transport username. It
does not identify a kan principal, author, trust frame, or acting identity.

Native unauthenticated `git://`, FTP, and transport probing are forbidden. A
transport failure remains a transport failure and does not switch protocols.
Credential use is separately authorized by caller transport configuration;
resolving a URI does not itself authorize a prompt, agent, or key.

An omitted snapshot asks the source for its disclosed default commit. `ref`
asks the Git source to resolve a mutable full ref. Every success reports the
complete commit object identifier and an immutable `commit` replay URI.

The Git remote and commit establish source provenance, not scope identity.
Resolution verifies `ScopeInception` evidence in the GitTree source and
reports its derived `ScopeId`.

### `kan+at` source

`kan+at` treats an ATProto account repository as a carrier of public records,
not as a kan scope. Claims are records. Subjects, scope-locator bindings, and
scope-specific sources are derived by querying those records.

For a handle authority, resolution:

1. validates and resolves the handle under the ATProto handle specification;
2. resolves the resulting DID document;
3. verifies the handle-to-DID relationship bidirectionally;
4. extracts the account PDS service endpoint;
5. selects the canonical kan AppView by default, or the explicitly requested
   `source` and `service`;
6. performs the normative `tools.kan.*` query using the canonical account DID,
   exact scope locator, resource, and optional account-repository `commit`;
7. verifies returned kan records, inception, scope identity, and source
   provenance independently of the AppView's assertion; and
8. evaluates admission and trust after evidence collection.

For reserved DID authority syntax, steps 1 and 3 are omitted:

```text
kan+at://did/plc/abc123/kan-tools:day/subject/x
kan+at://did/web/example.com:users:alice/kan-tools:day/subject/x
```

The `tools.kan.*` Lexicon namespace is controlled under `kan.tools`. Clients
resolve `_lexicon.kan.tools`; the resulting namespace DID is also the canonical
kan AppView service DID. Its DID document MUST contain exactly one applicable
`#kan_appview` service entry of type `KanAppView`, with an HTTPS origin endpoint
and no path, query, or fragment. Public queries call that origin directly.
Authenticated future queries may call through the account PDS with
`atproto-proxy: <namespace-did>#kan_appview` under the standard service-
authentication rules. An explicit `service` selector MAY name another complete
DID-plus-fragment service reference, but never changes the authority for the
Lexicon schemas.

The v1 AT source kinds are:

| `source` value | Behavior |
|---|---|
| `appview` | Query the selected or canonical kan AppView |
| `pds` | Fetch applicable `tools.kan.*` records from the account PDS and derive the same result client-side |

Both may be selected by repeating `source`. They are distinct sources even when
derived from the same account commit. An omitted `source` means canonical
AppView and MUST be disclosed. Failure of one source never silently selects the
other.

The AppView and direct-PDS algorithms have the same logical inputs and conflict
rules. Records binding one account-local locator to different verified scope
identifiers produce `ambiguous-scope-locator`; indexing order never selects a
winner.

`commit` selects the exact underlying account-repository commit for both source
kinds. An omitted commit resolves current state, reports the verified commit,
and returns an immutable replay URI. A supplied commit succeeds only when the
selected source can furnish and verify that exact repository state: normally
the current state or a verified local cache for direct PDS resolution, and a
retained indexed state for AppView resolution. RFC 2 imposes no historical-
retention minimum. Unavailability is `snapshot-unavailable`; a resolver MUST
NOT fall forward to current state. Every pagination cursor is source-specific
and bound to the first page's account commit.

The canonical schema and release repository is
[`kan-tools/kan-lexicon`](https://github.com/kan-tools/kan-lexicon). It owns the
`lexicons/tools/kan/` source tree, schema evolution, code-generation
configuration, cross-language client fixtures, and immutable releases. This
repository pins revision `21223656d9954f93d4dc5b0a16c144b6bce1902c`
(`v0.1.0`) and vendors byte-identical
RFC/CI snapshots under `.design/rfc-2-lexicons/`; it is a consumer, not a
second Lexicon publication source. Runtime clients do not consult GitHub.
Protocol authority remains the namespace DID resolved through
`_lexicon.kan.tools`.

The five normative Draft Lexicons and their proposed upstream paths are:

| NSID | `kan-lexicon` path | Vendored RFC snapshot | Contract |
|---|---|---|---|
| `tools.kan.claim` | `lexicons/tools/kan/claim.json` | `.design/rfc-2-lexicons/tools.kan.claim.json` | One typed current claim record, keyed by kan claim CID |
| `tools.kan.defs` | `lexicons/tools/kan/defs.json` | `.design/rfc-2-lexicons/tools.kan.defs.json` | Closed claim/anchor/subject/artifact/identity unions and shared provenance views |
| `tools.kan.getClaim` | `lexicons/tools/kan/getClaim.json` | `.design/rfc-2-lexicons/tools.kan.getClaim.json` | Exact single-claim query; never paginated |
| `tools.kan.getSubject` | `lexicons/tools/kan/getSubject.json` | `.design/rfc-2-lexicons/tools.kan.getSubject.json` | Paginated subject-claim query |
| `tools.kan.getIdentity` | `lexicons/tools/kan/getIdentity.json` | `.design/rfc-2-lexicons/tools.kan.getIdentity.json` | Typed scope, authority, or principal identity query |

The schemas themselves, rather than a prose transcription, fix required
parameters, lower bounds and maxima, union membership, output shapes, and XRPC
error names. `getClaim` requires `repo`, `scope`, and `cid`; `getSubject`
requires `repo`, `scope`, and `subject`; `getIdentity` requires `repo` and
`kind`. All accept optional `commit`. Only `getSubject` and `getIdentity`
accept `limit` and opaque `cursor`. Later pages hold every other input fixed.

`scope` is the decoded URI scope segment: either the exact named locator or the
complete `@id:<scope-id>` selector. It is not silently rewritten before the
request. `getIdentity` applies these additional closed rules:

| `kind` | `scope` | `did` | `version` |
|---|---|---|---|
| `scope` | required | forbidden | forbidden |
| `authority` | optional for scoped versus bare authority identity | forbidden | forbidden |
| `principal` | optional for scoped versus freestanding resolution | required | optional |

Supplying a forbidden field, or omitting a required one, is XRPC invalid-
request handling and maps to the URI failure `inapplicable-parameter` when the
request originated as a URI. The AppView request for a claim is therefore
exactly `tools.kan.getClaim?repo=<account-did>&scope=<decoded-scope>&cid=<claim-cid>`
plus `commit` when selected; the subject and identity methods substitute only
their declared parameters. `service`, `source`, `trust`, and `at` are resolver
inputs and are never forwarded as undeclared XRPC parameters.

Direct-PDS resolution does not call a `tools.kan.*` AppView query. It fetches
the current account repository with `com.atproto.sync.getRepo?did=<account-did>`
and derives the same logical result from `tools.kan.claim` records after
verifying the returned signed commit. A selected non-current commit can be read
only from a previously verified cached CAR rooted at that commit; otherwise it
is `snapshot-unavailable`.

The shared result provenance distinguishes account DID, verified kan scope,
source kind, account commit, completeness, and AppView index state. Each query
declares its resource-specific not-found error and the applicable stable XRPC
errors `SnapshotUnavailable`, `InvalidClaim`, `UnsupportedClaimCodec`, and
`IndexNotReady`; paginated methods additionally declare `InvalidCursor` and
`CursorSnapshotMismatch`.

Lexicon does not permit a `type: record` definition to be embedded as an XRPC
output property. Read methods therefore expose `claimView.record` through the
explicit `claimRecordView` object, which duplicates the fields of the current
supported `tools.kan.claim` record without claiming to be a second stored
record type. AppViews and direct-PDS readers convert supported historical
records to this current view before returning them. Unknown body encodings or
codecs fail with `UnsupportedClaimCodec`; violations of the declared current
schema fail with `InvalidClaim`.

#### Claim record conversion

The canonical collection is `tools.kan.claim` on the local MST and ATProto.
The early local collection `dev.kan.claim` is a migration input only. One claim
occupies one record whose record key and `claimCid` are the original kan claim
CID. `codec` is the closed token `kan-claim-v1`; `content` is the fully typed
current projection; `signature` is the original author signature; and `rev` is
the per-claim storage TID. The enclosing ATProto record CID authenticates the
converted record but is never substituted for the kan claim CID in signatures
or citations.

Publishing or migration first decodes a historical record with the current kan
decoder. Decoder support alone does not guarantee ATProto publishability:
before any MST mutation, conversion checks every Lexicon byte and array bound,
the interoperable integer range, DID and TID formats, and the one-megabyte
encoded-record ceiling. An incompatible historical claim remains intact and
readable in append-only legacy history but is not inserted into
`tools.kan.claim`; migration fails explicitly rather than truncating or
rewriting signed content. Every supported historical enum tag that passes
those checks is converted to the corresponding
closed `$type` union member in `tools.kan.defs`; tuple fields become named
objects, Rust snake-case fields become lower camel case, and enum values become
the declared kebab-case values. In particular, historical absence of
`recorded_at` becomes absence of `recordedAt`, not zero or null.

The conversion table is exact:

| Historical family | `tools.kan.defs` members |
|---|---|
| anchors `Workspace`, `Commit`, `Blob`, `FileAt`, `LineRangeAt` | `#workspaceAnchor`, `#commitAnchor`, `#blobAnchor`, `#fileAtAnchor`, `#lineRangeAtAnchor` |
| subjects `Local`, `Anchor` | `#localSubject`, `#anchorSubject` |
| artifacts `Commit`, `FileAt`, `LineRangeAt`, `ToolOutput` | `#commitArtifact`, `#fileAtArtifact`, `#lineRangeAtArtifact`, `#toolOutputArtifact` |
| bodies `Subject`, `Observation`, `Plan`, `Decision`, `Blocker`, `Resolution`, `Result`, `Status`, `Relation`, `Retraction`, `Rejects`, `Publication`, `RoleDeclaration` | the same lower-camel stem plus `Body` |

Tuple positions map in order to the named `path`, `sha`, and `span` fields.
`subject_kind` maps to `subjectKind`; `recorded_at` maps to `recordedAt`.
`SubjectKind`, `StatusValue`, `RelationKind`, and `Layer` variants map to the
closed kebab-case strings declared in the Lexicon, including `InProgress` to
`in-progress`, `SameAs` to `same-as`, and `GitTree` to `git-tree`. The inverse
applies this mapping exactly. Envelope fields `claimCid`, `codec`, `signature`,
and `rev` never enter the reconstructed `ClaimContent` map.

Verification applies the specified inverse conversion for `kan-claim-v1`,
reconstructs canonical historical `ClaimContent` DAG-CBOR, requires its hash to
equal `claimCid`, and verifies `signature` over that CID. A conversion is
accepted only when this round trip reproduces the exact signed bytes. Unknown
body kinds and unsupported codecs fail as `UnsupportedClaimCodec`; declared
schema violations and other non-invertible records fail as `InvalidClaim`.
There is no opaque escape hatch. Writers emit only
`tools.kan.claim` and never dual-write. Historical CAR blocks remain append-
only and reachable through their earlier commits.

The six narrative body strings retain large inline maxima because they are part
of the signed claim content and must survive inverse conversion. The official
Go Lexicon linter consequently reports six deliberate `large-string` style
warnings. Moving this content to blobs would make reconstruction depend on a
second object and would not preserve the authenticated bytes. All five schemas
otherwise parse under `goat lex parse` and have no other lint finding.

## Canonicalization and equivalence

Canonicalization is syntactic and MUST NOT perform network access.

1. Lowercase the scheme and DNS host. Preserve case in path and query data
   except where a component's grammar requires lowercase.
2. Reject userinfo except `kan+git` transport username. Reject password-like
   `:` in that username.
3. Parse URI components and path segments before percent-decoding.
4. Decode exactly once. Invalid escapes, invalid UTF-8, and NUL are errors.
5. Emit uppercase hex digits in percent encodings.
6. Decode percent-encoded unreserved ASCII in canonical output.
7. Encode UTF-8 bytes outside the allowed ASCII repertoire. Unicode is not
   normalized; NFC and NFD strings remain distinct.
8. Reject empty path segments, trailing slash, complete `.` and `..` segments,
   and their percent-encoded equivalents.
9. Reject percent-encoded `/` in locators, DID path components, and subjects.
   Decoding MUST NOT reveal a hidden structural separator.
10. Validate and emit the complete exact scope locator. Do not perform prefix
    matching or alias substitution during syntactic canonicalization.
11. Canonicalize query parameters in registry order, sort `source` values, and
    apply scheme-specific value validation. Do not treat `+` as space.
12. Reject fragments.

Percent-encoded unreserved ASCII and lowercase percent hex are resolvable but
non-canonical. All other rejected forms fail rather than normalize.

Two canonical URIs are request-equivalent only when they are byte-identical.
Two non-identical requests may resolve to the same target key—for example a
named locator and direct `@id:` selector, or different trust frames over one
subject. Resolution MUST report target-key equality separately from request
equivalence.

Aliases are not canonical merely because they currently resolve to one scope.
Handles, local locators, hosted locators, Git refs, and configured trust names
are mutable aliases. Immutable replay replaces mutable source selectors with
the exact snapshots used but does not rewrite the authority or locator into a
claim of global canonical location.

## Resolution or processing algorithm

All schemes use this ordered algorithm:

1. Parse under the scheme-specific ABNF. Reject unsupported fragments,
   userinfo, path families, query names, duplicates, and combinations.
2. Canonicalize syntax without access and retain the original input for
   diagnostics.
3. Resolve and verify the authority identity when the scheme defines one.
4. Resolve an exact scope locator or direct scope identifier to candidate
   sources. For unscoped identity paths, select the authority or DID sources
   instead.
5. Apply `source` and `service`. Report every selected, inaccessible, missing,
   or rejected source independently.
6. Apply `commit`, `ref`, or `snapshot`, producing one immutable snapshot per
   available source. Never substitute current for an unavailable immutable
   selection.
7. Verify scope inception evidence and derive the scope identifier. Reject
   a direct identifier mismatch and report conflicting locator bindings as
   ambiguous.
8. Retrieve the typed resource and all available supporting identity,
   governance, delegation, revocation, and claim evidence. Preserve invalid and
   unsupported evidence for diagnostics.
9. For principal identity, apply `version` within the selected evidence.
10. Perform cryptographic validity and identity-standing resolution under RFC
    1.
11. For scoped actions and claims, resolve governance and scope admission
    under RFC 1 using `at` when time evidence is required.
12. Apply `trust` independently. If omitted, disclose the exact configured
    default used.
13. Return the typed resource, separated provenance and evaluation results, the
    canonical request, and an immutable replay URI.

Resolution is read-only. It MUST NOT mint or select a signing key, select an
acting principal, write a profile, alter governance, grant source access,
change admission, mutate a trust frame, or authorize transport credentials.

### Stable failure classes

V1 defines at least:

```text
malformed-uri
unsupported-scheme
userinfo-forbidden
credential-in-userinfo
fragment-not-supported
invalid-percent-encoding
invalid-utf8
invalid-path-segment
encoded-separator
non-canonical-identifier
unsupported-parameter
duplicate-parameter
inapplicable-parameter
conflicting-snapshot-selectors
evaluation-time-required
authority-not-found
authority-identity-unknown
authority-identity-unsupported
scope-not-found
ambiguous-scope-locator
source-not-found
access-denied
snapshot-unavailable
resource-not-found-at-snapshot
scope-identifier-mismatch
transport-failure
unsupported-did-method
unknown-history
contested
unsupported
invalid
```

Later RFCs may add stable identifiers but MUST NOT silently reclassify a v1
input that this RFC requires to fail.

## Authority and trust model

Authority is plural and explicit:

- URI syntax determines how a request is parsed, not whether returned evidence
  is true.
- A kan authority manifest or AT account establishes routing provenance, not
  kan scope identity.
- Canonical scope inception bytes establish scope identity.
- Identity events and DID method evidence establish principal control.
- Governance, delegation, and revocation evidence establish scope admission.
- Claim bytes, CIDs, and proofs establish authentic speech.
- A source-access service decides whether evidence is disclosed.
- The consumer supplies the trust frame applied after verification and
  admission.
- Source snapshots establish bounded provenance, not universal completeness.

No substrate is trusted merely because it delivered bytes. Git signatures, AT
repository commits, HTTPS, service-auth tokens, and local filesystem ownership
authenticate transport or carrier state; kan objects are still verified under
their own content, proof, identity, and governance rules.

An AppView may select, index, omit, or delay records. It MUST NOT return a
folded result as authoritative kan truth. It returns claims and evidence plus
selection provenance; the client can verify and fold them.

## Security considerations

- **Misleading authority:** Userinfo is forbidden except as a Git transport
  username, and that exception never denotes a kan actor. Renderers SHOULD
  emphasize the host and MUST NOT visually merge userinfo with it.
- **Credential disclosure:** Password-bearing userinfo is forbidden. Query
  parameters MUST NOT carry private keys, bearer tokens, or service-auth JWTs.
- **Locator rebinding:** Single-segment exact locators prevent a newly added
  longer prefix from changing an existing URI's repository/resource boundary.
- **Scope substitution:** Named routes are verified against inception.
  Direct `@id:` requests fail when evidence derives another identifier.
- **Alias mutability:** Handles, locators, refs, and defaults are disclosed as
  mutable. Every successful resolution supplies immutable snapshot replay.
- **Normalization attacks:** Parsing precedes one decoding pass. Encoded slash,
  dot segments, invalid UTF-8, NUL, Unicode normalization, and double decoding
  cannot change a subject or capability boundary silently.
- **Trust confusion:** `trust` is an evaluation input. It does not authenticate
  a source, admit a claim, identify an authority, or select credentials.
- **Time confusion:** `at` is caller-supplied trusted evaluation time. Author
  timestamps and source observation time do not substitute for it.
- **Source fallback:** An access denial or transport failure cannot silently
  select a more public or less complete source.
- **Differential disclosure:** Different authenticated bodies require distinct
  source identities or disclosure projections so one snapshot identifier does
  not commit to several requester-dependent sets.
- **AppView omission:** Per-account results identify the account commit used.
  Cross-account completeness remains unprovable and is labelled selection.
- **Handle takeover or rotation:** `kan+at` verifies handle/DID binding and
  reports the resolved DID. A changed handle binding changes authority
  provenance but does not rewrite kan scope or principal identity.
- **Service confusion:** `service` is a canonical DID URL with a service
  fragment and must be compatible with the selected source. Service-auth
  audiences include that identity; bare DID wildcard interpretation is
  forbidden.
- **Transport downgrade:** Git inference never probes or falls back. Native
  unauthenticated Git transport is not inferred.
- **Ambient action:** Resolution is read-only and cannot authorize credential
  prompts, signing, writes, governance, ACL changes, or acting-principal
  selection.
- **Fragments:** Unsupported fragments fail rather than being discarded. A
  percent-encoded `#` inside a DID service query value remains data.
- **Withholding:** No resolver can prove that unseen evidence does not exist.
  Results disclose consulted and inaccessible sources so callers can compare
  independent observations.

## Compatibility

This RFC changes no released claim, subject, GitTree, or DID bytes. Existing
repository-local `did:key` authors and GitTree records remain readable
under their existing compatibility rules.

The schemes are new. Implementations MUST NOT infer URI meaning from current
CLI positional arguments, filesystem layout, Git remote syntax, or AT URI
syntax where this RFC differs. In particular:

- `kan+git://git@github.com/kan-tools:day/...` intentionally differs from Git's
  slash-separated remote path spelling;
- `kan+at` is not the AT URI scheme and does not identify an AT record by
  collection and rkey;
- `kan://local/...` is machine-relative routing, while returned scope identity
  remains stable; and
- `@id:` is a typed URI selector around RFC 1's canonical `ScopeId` display,
  not part of the signed or stored scope identifier.

Future schemes or query parameters require an RFC. V1 parsers reject unknown
parameters so an older implementation cannot silently ignore a security- or
identity-relevant input.

## Alternatives considered

- **Slash-separated repository paths with longest-prefix matching:** Rejected
  because adding or removing a nested mapping can change both repository and
  resource interpretation of an existing URI.
- **A `/-/` repository/resource sentinel:** Unambiguous but needlessly noisy
  once one-segment colon locators provide the same property.
- **Fixed-depth owner/repository paths:** Works for GitHub and Hugging Face but
  not general kan, Git, or ATProto authorities.
- **Copy native Git remote syntax:** Rejected because Git's SSH, SCP-like,
  HTTPS, local, and suffix conventions are non-uniform and leave the kan
  resource boundary ambiguous.
- **Require `.git` as delimiter:** Rejected because `.git` is not universally
  required and probing both spellings would make resolution nondeterministic.
- **Put snapshot selectors in the path:** Rejected because query parameters
  already model resolution inputs and can keep evidence selection distinct from
  evaluation without expanding the resource vocabulary.
- **Treat all query parameters alike:** Rejected because commits select the
  evidence universe while trust evaluates already selected evidence.
- **Use userinfo for acting identity:** Rejected as misleading, security
  sensitive, and contrary to read-only identity resolution.
- **Make scopes public or private:** Rejected as too coarse. One logical scope
  may have several sources with different disclosure policies.
- **Claim-level read ACLs:** Rejected for v1 because they complicate citation,
  folding, encryption, metadata leakage, and revocation. Source access is the
  coherent initial boundary.
- **Treat an ATProto repository as a kan scope:** Rejected because one account
  repository can carry records for many kan scopes, and scope identity is
  independently derived from inception.
- **Require a stored AT source manifest:** Rejected for vanilla public ATProto.
  Scope and subject indexes are derived from records by the AppView or client.
- **Direct PDS as the default:** Rejected because the ATProto application model
  normally queries an application-specific AppView. Direct PDS remains an
  explicit source using the same logical algorithm.
- **Use `self` identity:** Rejected because it can mean authority, caller,
  configured principal, source operator, or acting credential.
- **Principal identities only:** Rejected because scope and authority identity
  are useful, distinct, and not principals.
- **Allow fragments:** Rejected for v1 because claims and identities are
  semantically atomic and no representation-independent subject fragment is
  established. Semantic subresources use explicit paths; subject operations use
  typed queries.
- **Normalize Unicode:** Rejected because RFC 1 preserves distinct UTF-8 text
  identifiers and implicit normalization can change subject and capability
  identity.

## Reference test vectors

Normative machine-readable vectors will live under
`tests/fixtures/uri-v1/manifest.json`. Every vector contains input URI, expected
parse or exact failure, canonical request when successful, target key when
known, and expected source/evaluation classification. Retrieval vectors also
contain source fixtures, the exact AppView or direct-PDS XRPC request,
source-specific provenance, and immutable replay output.

The mandatory finite matrix is:

| Dimension | Required values |
|---|---|
| scheme | `kan`, `kan+git`, `kan+at` |
| authority | local, DNS, Git username+DNS, AT handle, reserved DID |
| scope locator | named, direct `@id:`, missing, conflicting |
| resource | claim, subject, scope identity, authority identity, scoped principal, freestanding principal |
| source access | available, denied, absent |
| snapshot | omitted/current, mutable ref, immutable available, immutable unavailable |
| evaluation | default trust, explicit trust, trusted time, missing required time |
| result | success and each stable failure family |

Vectors MUST include at least:

1. exact colon locator matching and absence of prefix fallback;
2. named and direct locators resolving the same scope identifier through
   different requests;
3. one locator producing conflicting inception identifiers;
4. canonical and non-canonical percent encodings;
5. UTF-8 NFC and NFD subjects remaining distinct;
6. empty, trailing, dot, dot-dot, encoded-slash, NUL, invalid UTF-8, and
   double-decoding rejection;
7. outer fragment rejection and encoded service-fragment preservation;
8. Git SSH inference from userinfo, HTTPS inference without it, explicit ports,
   local routing, forbidden password material, and no fallback;
9. Git colon-to-path mapping with explicit presence and absence of `.git`;
10. full Git commit, full ref, abbreviated-hash rejection, selector conflict,
    mutable resolution, and immutable replay;
11. AT handle-to-DID success, failed bidirectional verification, reserved
    `did:plc` and `did:web`, canonical AppView default, direct PDS selection,
    both sources, service override, and no silent fallback;
12. AppView and PDS resolution at the same account commit producing equivalent
    kan evidence, plus divergent source provenance;
13. unavailable historical AT commit failing instead of selecting current;
14. source denial, source absence, resource absence, and snapshot absence as
    distinct results;
15. trust changing the fold result without changing source snapshot or
    admission;
16. admission changing with trusted evaluation time without changing claim
    validity or source access;
17. scope identity returning `ScopeId`, inception, and active, contested,
    unknown, unsupported, and invalid governance states;
18. authority identity under hosted kan and ATProto, unknown local authority,
    and unsupported Git authority identity;
19. scoped and freestanding resolution of one DID seeing different histories
    while retaining the same principal identifier;
20. all four RFC 1 `IdentityVersion` variants and inapplicable `version` use;
21. unknown parameters, duplicate singletons, duplicate sources, empty values,
    non-canonical order normalized canonically, and scheme-inapplicable
    parameters;
22. negative controls proving resolution does not access signing credentials,
    select an actor, write state, change ACLs, alter admission, or mutate trust.

The conformance harness MUST be usable without linking kan's URI parser or
resolver implementation. The interoperability telos additionally requires one
clean-room non-kan implementation and one independently authored implementation
to pass these vectors.

## Unresolved questions

None. The former ATProto blocker is resolved by the five normative Draft
Lexicons, the namespace-DID `#kan_appview` discovery rule, commit-bound cursor
contract, and exact historical conversion above. Review may still find a
defect, but no design choice is being deferred under an implementation-shaped
placeholder.

## Deferred questions

- Concrete hosted-kan manifest format, authentication, and source ACL
  protocols. RFC 2 fixes their URI-visible behavior, not their wire protocol.
- Permissioned/private ATProto repositories and the evolving ATProto permission
  model. V1 specifies vanilla public account records and leaves source-level
  access hooks explicit.
- Claim-level confidentiality or recipient syntax.
- Additional resource kinds beyond `claim`, `subject`, and `identity`.
- Representation-independent fragments, should a future resource establish
  genuine composition semantics.
- Issue #226's terse GitTree references to canonical content already present in
  the tree.
- IANA registration. The schemes remain private-use during draft and
  implementation validation; registration follows RFC 7595 when deployment and
  interoperability evidence justify it.

## Implementation status

Draft schemas, local claim-collection migration, and an
implementation-independent executable reference harness are implemented. The
production Rust request types, strict parser, and access-free syntactic
canonicalizer execute every checked parse vector. Trust selection is a closed
Rust union, including an ordered, duplicate-free inline composite that compiles
the released repeatable CLI/MCP selector surface into one `trust` parameter.
Production `kan://local`
resolution now selects exact named or direct scopes, returns typed claim,
subject, scope-identity, and principal results, preserves separate RFC 1 claim
judgments, emits immutable replay URIs, and recomputes disposable projections
in memory so explicit resolution changes no filesystem bytes. Linked Git
worktrees fail explicitly pending issue #197's workspace-ownership decision.
Current/scoped CLI recalling verbs and MCP tools compile their trust vector
through `ResolutionRequest`, pass their already-open application reader into
the same resolver so the signed log is not projected twice, and render from the
exact retained workspace, projection, and trust frame. Application shorthand
may refresh its disposable SQLite index before entering resolution; the
explicit URI resolver does not. MCP advertises direct-scope RFC 2
subject resources for those workspaces. Only a workspace positively classified
from released-v1 evidence retains the `kan://claims/{subject}` and direct action
compatibility route. A repository with neither a scope nor readable claim
evidence has a distinct data-free state that can answer an empty tool/CLI read
but advertises no MCP resource. No synthetic scope identifier is minted. Hosted
kan, PDS, and AppView remain.
The governing design is `.design/rfc-2-kan-uri-scheme.md`. The five
`.design/rfc-2-lexicons/*.json` files parse with the independent Go ATProto
toolchain and fix the record/XRPC contract. The finite conformance manifest has
60 URI vectors and 9 hostile/positive service-discovery vectors. Every
resolution/safety vector has an explicit production or deferred-resolver
disposition; the local milestone's four applicable vectors execute against
the Rust resolver/selector and the remainder name their hosted, Git, ATProto,
or source-evaluation milestone. Its gate
executes parsing, resolution, exact XRPC request construction, discovery, and
read-only checks, and its five mutation controls prove that corrupted canonical
output, requests, family coverage, production-resolver coverage, and discovery
expectations are rejected. Local
writers now write only typed `tools.kan.claim` records. Writable open verifies
and migrates `dev.kan.claim`, coalesces identical mixed collections, rejects
conflicts and unverifiable or unsupported history, removes legacy keys from the
live MST without deleting historical CAR blocks, and is idempotent across
reopen. The second generated-client witness remains outstanding before Review.
