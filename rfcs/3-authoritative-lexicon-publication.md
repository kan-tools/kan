# RFC 3: Authoritative Lexicon publication and versioned AppView

- Status: Review
- Authors: kan maintainers
- Created: 2026-08-16
- Discussion: https://github.com/kan-tools/kan/pull/231
- Review-period-ends: 2026-08-19T22:26:55Z
- Review-override: None
- Supersedes: RFC 2 requirements 14, 15, and 17 where explicitly stated; amends requirement 18
- Superseded-by: None

## Summary

This RFC defines how the kan repository family publishes authoritative
`tools.kan.*` Lexicons and serves version-normalized claim views without
rewriting signed records. It establishes:

- DNS-rooted Lexicon authority at `did:web:kan.tools`;
- a stable `tools.kan.claim` collection whose required `codec` field selects
  an immutable canonical representation;
- append-only `tools.kan.codec` and `tools.kan.lens` registers binding every
  codec and directed projection to exact Lexicon, vector, and source revisions;
- a portable reference AppView that normalizes only through registered total
  lenses while retaining raw provenance; and
- a private Railway deployment boundary in which GitHub possesses no
  production PDS, signing, Railway, or recovery credential.

The architectural record remains in `kan`. Public schemas live in
`kan-tools/kan-lexicon`, portable AppView code lives in
`kan-tools/kan-appview`, and private deployment state lives in
`kan-tools/kan-infra`.

## Motivation

RFC 2 made `tools.kan.claim` the canonical claim collection and defined five
Lexicons, but deliberately stopped before authoritative network publication.
Publishing those schemas makes two previously reversible assumptions durable:

1. RFC 2's current projection closes the claim union over `kan-claim-v1`.
   Treating the schema that resolves today as the only meaning of every
   historical record makes incompatible evolution require either a new
   collection or ambiguous reinterpretation.
2. RFC 2 uses the Lexicon namespace DID as the canonical AppView service DID.
   Namespace control and application operation have different key, deployment,
   and recovery lifecycles.

ATProto's current Lexicon guidance permits only narrow compatible evolution
under one NSID and recommends a new NSID for larger changes. Community
versioning work has also identified the value of a stable collection plus a
record-level revision: firehose filters, storage, and semantic identity remain
stable while consumers dispatch explicitly. kan already has that discriminator:
the required `codec` field with value `kan-claim-v1`.

A discriminator alone is insufficient. A historical record must resolve to
the exact schema that defined its codec, not to the latest mutable
`com.atproto.lexicon.schema` record. The codec register supplies that immutable
binding. Lenses then make version conversion explicit and testable rather than
an undocumented AppView behavior.

Publication also crosses a security boundary. Source validation belongs in
public CI; PDS and deployment authority do not. A compromise of a public
workflow must not become authority to rewrite the canonical schema repository.

## Terminology

- **Repository family:** The governed set of `kan`, `kan-lexicon`,
  `kan-appview`, and `kan-infra` repositories with the ownership boundaries in
  this RFC.
- **Lexicon authority DID:** `did:web:kan.tools`, the DID named by
  `_lexicon.kan.tools` for the `tools.kan.*` authority group.
- **Schema record:** A `com.atproto.lexicon.schema` record whose rkey and `id`
  are the Lexicon NSID.
- **Schema record CID:** The CID of one exact schema record value.
- **Embedded schema:** Canonical DAG-CBOR bytes for an exact
  `com.atproto.lexicon.schema` record, carried inside a create-only codec entry
  with the CID those bytes reproduce.
- **Codec:** A stable ASCII identifier for one canonical signed kan claim
  representation, such as `kan-claim-v1`.
- **Codec entry:** An immutable `tools.kan.codec` record binding one codec to
  its schema and source provenance.
- **Lens entry:** An immutable `tools.kan.lens` record binding one globally
  unique lens identifier to a directed codec projection, normative vectors,
  and declared totality/losslessness.
- **Raw record:** The original signed `tools.kan.claim` record retrieved from an
  ATProto repository.
- **Normalized view:** An AppView response projected from a verified raw record
  to a requested codec.
- **Publication:** One atomic repository commit containing current schema-rkey
  updates, exactly one new create-only codec entry with self-contained
  immutable schemas, and any new create-only lens entries released with that
  codec. A release with multiple new codecs uses multiple independently atomic
  publications.
- **Deployment provenance:** The source tag and commit, generated artifact
  digests, ATProto repository commit, record CIDs, and verification result for
  one publication attempt.

Normative words such as MUST, SHOULD, and MAY have their RFC 2119 meanings.

## Detailed design

### Repository-family ownership

The repositories have non-overlapping authority:

| Repository | Visibility | Authority |
|---|---|---|
| `kan-tools/kan` | public | RFCs, canonical codec semantics, Rust reference lenses, local compatibility |
| `kan-tools/kan-lexicon` | public | Lexicon JSON, release tags, generated clients, language-neutral vectors |
| `kan-tools/kan-appview` | public | portable reference AppView and container artifact |
| `kan-tools/kan-infra` | private | Railway configuration, deployment pins, secrets, monitoring, recovery runbooks |

An infrastructure deployment MAY pin an AppView artifact. It MUST NOT patch or
fork its protocol behavior privately. A schema repository MAY implement a
decision in this RFC. It MUST NOT become the architectural source of truth.

### Namespace authority

Every NSID whose group is exactly `tools.kan` resolves through:

```text
_lexicon.kan.tools TXT "did=did:web:kan.tools"
```

The DID document is retrieved from:

```text
https://kan.tools/.well-known/did.json
```

The DID document MUST be hosted outside the Railway PDS/AppView failure domain.
It MUST declare the authoritative PDS using the standard ATProto PDS service.
The PDS repository MUST contain all authoritative `tools.kan.*` schema and
codec records.

The coupling of domain and DID authority is intentional. Loss of `kan.tools`
already permits replacement of `_lexicon.kan.tools`; a PLC DID would not
preserve Lexicon authority against that event. Other kan services MAY use
separate DIDs.

The DID document MAY advertise the canonical AppView using a custom
`#kan_appview` service entry. That entry MUST contain:

```text
id              = did:web:kan.tools#kan_appview
type            = KanAppView
serviceEndpoint = { uri: HTTPS origin, serviceDid: DID }
```

`serviceDid` MUST be resolved and verified separately. The service DID is not
Lexicon authority, and changing it MUST NOT change schema or codec bindings.

### Stable claim envelope

`tools.kan.claim` remains the semantic collection for every canonical kan
claim representation. Its envelope MUST contain:

```text
$type      = tools.kan.claim
codec      = Codec
claimCid   = CID string
signature  = bytes
rev        = TID
versioned claim payload
```

`codec` is the only schema-version discriminator. A second `schemaVersion`
field is forbidden. The Lexicon envelope MUST use an open payload boundary:
it validates the common envelope fields but does not close future payload
shapes over the v1 definitions. Exact payload validation is selected by the
codec entry. An older transport MUST therefore preserve a record carrying an
unknown future codec without interpreting it as a known version or stripping
fields. Generated clients MUST expose that unsupported payload as raw ATProto
data rather than deserialize and reserialize it through the v1 type.

The exact `kan-claim-v1` payload and inverse conversion remain those defined by
RFC 2 and implemented by `src/at_claim.rs`. RFC 3 changes neither its canonical
content bytes, content CID, nor signature semantics.

Codec strings MUST:

- contain 1 through 32 ASCII bytes;
- match `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`;
- compare byte-for-byte and case-sensitively; and
- satisfy the ATProto `record-key` grammar unchanged when used as an rkey.

### Append-only codec register

The collection `tools.kan.codec` has one record per codec. The rkey is exactly
the codec string. Its record contains:

```text
$type:                   tools.kan.codec
codec:                   Codec
claimLexicon:            NSID
envelopeLexiconRecordCid: CID link
envelopeLexicon:         bytes
payloadSchema:           Lexicon reference
payloadLexiconRecordCid: CID link
payloadLexicon:          bytes
sourceRepository:        URI
sourceCommit:            40 lowercase hexadecimal Git object ID
sourceTag:               immutable release-tag string
canonicalSpecification: URI
```

The separate collection `tools.kan.lens` has one record per directed lens. Its
rkey is exactly the globally unique lens identifier. Each record contains:

```text
$type:        tools.kan.lens
id:           LensId
sourceCodec:  Codec
targetCodec:  Codec
vectorsCid:   CID link
vectors:      bytes
total:        boolean
lossless:     boolean
sourceRepository: URI
sourceCommit: 40 lowercase hexadecimal Git object ID
sourceTag:    immutable release-tag string
canonicalSpecification: URI
```

`codec` MUST equal the rkey. `claimLexicon` for kan claim codecs MUST equal
`tools.kan.claim`. `envelopeLexicon` MUST be canonical DAG-CBOR for the exact
`com.atproto.lexicon.schema` record defining that envelope, and
`envelopeLexiconRecordCid` MUST reproduce from those bytes.
`payloadSchema` MUST be an exact Lexicon NSID-plus-fragment reference, and
`payloadLexicon` MUST be canonical DAG-CBOR for the schema record defining that
reference; `payloadLexiconRecordCid` MUST reproduce from those bytes. For
`kan-claim-v1`, `payloadSchema` is `tools.kan.defs#claimContent`.
`sourceCommit` and `sourceTag` MUST reproduce all embedded schema bytes from
`sourceRepository`. Each lens entry's `vectorsCid` MUST reproduce from its
canonical embedded `vectors` bytes and the same immutable source revision.

Each embedded value MUST declare a Lexicon byte maximum, and every codec or lens
record MUST remain within ATProto's one-megabyte record limit. A schema or
normative-vector set that does not fit is not publishable under this RFC; it
MUST NOT be truncated.

A publication MUST create no more than one codec entry, MUST contain no more
than 200 repository operations, and the complete block closure of its proposed
repository commit MUST be no larger than 2,000,000 bytes. The publisher MUST
construct and measure that closure before mutation and fail closed when either
aggregate limit is exceeded. Per-record validation does not establish commit
feasibility. Several codecs from one source release are published sequentially
as separately verified atomic publications; a later failure does not invalidate
an earlier immutable binding.

Codec and lens records are create-only. A request to create a byte-identical
existing entry is an idempotent success without a write. Any non-identical
existing codec entry is `codec-binding-conflict`; any reused lens ID or
non-identical lens entry is `lens-binding-conflict`. Both MUST fail before
repository mutation. Deletion is forbidden.

The embedded bytes and their CIDs make historical validation independent of
PDS history retention. The signed current repository proves the create-only
codec entry remains authoritative; the Git commit and tag establish public
source provenance. None substitutes for the others.

### Lens contract

Lens identifiers are globally unique stable strings in the authoritative
`tools.kan.lens` collection. A lens entry is immutable. Its `sourceCodec` and
`targetCodec` MUST each resolve to a valid codec entry, and its vectors define
a function from canonical decoded source values to either:

```text
success(canonical target value)
refusal(stable reason)
```

Lens identifiers contain 1 through 64 ASCII bytes, match
`[a-z][a-z0-9]*(?:-[a-z0-9]+)*`, compare byte-for-byte and case-sensitively,
and MUST also satisfy the ATProto `record-key` grammar unchanged.

A **total** lens has no refusal for any valid source value. A **lossless** lens
preserves all source information required by its declared inverse. A lens used
for default AppView normalization MUST be total. A lossy lens MUST NOT be
selected implicitly.

For each registered adjacent lens, two independent implementations MUST agree
on the normative vectors. Total lossless inverse pairs MUST satisfy:

```text
decodeTarget(encodeTarget(forward(x))) = forward(x)
backward(forward(x))                   = x
forward(backward(y))                   = y
compose(identity, forward)(x)          = forward(x)
```

for every valid vector in the declared domains. The first equality is byte
canonicalization; the others are value equality under the exact codec schemas.

`kan` ships the default Rust implementation. `kan-appview` MAY implement lenses
in another language, but it MUST pass the same vectors. The vectors, not one
implementation's internal API, are normative.

### AppView contract

The portable reference implementation lives in `kan-tools/kan-appview` and
implements the view Lexicons released by `kan-lexicon`. It MUST run outside
Railway against any conforming PDS and durable backing services.

Before projection the AppView MUST:

1. verify the raw ATProto repository proof and record CID;
2. resolve the exact codec entry;
3. hash and decode the embedded envelope and payload schemas, then validate the
   raw record against them;
4. reconstruct and verify the kan content CID and signature; and
5. resolve one verified repository snapshot of the complete
   `tools.kan.lens` collection and select a path consisting only of those
   registered lenses.

`tools.kan.getClaim`, `tools.kan.getSubject`, and `tools.kan.getIdentity`
default to the AppView's declared preferred codec. A caller MAY request a
specific target codec. Every normalized claim view contains:

```text
sourceCodec
viewCodec
sourceUri
sourceRecordCid
lensesApplied[]
```

The original content CID and signature remain available in the typed view.
Raw records remain retrievable through standard ATProto repository APIs.

Stable failures are:

| Error | Meaning |
|---|---|
| `unsupported-source-codec` | no valid codec entry or decoder |
| `unsupported-target-codec` | requested target is unknown |
| `lens-path-unavailable` | no registered total path connects source and target |
| `lens-refused` | an explicitly requested partial projection refused its input |
| `schema-binding-mismatch` | registry provenance does not reproduce the schema |
| `claim-cid-mismatch` | decoded canonical content does not reproduce `claimCid` |
| `invalid-signature` | claim signature verification failed |
| `source-snapshot-unavailable` | exact source repository state is unavailable |

The AppView MUST NOT fall forward from an unavailable snapshot, silently use a
lossy lens, or replace raw provenance with normalized provenance.

### Railway publication boundary

The public `kan-lexicon` release workflow validates an immutable tag and emits
public provenance. It has no production publication or deployment credential.
A Railway-hosted GitHub App receives authenticated release events. The event is
a trigger, not evidence: the publisher independently resolves the tag, checks
that it is immutable and eligible, checks out its exact commit, and reruns all
generation, lint, compatibility, client, codec, and lens gates.

PDS credentials are available only to Railway runtime services over the private
network. PDS signing material remains under PDS control on persistent storage.
Sealed Railway variables MUST have independently recoverable copies in an
operator-controlled protected vault before sealing. The vault begins with
macOS Keychain and an independent encrypted backup; it is a recovery root, not
an automated runtime dependency.

Staging and production MUST have separate services, secrets, volumes, and
promotion state. Railway-native backups MUST NOT be the sole recovery copy.
The runbook MUST reconstruct DNS, DID hosting, GitHub App configuration,
Railway services, PDS state, runtime secrets, and public verification from
declared recovery artifacts.

## Canonicalization and equivalence

Codec equality is exact ASCII byte equality. Codec strings are not case-folded,
Unicode-normalized, percent-decoded, or treated as semantic-version ranges.

A codec binding is equal only when every normative registry field is equal,
including both schemas and CIDs, payload reference, source commit and tag,
and canonical specification URI. A lens binding is equal only when its ID,
endpoints, classification, vector bytes and CID, and source provenance are all
equal. Two bindings with the same schema or vectors but different provenance
are not the same binding.

Lexicon JSON source follows ATProto Lexicon semantics. Each schema's immutable
identity in the registry is its DAG-CBOR record CID, not whitespace or JSON
object order in a checked-out file. The source tag and Git commit MUST
deterministically reproduce both registered record CIDs.

Lens path equality is ordered identifier equality. Two paths producing equal
view values remain distinct provenance when their identifiers differ.

A normalized view is not equivalent to its raw record as signed data. It is a
projection whose provenance points to that record. Equality of normalized
values never authorizes substitution of record CIDs, content CIDs, signatures,
or source snapshots.

## Resolution or processing algorithm

### Resolve a schema

1. Remove the final name segment from the NSID and reverse the remaining
   authority segments.
2. Query exactly `_lexicon.<authority-domain>`; do not recurse up or down.
3. Require exactly one supported `did=` value and, for `tools.kan.*`, require
   `did:web:kan.tools`.
4. Resolve the DID document and its standard PDS service.
5. fetch `com.atproto.lexicon.schema/<nsid>` from that DID's repository.
6. Require `$type = com.atproto.lexicon.schema`, `id = <nsid>`, rkey equality,
   and valid Lexicon language version.
7. Return the schema record CID and verified containing repository commit.

### Resolve a codec

1. Validate the codec grammar.
2. Resolve `tools.kan.codec/<codec>` from the Lexicon authority repository.
3. Require record `$type`, codec, and rkey equality.
4. Hash the embedded envelope and payload bytes and require their CIDs to equal
   `envelopeLexiconRecordCid` and `payloadLexiconRecordCid`; decode them as
   valid Lexicon schema records and require `payloadSchema` to resolve within
   the embedded payload schema.
5. Reproduce the schema and canonical codec fixtures from the registered Git
   commit and tag.
6. Return the immutable binding or a stable failure; never substitute the
   current schema record.

### Resolve the lens graph

1. List the complete `tools.kan.lens` collection from the same verified
   authority-repository snapshot used for the request.
2. Require each rkey to equal its globally unique `id`; duplicate IDs or any
   non-identical reuse fail the entire graph as `lens-binding-conflict`.
3. Resolve both endpoint codec entries and require exact byte equality with the
   lens record's `sourceCodec` and `targetCodec`.
4. Hash and decode the embedded vectors, require `vectorsCid` to reproduce,
   and reproduce them from the lens record's immutable Git repository, commit,
   and tag.
5. Build the directed graph from exactly that snapshot. Consumers MUST NOT
   infer edges from codec records, release order, local implementations, or
   records observed in a different repository commit.

### Publish a release

1. Receive an authenticated release notification.
2. Independently resolve the immutable release tag and commit.
3. Generate and validate every schema, client fixture, codec vector, and lens
   vector from that tree.
4. Resolve current authoritative records and compare the complete desired set.
5. Reject tag drift, source drift, an older desired binding, deletion, or a
   conflicting codec rkey.
6. Select exactly one new codec, construct one guarded
   `com.atproto.repo.applyWrites` request containing its changed current schema
   rkeys, create-only codec entry, and any create-only lens entries released
   with it. Reject a reused lens ID, more than 200 operations, or a proposed
   commit block closure larger than 2,000,000 bytes before mutation.
7. Commit once. A failure leaves both the current schema surface and that codec
   absent; there is no staged-unactivated state. Repeat from step 4 for another
   codec from the same release.
8. Starting from public DNS, read back and verify the complete desired set.
9. Record `verified` deployment provenance only after step 8. A committed write
   whose public read-back fails is `published-unverified`; retry verification
   before considering another write.

### Produce a normalized view

1. Resolve and verify the exact raw source snapshot and record.
2. Read `codec`; never infer it from record age or current schema.
3. Resolve and verify the codec binding and one complete lens-graph snapshot.
4. Verify canonical content CID and signature under that codec.
5. Select the requested target or the AppView's declared preferred codec.
6. Find a path of registered total lenses. For equal codecs, use the empty
   identity path.
7. Apply each lens deterministically and validate every intermediate value.
8. Return the typed view with raw provenance and ordered path.
9. On any failure, return its stable error without a partial or fallback view.

## Authority and trust model

DNS control of `kan.tools` is the root authority for the `tools.kan.*` NSID
group. `did:web:kan.tools` controls the authoritative schema repository. The
signed PDS repository establishes record history and commits; it does not
replace DNS namespace authority.

The merged `kan` RFC is authoritative for architecture and codec/lens
semantics. An immutable `kan-lexicon` tag and commit are authoritative public
source for generated schema artifacts. The codec record binds those two
authority planes; neither GitHub nor the PDS can silently redefine a historical
codec without producing a detectable mismatch.

The AppView service DID authenticates the service, not the Lexicon namespace.
An AppView is trusted only for the projections it proves from raw provenance.
Consumers MAY implement the same lenses independently and MUST be able to
verify raw claims without trusting the reference AppView.

Railway is an operational trust boundary, not protocol authority. GitHub
release events are untrusted triggers until independently verified. The
operator vault is recovery authority for deployment secrets but has no power
to change codec semantics without a public RFC, source release, and signed
repository publication.

## Security considerations

- **Public-workflow compromise:** Public GitHub Actions have no PDS, signing,
  Railway, or recovery credentials. A malicious event cannot publish until the
  Railway worker independently verifies immutable source and all gates.
- **Tag movement:** The publisher resolves and pins the commit itself. A moved
  or reused tag conflicts with recorded provenance and fails closed.
- **Codec rebinding:** Codec records are create-only. Non-identical reuse of an
  rkey is corruption, not an update.
- **Current-schema substitution:** Historical decoding starts from the codec
  entry's record and repository CIDs, never the mutable current schema rkey.
- **Lens downgrade:** Default normalization uses only registered total lenses.
  Lossy or partial conversion is never silent.
- **Provenance laundering:** A normalized view always exposes its raw AT URI,
  record CID, source codec, target codec, and lens path.
- **Mixed release:** Current schema updates, one self-contained codec entry,
  and its new globally registered lens entries share one atomic commit.
  Aggregate operation and block-closure limits are checked before mutation. A
  multi-codec release is a sequence of independently verified publications,
  never an oversized all-codec transaction.
- **DNS or domain loss:** This loses Lexicon and DID authority by design.
  Domain protection, registrar recovery, DNSSEC where operationally supported,
  and independent monitoring are required controls.
- **Railway loss:** Railway backups alone are insufficient because they remain
  coupled to the same project. Independent encrypted recovery material and a
  tested reconstruction procedure are required.
- **Sealed-secret loss:** A Railway sealed value is not recoverable through its
  UI or API. It MUST be backed up before sealing and rotation MUST update both
  operational and recovery copies.
- **PDS compromise:** Repository signatures, public drift monitoring, immutable
  source bindings, and external backups bound impact and make unauthorized
  changes observable. Recovery rotates affected keys and republishes identical
  valid state; it does not rewrite codec history.
- **Service-identity confusion:** The AppView DID and Lexicon authority DID are
  distinct. Discovery of one never grants the other's authority.

## Compatibility

`kan-claim-v1` remains byte-for-byte compatible with RFC 2. Existing content
CIDs, signatures, local MST keys, and legacy-to-current migration results do
not change. An identity lens from v1 to v1 MUST reproduce the same decoded
value and canonical bytes.

RFC 3 amends only these parts of RFC 2:

- RFC 2 REQ-17's statement that the Lexicon authority DID is also the canonical
  AppView service DID is replaced. Its DID document remains the discovery root,
  but the service endpoint names and authenticates a separately governed DID.
- RFC 2 REQ-18 continues to make `kan-tools/kan-lexicon` the canonical schema
  source. Its five current closed v1 schemas remain the exact v1 definition,
  while the `tools.kan.claim` transport envelope becomes open at the versioned
  payload boundary and exact typing is selected by the append-only codec
  register.
- RFC 2 REQ-14 and the affected REQ-15 current-view rules continue to reject
  unsupported codecs at semantic decode and AppView projection boundaries, but
  no longer permit a transport, mirror, or repository reader to discard an
  otherwise valid raw ATProto record merely because its codec or payload shape
  is unknown. Preservation is not publication as a known codec and never
  authorizes interpretation as v1.

Older consumers that support only v1 MUST preserve unsupported future records
and report `unsupported-source-codec`; they MUST NOT decode them as v1. Newer
AppViews continue serving v1 through the identity path and MAY normalize it to
a later codec only through registered total lenses.

The initial authoritative publication MUST include `kan-claim-v1`, MUST bind
it to the exact schema shipped from `kan-lexicon`, and MUST create the canonical
v1 identity-lens entry. No second real codec is required to implement this RFC;
a synthetic future codec exercises extension and refusal behavior in
conformance tests.

## Alternatives considered

- **New NSID for every representation version:** Rejected because it fragments
  collection identity, firehose filtering, and semantic record type. A new
  NSID remains correct for genuinely different semantics.
- **Use only the mutable current schema record:** Rejected because historical
  records would lack an unambiguous immutable schema binding.
- **Add `schemaVersion` beside `codec`:** Rejected because both fields express
  one fact and can disagree. `codec` already exists and is required.
- **Use Git tags without an ATProto codec register:** Rejected because a raw
  network record would not carry a network-resolvable binding to exact schema
  provenance.
- **Reference historical repository commits:** Rejected because standard PDS
  APIs do not guarantee arbitrary historical commit retention or expose the
  containing-commit proof this would require. The live create-only codec record
  instead embeds exact schema bytes and CIDs and binds them to immutable source.
- **Publish a mutable release-manifest singleton:** Rejected as a second mutable
  source of truth. Atomic commits, append-only bindings, and deployment
  provenance cover the required facts.
- **Put production PDS credentials in `kan-lexicon` Actions:** Rejected because
  public source validation compromise would become publication authority.
- **Have private infrastructure poll GitHub:** Viable but rejected as the
  default because an authenticated GitHub App event is immediate without
  granting GitHub production credentials.
- **Use `did:plc` for Lexicon authority:** Rejected because DNS already controls
  NSID resolution; PLC adds a dependency without preserving authority after
  domain loss.
- **Use one DID for every kan service:** Rejected because Lexicon authority,
  AppView operation, relay operation, and human identity have different
  lifecycles and compromise domains.
- **Implement the AppView only inside `kan-infra`:** Rejected because private,
  deployment-coupled code cannot be an independently portable reference
  implementation.
- **Normalize by rewriting stored records:** Rejected because it destroys raw
  provenance and invalidates signatures and record CIDs. Lenses are views.

## Reference test vectors

Normative proposal vectors live at
`tests/fixtures/lexicon-publication-v1/manifest.json`. The proposal fixture
covers:

1. exact `tools.kan` authority derivation and non-recursive DNS lookup;
2. `did:web:kan.tools` resolution and a distinct AppView service DID;
3. valid and invalid codec strings;
4. exact codec/rkey equality and immutable binding fields;
5. idempotent create and conflicting rebind;
6. atomic schema, codec, and globally keyed lens publication plus injected
   pre-commit failure;
7. exact embedded envelope and payload schemas with reproducible DAG-CBOR CIDs;
8. executable identity, total lossless, partial, lossy, refusal, and round-trip
   lens examples;
9. exact default, requested, partial, lossy, and unknown-codec normalization
   outcomes;
10. the required normalized-view provenance field set;
11. public GitHub, private Railway, PDS-volume, and external-vault secret
    boundaries; and
12. published-unverified recovery without a blind second write.

`scripts/check-lexicon-publication-v1-fixtures.py` independently encodes the
concrete schema values as deterministic DAG-CBOR, reproduces their CIDs,
executes the synthetic lens examples and laws, requires every finite matrix and
inventory exactly, and runs hostile mutation controls. The controls include the
invalid states found during cold review: empty authority, insecure endpoint,
mislabeled or duplicated resolution, deletion of negative codec cases, changed
schema bytes or CID, split or multi-codec publication, wrong lens output,
deletion of a coherently rehashed refusal vector, unknown-codec identity, lossy
default normalization, missing provenance, and deleted secrets. The harness
does not import kan's Rust implementation.

The checked codec record is explicitly `fixtureOnly` and uses the reserved
synthetic codec `kan-claim-v2-test`. It contains the actual base64-encoded
DAG-CBOR envelope, payload, and per-lens vector bytes; linked CIDs and declared
byte maxima must reproduce those bytes, and the complete encoded record must
remain below one megabyte. The fixture publication contains exactly one codec
and seven operations, including four globally keyed lens records. It does not
construct an MST, signed commit, inversion proof, or CAR and therefore makes no
claim to prove the complete commit-block closure; that remains AC-5 evidence
for the publisher implementation. Its `example.invalid` repository, zero commit, and
fixture tag are deliberately non-publishable sentinel provenance. The checker
requires those exact sentinels so proposal evidence cannot masquerade as a
released `kan-lexicon` binding. A production entry MUST omit `fixtureOnly` and
pass the immutable Git source-reproduction requirement.

The publication vectors execute a repository-state transition: all desired
schema keys and the single codec key enter one candidate map and become visible
through one simulated `applyWrites` commit, while injected pre-commit failure
preserves the prior map byte-for-byte and verification retry performs no write.
This proves the proposal state machine, not the behavior of the unbuilt
publisher or PDS.

These are proposal self-consistency vectors, not evidence that the unbuilt
publisher, AppView, infrastructure, or independent implementations satisfy the
implementation acceptance criteria. AC-3 through AC-16 remain pending where
they require those artifacts; RFC acceptance approves the contract, not a
fiction that deployment evidence already exists.

Implementation acceptance additionally requires two codec/lens implementations
to pass canonical byte vectors and one portable AppView run outside Railway to
produce the same typed views as the deployed service.

## Unresolved questions

None.

## Deferred questions

- The first real post-v1 codec and its lens semantics. A synthetic future codec
  is sufficient to prove envelope extensibility without inventing a migration.
- General dependency solvers, version ranges, and lockfiles for arbitrary
  third-party Lexicon graphs.
- A network-wide standard for lens publication. `tools.kan.lens` specifies the
  kan convention without claiming protocol-wide authority.
- The product and access-control model for hosted private kan scopes.
- Additional AppView instances and selection policy beyond explicit RFC 2
  service selection.

## Implementation status

Not implemented. The governing design is
`.design/rfc-3-authoritative-lexicon-publication.md`. RFC 2 supplies the
existing `kan-claim-v1` conversion and five draft schemas. Implementation will
add the codec register and version-aware schemas in `kan-lexicon`, the portable
`kan-appview` repository, and private Railway deployment in `kan-infra`.
