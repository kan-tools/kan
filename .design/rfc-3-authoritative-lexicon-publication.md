# Feature: RFC 3 — authoritative Lexicon publication and versioned AppView

## Summary

Define how the kan repository family publishes authoritative `tools.kan.*`
Lexicons, binds every claim codec to an immutable schema version, supplies
official version lenses, and serves normalized views without rewriting signed
records. The design separates public protocol source, portable AppView code,
private Railway operations, and the DNS-rooted Lexicon identity so that no
GitHub workflow holds production publication credentials.

## Requirements

- REQ-1: RFC 3 is owned by the `kan` repository under the process in
  `rfcs/0-rfc-and-adr-process.md`, even though implementation is divided among
  the kan repository family. Architectural decisions do not move into a
  component repository merely because that component implements them.
- REQ-2: The repository family has four explicit ownership boundaries:
  `kan` owns RFCs, canonical claim codecs, and normative lens semantics;
  public `kan-tools/kan-lexicon` owns Lexicon source, generated clients,
  release tags, and cross-language fixtures; public
  `kan-tools/kan-appview` owns a portable reference AppView implementation;
  and private `kan-tools/kan-infra` owns Railway deployment, credentials,
  recovery procedures, monitoring, and environment configuration.
- REQ-3: Authority for every `tools.kan.*` NSID group is rooted by the DNS TXT
  record `_lexicon.kan.tools`, whose value is `did=did:web:kan.tools`.
  `https://kan.tools/.well-known/did.json` is hosted independently of Railway
  and names the PDS endpoint carrying the authoritative Lexicon repository.
  This DID is dedicated to Lexicon authority; other kan ATProto services may
  use separate DIDs chosen for their own lifecycle and threat model.
- REQ-4: GitHub validates and announces `kan-lexicon` releases but holds no
  PDS credential, repository signing key, Railway API token, or DID recovery
  secret. A Railway-hosted GitHub App receives authenticated release events,
  independently fetches and verifies the immutable tag and commit, and invokes
  a publisher over Railway's private network. Runtime secrets are sealed in
  Railway; independently recoverable copies are held in an operator-controlled
  protected vault outside GitHub and Railway.
- REQ-5: Publication materializes each schema as a
  `com.atproto.lexicon.schema` record whose rkey equals its NSID. One guarded
  repository commit atomically updates current schema rkeys and creates exactly
  one associated codec entry, which embeds the canonical envelope schema,
  payload schema, plus any create-only `tools.kan.lens` records released with
  it, each carrying vectors and their content CID. The publisher
  rejects more than 200 operations or a proposed commit block closure larger
  than 2,000,000 bytes before mutation. A release with several new codecs uses
  separately verified atomic publications. Publication is idempotent,
  rejects tag or source drift, and never declares success until complete-set
  read-back through DNS, DID, and the public PDS route matches the tagged
  source.
- REQ-6: `tools.kan.claim` remains the stable semantic collection across
  representation changes. Its required `codec` field is the sole claim-schema
  version discriminator; RFC 3 does not add a redundant `schemaVersion` field.
  `content` is an open Lexicon union whose known object arms carry `$type` and
  generate concrete wire types. The codec entry's `payloadSchema` must equal
  the selected arm's `$type`; invalid combinations fail before semantic decode.
  Unknown codec/arm pairs are preserved as raw ATProto data but unsupported by
  semantic readers.
- REQ-7: The authority repository carries append-only `tools.kan.codec` and
  `tools.kan.lens` registers. Codec records are keyed by codec string; lens
  records are keyed by a globally unique lens ID and bind exact source and
  target codecs. Consumers construct the directed graph from one complete
  verified authority-repository snapshot, never from codec-local hints.
  Each codec entry binds the codec to its claim-envelope NSID, canonical embedded
  envelope schema and CID, exact payload Lexicon reference, canonical embedded
  defining schema and CID, immutable `kan-lexicon` Git commit and release tag,
  and canonical codec specification. Each lens entry embeds normative vectors
  and CID with the same source provenance. Re-creating an identical entry is
  idempotent; changing an existing binding or reusing a lens ID is corruption
  and fails closed.
- REQ-8: Every published codec has immutable normative canonical bytes,
  validation rules, and valid and invalid vectors. `kan` supplies a default
  executable lens for each supported adjacent codec transition, while
  repository-family fixtures are implementation-independent. Lenses are
  deterministic projections over preserved raw records: total lossless lenses
  obey identity and round-trip laws; partial or lossy transformations are
  explicitly classified and are never selected by default normalization.
- REQ-9: The reference AppView defaults typed view XRPC responses to its
  declared current preferred codec and accepts an optional requested target
  codec. Every normalized response carries `content` in the same append-only
  open typed union as `tools.kan.claim`; `viewCodec` must resolve to a codec
  entry whose `payloadSchema` equals `content.$type`. It also discloses
  `sourceCodec`, the original AT URI and record CID, and the ordered lens
  identifiers applied.
  Missing, partial, or lossy lens paths fail with a stable typed error. Among
  eligible paths the AppView minimizes hop count and then chooses the bytewise
  lexicographically smallest lens-ID sequence. Raw retrieval
  remains available through standard ATProto repository APIs and is never
  replaced by a normalized view.
- REQ-10: `kan-tools/kan-appview` is portable application code, not Railway
  configuration. It implements the view Lexicons owned by `kan-lexicon`,
  verifies raw claim CID and signature before projection, selects only
  registry-authorized lenses, and can run outside Railway against any
  conforming PDS and durable backing services. `kan-infra` deploys a pinned
  AppView artifact but does not become its source repository.
- REQ-11: Lexicon and codec evolution is monotonic. Existing raw records remain
  valid and retrievable; unsupported codecs are preserved and reported rather
  than repaired or decoded as current. A new codec represents a new canonical
  claim encoding under the stable collection. A new NSID is required only for
  a different semantic record type. Operational recovery restores identical
  authoritative state; schema history is not rolled back or rebound.
- REQ-12: Railway deployment includes separate staging and production
  environments, persistent PDS state, scheduled and independently restorable
  backups, health checks, public-resolution probes, drift detection, key and
  credential rotation, and a tested reconstruction runbook. Railway volume
  backups are not the sole recovery copy because they remain coupled to the
  Railway project and environment.
- REQ-13: RFC 3 explicitly amends RFC 2 REQ-14 and affected REQ-15 view clauses
  so unknown future codecs are preserved by raw transports but still rejected
  at semantic decode and projection boundaries. It supersedes the current-only
  closed projection where that shape prevents raw preservation, while retaining
  `kan-claim-v1`, its exact inverse conversion, content CID, signature, and
  migration guarantees from `src/at_claim.rs` and `src/store/log.rs`. It also
  supersedes RFC 2's requirement that the Lexicon authority DID itself be the
  canonical AppView service DID; discovery may point to a separately governed
  AppView DID without transferring Lexicon authority.
- REQ-14: Production publication is gated by an independently implementable
  conformance suite covering schema resolution, codec-register verification,
  atomic publication, lens laws, AppView normalization, provenance disclosure,
  secret-boundary negative controls, and recovery. A failed check cannot be
  waived by treating a Git tag, Railway deployment, or successful write
  response as equivalent to verified public availability.
- REQ-15: A publishable `kan-atproto` workspace crate owns Lexicon-generated
  wire DTOs, the typed open union and raw unknown arm, `$type`, record bounds,
  and codec/content-type validation without depending on kan's domain model.
  `src/at_claim.rs` is reduced to a thin adapter; internal `ClaimContent`, its
  canonical bytes, CID, and signatures never acquire wire-only `$type` data.

## Acceptance Criteria

- [ ] AC-1: `rfcs/3-authoritative-lexicon-publication.md` passes
      `scripts/check-rfcs-adrs.sh`, is indexed by `rfcs/README.md`, and names
      all four repository-family ownership boundaries without moving RFC
      authority out of `kan`. (REQ-1, REQ-2)
- [ ] AC-2: Resolution vectors derive `_lexicon.kan.tools` from each published
      `tools.kan.*` NSID, require exactly `did=did:web:kan.tools`, resolve the
      independently hosted DID document, validate its exact standard PDS
      service entry, and reach the configured PDS. Negative
      vectors reject a wrong DID, wrong authority group, missing TXT record,
      unavailable DID document, and PDS endpoint mismatch. (REQ-3)
- [ ] AC-3: A secrets inventory assigns every credential and recovery artifact
      to GitHub, Railway runtime, the PDS volume, or the external protected
      vault. A CI negative control proves pull requests and release workflows
      in public repositories cannot read or exercise any production PDS,
      Railway, signing, or recovery credential. (REQ-4)
- [ ] AC-4: An authenticated release event causes the Railway publisher to
      resolve the tag to an allowlisted immutable commit, re-run all
      `kan-lexicon` validation from that tree, and reject a moved tag, payload
      SHA supplied only by the event, untagged commit, failed validation, or
      source tree differing from the release provenance. (REQ-4, REQ-5)
- [ ] AC-5: A publication fixture changing multiple mutually referring
      Lexicons produces one guarded commit containing current schema updates
      and exactly one create-only codec entry with embedded immutable schemas,
      plus its create-only globally keyed lens entries. The real publisher
      reproduces deterministic MST/inversion block shapes and a size-equivalent
      preflight CAR using fixed-width placeholders for PDS-chosen values. The
      PDS constructs and signs the actual commit, enforces the 200-operation
      and 2,000,000-byte `commit.blocks` CAR limits atomically. Standard APIs
      do not expose that exact per-commit CAR after the fact; the publisher
      performs complete public record read-back without claiming CAR
      verification. An
      injected pre-commit failure leaves all schema and codec rkeys unchanged,
      and public read-back checks the complete set rather than only changed
      records.
      (REQ-5)
- [ ] AC-6: Replaying one release against identical authoritative records
      performs no semantic write and succeeds with the same bindings. Reusing
      a tag for different bytes, publishing an older desired state over a newer
      binding, or changing an existing codec-register entry fails before a
      repository commit. (REQ-5, REQ-7, REQ-11)
- [ ] AC-7: The evolved `tools.kan.claim` Lexicon requires exactly one `codec`
      discriminator and an open `content` union with typed v1 and synthetic
      future arms. Fixtures require `$type`, accept exact registered codec/arm
      pairs, reject every mismatch as `codec-content-type-mismatch`, and show
      an old transport preserving an unknown codec plus unknown arm without
      interpreting it as v1. (REQ-6, REQ-11, REQ-13)
- [ ] AC-8: Codec/lens-register fixtures resolve a codec to exact embedded
      envelope and payload schema bytes and CIDs and resolve a complete,
      globally keyed lens graph from one repository snapshot. They reproduce
      schemas and vectors from the pinned `kan-lexicon` tag and Git commit and
      reject mismatched codec, endpoint, lens ID, NSID, bytes, record CID, Git
      tree, or tag.
      (REQ-7)
- [ ] AC-9: Two independent implementations validate the codec/lens registers
      and every codec's positive and negative canonical-byte vectors. Mutation
      tests prove that changing canonical bytes, a bound, a discriminator, or
      a registered schema CID is detected. (REQ-7, REQ-8, REQ-14)
- [ ] AC-10: Lens fixtures exercise identity, deterministic output, composition,
      and round-trip laws for every total lossless adjacent lens. A declared
      partial lens returns its specified refusal outside its domain, and a
      lossy lens is never used by default normalization. (REQ-8)
- [ ] AC-11: AppView contract tests request the default and an explicit target
      codec and assert `sourceCodec`, `viewCodec`, original AT URI, original
      record CID, ordered lens identifiers, and a concrete known arm of the
      open view-content union. Exact fixtures accept registered
      `viewCodec`/`content.$type` pairs and reject a mismatch. Unsupported
      target codecs, absent paths, partial paths, invalid signatures, and
      claim-CID mismatch return stable declared errors without a fabricated
      view. (REQ-9, REQ-10)
- [ ] AC-12: The reference AppView's conformance suite runs both in its normal
      Railway deployment and in an independent local container against a
      conforming test PDS, with equivalent typed XRPC results and provenance.
      No test imports private `kan-infra` code or configuration. (REQ-2,
      REQ-10)
- [ ] AC-13: Compatibility fixtures prove every RFC 2 `kan-claim-v1` record
      reprojects through a wire-only `content.$type` while reconstructing
      identical internal canonical signed content, content CID, and signature.
      Pre-RFC-3 local ATProto records migrate deterministically to the union
      shape before publication, the v1 identity AppView projection is
      unchanged, and existing legacy migration fixtures remain green. (REQ-11,
      REQ-13, REQ-15)
- [ ] AC-14: A service-discovery fixture proves that Lexicon resolution remains
      rooted in `did:web:kan.tools` while the canonical AppView endpoint can
      authenticate as a different declared, separately resolved service DID
      whose authenticated endpoint matches the authority service entry.
      Changing the AppView DID or endpoint cannot change the codec register or
      Lexicon authority.
      (REQ-3, REQ-10, REQ-13)
- [ ] AC-15: Staging exercises initial deployment, repeated deployment,
      credential rotation, PDS restart, AppView replacement, public DNS/DID/PDS
      resolution, volume restoration, and complete reconstruction from the
      external protected vault. Each exercise produces an auditable result and
      production promotion requires all results to pass. (REQ-12, REQ-14)
- [ ] AC-16: A scheduled drift probe starts from public DNS, resolves the DID
      and PDS, verifies every current schema and append-only codec binding,
      checks the deployed AppView artifact and normalization contract, and
      alerts on any divergence from the last verified release provenance.
      (REQ-5, REQ-7, REQ-10, REQ-12, REQ-14)
- [ ] AC-17: `kan-atproto` can encode/decode every known union arm, preserve and
      byte-stably re-emit canonical DAG-CBOR for an unknown arm containing
      nested values, bytes, and a CID link, and reject a codec/arm mismatch
      without constructing domain `ClaimContent`. Dependency and source scans
      prove the crate has no domain-model dependency and `$type` handling does
      not spread outside it and the thin `src/at_claim.rs` adapter. (REQ-15)

## Architecture

### Repository-family boundary

RFC 3 treats the repositories as one governed family with deliberately
different visibility and release units. The architectural source of truth
remains this repository's `rfcs/` tree. The current projection and migration
implementation in `src/at_claim.rs` and `src/store/log.rs` remains the
executable definition of `kan-claim-v1` until the RFC implementation extracts
wire DTOs and validation into the publishable `kan-atproto` workspace crate.
That crate does not depend on domain `ClaimContent`; `src/at_claim.rs` retains
only explicit conversions between the wire crate and internal types.

The public `kan-tools/kan-lexicon` repository continues to own the five schemas
currently pinned by `scripts/check-kan-lexicon-sync.py`, and gains the codec
register, version-aware view contracts, generated clients, and cross-language
fixtures. The new public `kan-tools/kan-appview` repository contains the
portable service and container image. Private `kan-tools/kan-infra` contains
Railway configuration, deployment pins, operational probes, and runbooks. A
private deployment repository may select an artifact; it may not silently fork
the public AppView behavior.

### Authority and service identities

For `tools.kan.claim`, the NSID authority is `tools.kan`, so the protocol lookup
is exactly `_lexicon.kan.tools`. Its TXT value is
`did=did:web:kan.tools`. The DID document is static authority material hosted
outside the Railway failure domain and points to the authoritative PDS.

This coupling is deliberate. Loss of `kan.tools` already permits replacement
of the `_lexicon` TXT record, so a PLC DID cannot preserve namespace authority
against domain loss. `did:web` avoids an additional PLC dependency and makes
DNS recovery and Lexicon-DID recovery one operation. The consequence is
explicit: loss of the domain loses both authorities.

The Lexicon DID is not a universal kan service identity. The reference AppView,
relay, and future services can use independent DIDs. Canonical discovery may be
advertised from authority-controlled metadata, but clients verify the selected
service DID separately and never treat it as authority to redefine a Lexicon
or codec binding.

### Publication control plane

The public release workflow validates a release and emits provenance; it does
not deploy infrastructure or publish records. A Railway-hosted GitHub App
receives the authenticated release event. The private publisher treats the
event as a notification rather than evidence: it resolves the tag through
GitHub, verifies the expected commit and release state, checks out only that
tree, reruns schema generation, linting, client fixtures, compatibility checks,
and codec/lens vectors, then constructs the desired ATProto writes.

PDS credentials are sealed Railway runtime variables or internal service
credentials. Repository signing material remains under PDS control on its
persistent volume. The operator's protected vault carries independently
recoverable bootstrap and recovery copies; it begins in macOS Keychain and is
backed up to a separately protected vault such as Proton Pass. Because sealed
Railway variables cannot be read back, sealing is permitted only after the
recovery copy and reconstruction test exist.

All changed `com.atproto.lexicon.schema` records, exactly one create-only
`tools.kan.codec` entry, and its create-only `tools.kan.lens` entries are
written in one swap-guarded atomic commit. Each codec entry embeds canonical
DAG-CBOR bytes for its envelope and payload schema records plus the CIDs those
bytes reproduce; each globally keyed lens entry embeds canonical vectors with
their CID and source provenance. Historical verification therefore needs
neither a self-referential containing-commit field nor an archival PDS API. After the
commit, verification begins from public DNS and checks the complete desired
set. A write success without public verification is
`published-unverified`, not deployed; retry performs read-back before any new
write.

### Stable envelope and append-only codec/lens registers

RFC 2 made `tools.kan.claim` the canonical collection and `codec` a required
field with `kan-claim-v1` as a known value. RFC 3 promotes that field into the
normative version dispatch mechanism. The collection continues to mean “a kan
claim”; codecs distinguish canonical representations without fragmenting
firehose filters, storage collections, or the semantic record type.

The authoritative current Lexicon is an extensible transport envelope whose
`content` field is an open union. Known arms such as
`tools.kan.defs#claimContent` generate explicit wire DTOs and carry `$type`;
unknown arms remain raw objects. Exact semantic typing comes from requiring the
codec register's `payloadSchema` to equal the selected arm's `$type`, not from
assuming the current schema existed when a historical record was written. A
register entry binds:

```text
codec                 = kan-claim-v1
claimLexicon           = tools.kan.claim
envelopeLexiconRecordCid = immutable CID of the envelope schema record
envelopeLexicon         = canonical DAG-CBOR bytes of that record
payloadSchema          = tools.kan.defs#claimContent
payloadLexiconRecordCid = immutable CID of the payload-defining schema record
payloadLexicon          = canonical DAG-CBOR bytes of that record
sourceRepository       = kan-tools/kan-lexicon
sourceCommit           = immutable Git commit
sourceTag              = immutable release tag
canonicalSpecificationRepository = kan-tools/kan
canonicalSpecificationCommit = immutable Git commit
canonicalSpecificationPath = governing RFC path
```

The record rkey is the codec string. Register writes are append-only: a later
release can add a codec but cannot rebind one. The Git tag provides schema
source history; embedded schema bytes and CIDs make exact historical validation
available from the live codec record without depending on retained repository
commits. Separate globally keyed `tools.kan.lens` records carry vector bytes,
CIDs, endpoints, and their source and semantic provenance. The signed authority
repository proves that each create-only binding remains current.

Wire-only `$type` never enters internal `ClaimContent`. The `kan-atproto` crate
owns known and raw-unknown union arms and rejects invalid codec/arm pairs;
`src/at_claim.rs` removes the discriminator on inward conversion and restores
it on outward projection. This deliberately changes the pre-publication
ATProto record projection while preserving internal canonical bytes, content
CIDs, and signatures.

### Lenses and normalized views

A lens edge is identified, directed, and tied to exact source and target
codecs. The normative behavior is a set of implementation-independent vectors
and laws. `kan` ships the default implementation; the portable AppView and
other languages demonstrate agreement against the vectors. A total lossless
lens has deterministic output and round-trips through its declared inverse. A
partial lens declares its domain and typed refusal. A lossy transform is not a
lens eligible for default normalization.

The AppView verifies the raw record and resolves its exact registry binding
before projection. Its view methods default to a declared current preferred
codec or accept a requested target. A path is composed only from official
registered total edges. The response carries raw provenance and the selected
path, making normalization an inspectable projection in the same spirit as
kan's fold: raw attested data remains intact, while simplification occurs at
the view boundary.

The proposal fixture uses `kan-claim-v2-test` with an explicit `fixtureOnly`
sentinel rather than falsely claiming an unpublished envelope came from the
released `kan-lexicon` v0.1.0 tag. It serializes the actual synthetic envelope,
payload, and per-lens vector DAG-CBOR bytes into the codec record, verifies
their linked CIDs and maxima, enforces the complete record-size ceiling, and
executes the one-commit repository transition. Production source provenance
remains an implementation acceptance criterion and cannot be satisfied until
the corresponding immutable `kan-lexicon` release exists.

### Recovery and drift

Railway staging and production have separate services, secrets, volumes, and
promotion state. Scheduled volume backups cover ordinary failure, while an
external encrypted recovery set covers total Railway-project loss. The runbook
must recreate DNS, static DID hosting, Railway services, PDS repository state,
GitHub App configuration, sealed runtime variables, and public verification
from declared artifacts rather than undocumented operator memory.

Drift detection follows the consumer route. It does not trust the Railway
dashboard: it starts at `_lexicon.kan.tools`, resolves `did:web:kan.tools`,
fetches the PDS repository records, checks their CIDs and commit, validates the
append-only register, calls the deployed AppView, and compares all results with
the last verified immutable release provenance.

## Resolved Questions

- RQ-1: Lexicon namespace authority uses dedicated `did:web:kan.tools`; other
  infrastructure identities are separate where their lifecycle warrants it.
- RQ-2: Railway is the runtime and secret boundary. GitHub validates releases and
  emits events but holds no production publication or deployment credential.
- RQ-3: Current schemas and exactly one self-contained codec entry publish in
  one atomic commit within ATProto's operation and complete-block-closure
  limits, followed by complete public-route read-back. Multi-codec releases use
  separately verified publications; no mutable
  release-manifest record or historical PDS API is a second source of truth.
- RQ-4: `tools.kan.claim` remains stable and required `codec` supplies explicit
  record-level versioning. An append-only register binds codecs to immutable
  schema CIDs and source commits, and official law-tested lenses connect
  versions.
- RQ-5: The AppView automatically normalizes through registered total lenses while
  disclosing raw provenance and the exact lens path. Its reference
  implementation lives in public portable `kan-tools/kan-appview`, not in
  private deployment configuration.

## Open Questions

None.

## Out of Scope

- Implementing or deploying the PDS, publisher, AppView, DNS records, GitHub
  App, Railway project, or external vault during the RFC-authoring change.
- Defining a second claim codec before a representation change is actually
  needed; RFC 3 defines the registration and lens contract and uses a synthetic
  future codec for conformance.
- General-purpose package dependency solving, version ranges, or SAT resolution
  for arbitrary third-party Lexicons.
- Guaranteeing that third-party AppViews normalize claims; raw records and the
  public codec register remain sufficient for independent implementations.
- Giving the Lexicon authority DID control over unrelated relays, AppViews,
  hosted kan scopes, or human accounts.
- Treating Railway-native backups as the only disaster-recovery mechanism or
  the operator's personal vault as an automated production secret service.
