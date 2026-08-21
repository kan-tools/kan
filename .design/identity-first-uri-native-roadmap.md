# Feature: Identity-first URI-native product roadmap

## Summary

Sequence kan's next product milestones from foundations outward: implement the
accepted identity architecture, make the existing CLI and MCP surface resolve
resources through RFC 2 URIs, ship a self-hostable kan-native cloud service
using the same URI and typed API model, and only then add RFC 3 ATProto
publication and interoperability. The sequence makes identity, repository
scope, admission, and URI resolution product primitives rather than details
retrofitted beneath a network transport.

## Requirements

- REQ-1: The roadmap must preserve the dependency order identity → local URI
  application → kan-native hosted service → ATProto interoperability. A later
  milestone may prototype against an earlier contract, but it may not become
  the authority for identity, repository scope, admission, or URI semantics.
- REQ-2: Milestone 1 must implement accepted RFC 1 in compatibility-first
  stages: control-event and resolver primitives, system and repository
  identity, governance and delegated admission, modern claim authorship, and
  finally the default-write cutover. Existing claims and released workspaces
  must remain byte-stable and verifiable throughout.
- REQ-3: The identity implementation must keep cryptographic validity,
  identity-state standing, repository admission, and view trust as four
  separately reported judgments. It must not collapse repository identity,
  acting principal, role, verification method, or trust frame into one value.
- REQ-4: Identity cutover must be gated by RFC 1 reference vectors, released-
  workspace migration fixtures, the migration matrix, and explicit recovery
  paths. New identity behavior must not become the default while a lost key,
  binary upgrade, worktree, or recovery phrase can silently hide prior claims.
- REQ-5: Milestone 2 must make RFC 2's `ResolutionRequest` the common internal
  read model for the existing CLI and MCP application. Existing read verbs are
  local shorthand that compile to canonical `kan://local/...` requests rather
  than a second resolution implementation.
- REQ-6: Local URI resolution must cover claims, subjects, scope identity,
  authority identity, scoped principals, freestanding principals, source and
  snapshot selection, admission, and trust without causing signing, identity,
  governance, credential, or trust side effects.
- REQ-7: Milestone 3 must define and ship a public, self-hostable kan-native
  server repository that can be deployed to Railway as a container with
  persistent storage and recovery. A deployment at an authority such as
  `whatever.com` must resolve canonical resources such as
  `kan://whatever.com/kan-tools:kan/subject/...`.
- REQ-8: The hosted server must expose typed claim, subject, and identity read
  APIs with the same provenance, snapshot, admission, and trust semantics as
  the local resolver. Authenticated ingest and administration are separate
  APIs; credentials and acting authority must never be encoded in a read URI.
- REQ-9: The kan-native hosted resolver is distinct from the existing L1 blind
  backup design. The hosted resolver is allowed to understand indexed claims
  for authorized scopes; an encrypted backup remains opaque object storage and
  cannot satisfy URI resolution or AppView-like queries.
- REQ-10: The hosted API contract must be portable and deployment-neutral so
  the later RFC 3 AppView can reuse its domain model, conformance fixtures, and
  normalization behavior without importing Railway configuration or private
  infrastructure code.
- REQ-11: Milestone 4 must implement RFC 3 issues #235–#243 only after the
  local and hosted URI surfaces prove the resource model. ATProto codecs,
  Lexicons, PDS publication, and AppView endpoints adapt the proven kan model;
  they do not redefine it.
- REQ-12: Every milestone must carry a bounded maintenance lane. Security,
  silent-data-loss, migration, and recovery defects touched by that milestone
  are audited or fixed before release, while unrelated ergonomics and research
  issues remain visible without blocking the product spine.
- REQ-13: Every persistence change in all four milestones must update the
  read/write surface catalog, typed persistence capability, and conformance
  suite together. Derived indexes, hosted views, and AppView responses remain
  reproducible projections over retained raw evidence.
- REQ-14: GUI and TUI work must be tracked as later clients of the same URI and
  typed API contracts. They may add navigation, graph exploration, and
  identity/admission/trust presentation, but they must not create new storage,
  fold, authority, or mutation semantics.
- REQ-15: Each milestone must end in a mechanically witnessed release gate and
  a reconciled issue inventory: completed issues close, absorbed issues point
  to their replacement milestone, stale issues are verified before closure,
  and deferred issues retain an explicit reason.

## Acceptance Criteria

- [ ] AC-1: Milestone 1 adds reproducible RFC 1 identity vectors covering
      control-event CIDs, `did:kan`, repository inception, governance,
      delegation attenuation, revocation, contested histories, modern claim
      authorship, and all four read judgments. Two implementations agree on
      the canonical vectors. (REQ-2, REQ-3)
- [ ] AC-2: Released-workspace fixtures retain every legacy claim byte and
      signature while exercising identity creation, import, recovery, binary
      upgrade, worktree use, and default-write cutover. A negative control
      proves new writes cannot silently mint a replacement identity over prior
      state. (REQ-2, REQ-4)
- [ ] AC-3: Structured identity reads independently report cryptographic
      validity, identity standing, repository admission, and view trust for
      valid, invalid, unsupported, unknown, contested, admitted, unadmitted,
      included, and excluded cases. (REQ-3)
- [ ] AC-4: Milestone 2 runs all RFC 2 URI vectors against production parser,
      canonicalizer, and resolver code rather than a fixture-only model, and
      mutation controls reject every stable failure class. (REQ-5, REQ-6)
- [ ] AC-5: Equivalent CLI and MCP reads compile to the same canonical local
      resolution request and return the same target key, immutable replay URI,
      source provenance, identity standing, admission, and trust result.
      Read-only URI resolution produces no filesystem or credential mutation.
      (REQ-5, REQ-6, REQ-13)
- [ ] AC-6: A clean checkout of the hosted-server repository builds one
      container, deploys to a disposable Railway environment from documented
      configuration, persists an authenticated scope, and resolves a public
      `kan://<authority>/<locator>/...` claim, subject, and identity after
      restart. (REQ-7, REQ-8)
- [ ] AC-7: Local and hosted conformance tests issue the same logical claim,
      subject, and identity requests and agree on typed values and failure
      classes while disclosing their different sources and snapshots.
      Credentials appear only on ingest or administration calls. (REQ-8)
- [ ] AC-8: Threat-model tests prove the hosted resolver can index only scopes
      for which it has explicit access, while an L1 encrypted-backup object is
      neither indexed nor accepted as URI-resolvable evidence. (REQ-9)
- [ ] AC-9: The hosted service core runs outside Railway, exports language-
      neutral API fixtures, and is consumed by a clean-room client without
      importing deployment code. The later AppView suite reuses those fixtures
      for common resource and provenance semantics. (REQ-10)
- [ ] AC-10: Milestone 4 completes RFC 3's dependency graph #235–#241 and the
      reachable-error cleanup in #243, with codec and AppView behavior covering
      both preserved legacy claims and the modern identity-era claim shape
      without rewriting either. (REQ-11)
- [ ] AC-11: One end-to-end qualification resolves the same governed resource
      locally, through the kan-native hosted authority, and through ATProto;
      each route returns an equivalent target key and separated provenance,
      admission, and trust evidence. (REQ-1, REQ-10, REQ-11)
- [ ] AC-12: Before each milestone release, its issue audit reports every
      assigned correctness/security issue as fixed, verified stale, absorbed,
      or explicitly deferred, and the release gate fails on an unclassified
      assigned issue. (REQ-12, REQ-15)
- [ ] AC-13: Surface conformance and migration checks fail when a new stored
      value lacks a catalog row, when a derived value becomes authoritative,
      or when a hosted/local cache disagrees with recomputation from raw
      evidence. (REQ-13)
- [ ] AC-14: Two issue briefs exist for a GUI explorer and a TUI navigator.
      Each consumes canonical kan URIs and the typed local/hosted API, displays
      identity/admission/trust separately, and declares storage and protocol
      semantics out of scope. (REQ-14)
- [ ] AC-15: The roadmap gate emits the milestone order and issue allocation
      below, and rejects completion if a later product milestone ships while a
      required predecessor gate is absent. (REQ-1, REQ-15)

## Architecture

### Shipped baseline and correction to the current roadmap

The local append-only spine, GitTree publication, durable restore, compact
read manifest, and explicit persistence boundary are shipped. The relevant
implementation seams are `src/claim.rs`, `src/sign.rs`, `src/workspace.rs`,
`src/store/log.rs`, `src/fold/`, `src/transport/mod.rs`, `src/cli/mod.rs`, and
`src/mcp.rs`. `tests/surface_conformance.rs` guards the rule that raw authority
and derived projections remain distinct.

The current `docs/ROADMAP.md` jumps directly from that baseline to RFC 3. That
is no longer the intended product order. RFC 1 and RFC 2 are accepted but not
implemented: RFC 1 explicitly says the current identity is only its
compatibility source, while RFC 2 currently has production-quality fixture
evidence under `tests/fixtures/uri-v1/` but no runtime parser or resolver
module. This roadmap inserts those two missing product layers and a kan-native
hosted layer before ATProto.

### Milestone 1 — identity becomes real

This milestone is staged so compatibility is built before cutover:

1. **Identity kernel and vectors.** Implement RFC 1 control-event envelopes,
   canonical bytes, identifiers, proof verification, and resolvers without
   changing current writes. The oracle is a checked identity-v1 manifest with
   positive and negative cases, not current Rust object layout.
2. **System and repository identity.** Add explicit system identity state,
   repository inception, and deliberate initialization. Changes around
   `src/sign.rs` and `src/workspace.rs` must route through the persistence
   boundary rather than creating an unclassified identity store.
3. **Governance and admission.** Extend the fold from current author/trust
   selection to RFC 1 identity standing, governance, capability attenuation,
   revocation, and repository admission while retaining authentic excluded or
   unadmitted evidence.
4. **Modern authorship and migration.** Replace new `AuthorId.agent` writes
   with principal plus verification method and identity version. Legacy
   authorship remains readable and signed bytes never change. Only after the
   migration matrix and recovery paths pass do modern writes become default.

Issue #30 is design-complete because RFC 1 now governs it; it should be
reconciled into implementation children rather than treated as an unanswered
architecture question. Identity-adjacent issues #90, #173, #177, #188, #190,
and #205 belong in this milestone's audit because they concern initialization,
key continuity, released-workspace evidence, documentation, or recovery.

### Milestone 2 — the local application becomes URI-native

The existing CLI and MCP server remain the application surface. This milestone
does not create a GUI, TUI, or second fold. Instead, it gives all reads one
internal route:

```text
CLI shorthand or MCP request
    → RFC 2 ResolutionRequest
    → canonical kan://local/... URI
    → selected immutable local/Git snapshot
    → RFC 1 identity and admission evaluation
    → consumer trust evaluation
    → typed result plus immutable replay URI
```

Existing read verbs stay useful human shorthand. They must delegate to the
same resolver used by explicit URI and MCP-resource reads, so a subject string
and its equivalent local URI cannot drift into different products. The URI
path is read-only by construction; signing identity and transport credentials
enter only separate write or administration operations.

Issues #197, #198, #199, and #210 are natural local-app work: repository
identity across worktrees, human CID rendering, readable output, and navigable
citation relationships. Issues #72, #117, and #186 affect evaluation or
visibility and require explicit classification rather than being silently
folded into URI syntax. Issue #194 is a tooling fix that may travel with this
milestone when path resolution is touched.

### Milestone 3 — a kan-native hosted authority

Create a public server repository with a deployment-neutral service core and a
Railway-ready container. It is a hosted kan resolver and store, not an ATProto
PDS and not the opaque L1 backup server.

The read API should be recognizably parallel to RFC 3's future AppView:

- resolve one claim by stable target;
- resolve subject evidence with pagination bound to one snapshot;
- resolve scope, authority, scoped-principal, and freestanding-principal
  identity;
- disclose source, snapshot, completeness, canonical request, immutable replay
  URI, identity standing, admission, and trust; and
- return stable typed failures without falling forward to newer state.

The write plane is separate: authenticate, create or connect a governed scope,
ingest append-only evidence, and administer access. A bearer token, session,
or capability may authorize those calls, but never appears in a kan URI. A
self-hosted deployment can therefore expose
`kan://whatever.com/kan-tools:kan/...` while preserving the RFC 2 distinction
between a mutable authority-local locator and the stable repository identifier
it resolves.

The earlier `.design/hosted-relay.md` remains valid for L1 encrypted backup:
its server must not understand claims, subjects, CIDs, or MSTs. This milestone
is the higher, permissioned hosted-resolver rung whose product purpose is “my
kan claims live in the cloud.” They may share deployment infrastructure but
not threat-model claims or API contracts.

Issues #92, #158, #164, #212, #221, #226, and the hosted part of #29 need
reclassification against this milestone. A new hosted-server epic is warranted
instead of overloading #29, which now specifically tracks RFC 3.

### Milestone 4 — ATProto becomes an interoperability substrate

Only after the local and hosted URI contracts run end to end does RFC 3 become
the active implementation graph:

1. #235 extracts the domain-independent ATProto wire boundary from the modern
   local claim model while retaining legacy decoding.
2. #236 and #237 establish public Lexicons, codec/lens registers, DNS, and
   DID authority.
3. #238 and #239 implement atomic publication and a portable AppView that
   shares the hosted resolver's resource/provenance model.
4. #240 and #241 deploy, recover, qualify, and monitor the production route.
5. #243 removes or makes reachable the currently stray partial-lens error when
   the real AppView API fixes its exact error inventory.

This order changes ATProto from “the next architecture” into a transport and
ecosystem binding for an architecture already exercised locally and over a
kan-native network boundary.

### Rolling maintenance and issue allocation

The open tracker is larger than the product spine. It should be carried in
bounded lanes rather than converted into one stabilization season:

| Lane | Issues | Disposition |
|---|---|---|
| Identity release gate | #30, #90, #173, #177, #188, #190, #205 | implement, verify stale, or absorb into Milestone 1 |
| Local URI application | #72, #117, #186, #194, #197, #198, #199, #210 | classify against resolver/evaluation boundaries; fix only milestone-coupled work |
| Hosted kan service | #29, #92, #158, #164, #212, #221, #226 | re-home hosted-native scope without weakening append-only or blind-backup contracts |
| ATProto | #209, #220, #235–#243 | execute in Milestone 4; retain upstream and release-security work |
| Performance | #25, #151, #165 | measure continuously; promote when a milestone regresses the declared scaling shape |
| Deferred product/research | #15, #64, #75, #174 | keep explicit; do not make foundational semantics depend on them |

### GUI and TUI issue briefs

The design skill does not create GitHub issues. These are the two briefs to
create in the tracker after this roadmap is accepted:

1. **GUI: URI-native kan explorer.** A desktop/web client that opens canonical
   kan URIs, navigates claim/citation/subject graphs, compares local and hosted
   snapshots, and shows cryptographic validity, identity standing, admission,
   and trust separately. It consumes the typed local/hosted API and owns no
   storage, fold, identity, governance, or protocol semantics.
2. **TUI: terminal kan URI navigator.** A keyboard-first client over the same
   URI and API contracts, optimized for subject browsing, provenance drilldown,
   immutable replay, and switching declared trust views. It is not a config
   authority, daemon, alternate database, or second CLI vocabulary.

These interfaces become cheap and coherent only after Milestone 2 provides one
URI-native local contract and Milestone 3 proves the remote form.

## Resolved Questions

- **Product order:** Identity first, then the URI-native local application,
  then the kan-native hosted server, then ATProto interoperability.
- **Local application boundary:** The existing CLI and MCP surface is the local
  application; no GUI or TUI is required to complete the local URI milestone.
- **Hosted product boundary:** The hosted server understands authorized kan
  claims and resolves kan URIs. It is distinct from server-blind encrypted
  backup and precedes ATProto.
- **Identity rollout:** Build RFC 1 behind compatibility, prove released-
  workspace migration and recovery, then switch new workspaces and writes.
- **Future interfaces:** GUI and TUI are desirable later clients of the shared
  URI/API contract, not new semantic surfaces.
- **Maintenance policy:** Carry a bounded correctness/security allowance in
  each milestone instead of pausing the product roadmap for the entire backlog.

## Open Questions

None at roadmap scope. Authentication, tenancy, server repository naming,
hosted write protocol, deployment recovery, GUI toolkit, and TUI toolkit belong
to milestone-specific design passes before their respective builds.

## Out of Scope

- Implementing RFC 1, RFC 2, the hosted server, RFC 3, GUI, or TUI in this
  roadmap-writing change.
- Choosing the hosted server's language, framework, database, tenancy model,
  billing model, or production identity provider.
- Replacing the L1 encrypted-backup threat model with a readable service.
- Encoding credentials, acting authority, write capability, or default trust
  into kan URIs.
- Closing open GitHub issues solely because this roadmap assigns them; each
  issue still requires current-state verification or completed evidence.
- Making the vector index, generic relation enrichment, configuration TUI, or
  incremental fold a prerequisite for the identity/URI/hosted/ATProto spine.
