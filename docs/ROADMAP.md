# Current roadmap

This file is the short, current map of kan's shipped baseline and active
cross-repository work. It does not replace the authority of `docs/SPEC.md` or
an accepted RFC. Historical milestone designs and reconstructed ADRs explain
how kan arrived here; they are not a substitute for this current ordering.

## Shipped baseline

As of `v0.13.0-beta.1`, the local-first spine is built: signed append-only
claims, the local CAR log, tracked GitTree publication and ingestion, disposable
SQLite and overlay projections, deterministic folds, identity roles, CLI/MCP
reads and writes, durability reporting, and restore.

The read/write boundary is now explicit in `docs/SPEC.md` §10.1 and
`tests/fixtures/read-write-surface.tsv`. `tests/surface_conformance.rs` checks
the catalog against the implementation in both directions, and compiler policy
routes filesystem mutations through typed persistence capabilities. That work
landed in [PR #233](https://github.com/kan-tools/kan/pull/233) and closed
[issue #216](https://github.com/kan-tools/kan/issues/216).

## Active product track: identity first

The active sequence is identity → URI-native local application → kan-native
hosted service → ATProto interoperability. Later milestones may prototype
against an earlier contract, but they do not become authorities for identity,
governed scope, admission, or URI semantics.

| Milestone | Outcome | Governing design |
|---|---|---|
| 1 — Identity | Stable principals, governed scopes, governance, delegated admission, and four separately reported read judgments | [RFC 1](../rfcs/1-identity-system.md) |
| 2 — Local URI application | Existing CLI and MCP reads compile to one RFC 2 resolution request and canonical `kan://local/...` URI | [RFC 2](../rfcs/2-kan-uri-scheme.md) |
| 3 — Hosted kan | A Railway-deployable kan-native authority resolves the same typed resources while keeping authenticated ingest separate | [identity-first roadmap](../.design/identity-first-uri-native-roadmap.md) |
| 4 — ATProto | RFC 3 codecs, publication, and AppView adapt the proven identity and URI model | [RFC 3](../rfcs/3-authoritative-lexicon-publication.md) |

Milestone 1 began in commit `4ad239a`. The implemented first slice is deliberately
compatibility-only: `src/identity.rs` defines RFC 1's cryptographic validity,
identity standing, scope admission, and view-trust results; applies the
ordered admission table; and evaluates preserved legacy claims without changing
their bytes or the default writer. `src/identity/control.rs` adds the common
domain-separated control-event producer model, canonical proof ordering,
logical/proved event identifiers, static P-256 `did:key` proof checking, and a
lossless canonical decoder that retains and discloses unsupported fields. The
first `did:kan` genesis slice validates controller, verification-method,
purpose, and service ordering; derives the base32-lower SHA-256 multihash DID
from canonical unsigned payload bytes; pins one deterministic identifier
vector; and requires a valid listed recovery-controller proof. The complete
normative vector manifest remains a gate before this becomes a persistence or
write surface. `src/identity/did_kan_state.rs` now projects genesis into a full
identity state and applies the closed administration-operation semantics in
listed order. `src/identity/did_kan_update.rs` now fixes the typed serde
representation tracked by [#244](https://github.com/kan-tools/kan/issues/244),
makes absent-target removals invalid, pins canonical update bytes and a logical
CID, and resolves signed administration/recovery evidence without observation
order. Current authorship and write cutover remain pending.
In parallel, the scope-inception slice now validates and canonically orders
the unsigned payload, derives an exact 34-byte SHA-256 multihash `ScopeId`
with canonical base32lower display, pins a deterministic vector, and
requires a valid static P-256 `did:key` proof from a listed governance root.
It can now also bind scope inception to the exact active state and
`capabilityDelegation` method of the enrolled system `did:kan` principal;
method, state, algorithm, purpose, and signature substitution all fail closed.
Workspace-local scope persistence now retains the canonical inception event
immutably under `.kan/scope`, with a stable inception
nonce, serialized first installation, atomic visibility, idempotent proof
variants, and fail-closed conflict and symlink handling. Reads create nothing.
The explicit root `kan init` command now composes that store with the selected
system profile and public identity ledger: it resolves the profile's exact
active `did:kan` event and `capabilityDelegation` method, signs inception with
that credential, defaults the immutable discovery name to the Git directory,
and records kan's Git-genesis digest as a `gitGenesis` substrate anchor. A
plain retry reads the installed identity without consulting credentials;
explicit identical options remain idempotent, while changed inception options
are refused. Missing or stale actors and unsupported ledger envelopes fail
before scope inception is installed, and this path never creates or
consults the legacy workspace signing identity.
`src/identity/authorship.rs` now implements the non-ambiguous current
authorship boundary: the exact typed `Author { principal,
verificationMethod, identityVersion }` map is canonically encoded and pinned,
cannot represent a role or legacy agent, and verifies domain-separated claim
bytes only against the cited active `did:kan` event and resolved assertion
method. System profiles now construct a closed current `Claim` only after its
actor reference exactly matches the content author and sign the canonical
`{ codec: "kan-claim-v2", claim: CID }` input through the same provider/key
gate used for control events. `assertion` validity remains independent from
`capabilityInvocation` scope reach.

The first claim-v2 codec slice is also implemented. Current domain types are
unversioned under `claim`, released historical types are isolated under
`claim::v1`, and the common codec boundary distinguishes supported current,
supported v1, preserved future, and invalid records. It pins the v2 signing
input, rejects codec/content-arm contradictions and non-canonical DAG-CBOR,
preserves an unknown codec plus unknown arm byte-exactly, and retains v1's
raw-CID signature rule. Mixed-codec storage now keeps v1 and current records
in the same `tools.kan.claim` collection without rewriting historical blocks.
A typed mixed reader makes supported-current, supported-v1, and preserved
unsupported records an explicit branch. `ClaimView` now preserves those three
source shapes, keeps v1 and scoped-current subjects distinct, and carries all
four RFC 1 judgments without fabricating compatibility claims. The production
fold still sees only v1 until it consumes that view. A parallel disposable
SQLite projection now caches canonical mixed-codec envelopes and source
provenance, never judgments; cache reads reverify the envelope under an
explicit identity-resolution context. General reads dispatch from each
claim's typed author, verify static identities intrinsically, and select
`did:kan` state by both principal and exact event; unresolved identity-version
arms fail closed. The released v1 table and APIs remain
unchanged for cross-version coexistence. Mixed fold primitives now group
source-preserving views, retain future-codec records, merge same-as classes,
and implement the RFC 1 asymmetric migration rule: a matching current
principal may retract its v1 DID history, while v1 can never retract current
claims. Historical local paths enter a current scope only through an explicit
verified-scope projection input. Production render/state consumers still need
to move from the released v1 `FoldedView` to this mixed view. The mixed status
reducer is now available: it preserves exact v1/current author keys, computes
latest-per-author positions, honors citations across the codec boundary, and
produces the same settled/confirmed/contested display lattice. The mixed fold
also exposes subject lookup and per-subject trust-exclusion disclosure with
the released fold's semantics. Production renderers still need to consume
it. Current append is gated by an opaque `VerifiedScope` token that can only
be constructed by rechecking the stored inception proof
against its exact controller state, and the claim's cryptographic scope must
match that token. The production workspace now selects this writer policy at
the shared append choke point: empty workspaces refuse with the explicit
identity-init then scope-init sequence, released workspaces retain v1, and a
verified scope selects the resolved system actor, typed current content, and
independent repository transport signer. Existing repository history adopts
its exact released owner into the transport-only store without changing the
repository DID. Supported narrative, subject, status, relation, correction,
role-naming, citation, and Git-artifact intents compile without a stringly
intermediate, and successful current appends refresh the mixed cache. URI-
dependent publication and legacy anchor/unknown intents remain explicit
unsupported compiler arms. Production read/render consumers and specialized
correction/publication actions still need the mixed cutover. The production
read substrate now resolves every public `did:kan` ledger outcome without a
profile or credential lookup, opens mixed logs without asking the v1 decoder
to reinterpret current records, and constructs a source-preserving local
projection with verified scope admission and exact author trust. The released
renderers still consume the v1-only compatibility projection; adapting their
human/JSON output to `ClaimView` is the remaining read-surface cutover. The
underlying signing seams are now deliberately separate: a closed resolved
system-actor value keeps the kan author profile, exact identity state, method,
and credential provider together, while an explicit repository-transport
signer approves ATProto commits without acquiring kan authorship or scope
authority. Existing reachable commits must retain one transport DID.
The local side now has a typed durable home for that second principal:
`.kan/transport/identity` is an owner-only, create-new transport credential
whose wrapper exposes only an ATProto repository signer. It cannot be passed
as a kan author, read access creates nothing, and concurrent first writers
converge without overwriting a winner. Production current-claim wiring can now
resolve the kan actor and repository transport actor independently.
Workspace write-policy classification is now also explicit and read-only:
absence is `Uninitialized`, verified historical evidence is `V1`, a scope
whose inception proof verifies against the supplied exact actor state is
`Claim`, and partial, pre-release, inaccessible, or contradictory evidence is
`Incomplete`. Partial scope state never falls back to the v1 writer, and a
verified scope wins over retained v1 history. An explicit resolvable
`KAN_IDENTITY_FILE` on an otherwise empty scope-less workspace remains a v1
compatibility selection; implicit first-write identity creation stays
forbidden. The remaining cutover boundary is the production read/render
surface and the specialized correction/publication actions.
`src/identity/governance.rs` now produces canonical update and reconciliation
events and resolves unordered evidence deterministically: proof variants share
one logical event, sibling leaves are contested, reconciliation requires
authorization at every parent, and missing history remains distinct from
invalid or unsupported evidence. `src/identity/capability.rs` now adds validated
capability values, canonical delegation and revocation producers, static P-256
`did:key` authorization, strict single-parent attenuation, current-root and
governance-ancestry checks, and deterministic path evaluation across scope,
trusted-time, and ancestor-revocation boundaries. Its evidence resolver now
collapses proof variants, recognizes parents before children regardless of
observation order, authenticates revocations against recognized targets, and
keeps missing, unsupported, and invalid evidence distinct while retaining
additive envelope fields through the lossless control boundary.
`src/identity/ledger.rs` begins durable integration with a read-only-on-open,
immutable local control-event ledger: canonical bytes
are atomically installed under proved-event CIDs, proof variants coexist, and
temporary crash residue is never evidence.
`src/identity/system.rs` now supplies the profile portion: versioned local
profiles bind a path-safe alias and principal DID to one typed credential
provider reference, while deliberate first initialization atomically installs
the profile and selects its alias as the default actor. Reads never create
state or access credentials, identical initialization is idempotent, and
conflicting or concurrent initialization cannot silently switch actors.
Static `did:key` control proofs now support both RFC 1 algorithms: P-256 and
strict Ed25519, including canonical multikey and signature checks. Profiles
now select an exact `(principal, verification method, controller state)` actor,
and explicit owner-only-file or OS-keychain execution signs only after the
loaded P-256 key matches the resolved method; path escape, loose permissions,
symlinks, and key substitution fail closed. Hardware, agent, and external-
signer execution remain pending. The daily-device enrollment plan now creates
a proved `did:kan` genesis and the mandatory first administration event, binds
the daily method to all non-recovery v1 purposes, verifies separately declared
recovery and daily credentials, installs both events, and selects the default
profile last under one initialization lock. Competing setups publish only the
selected history, and any credential or ledger failure leaves no selectable
actor. `kan identity init` now performs that enrollment without opening a
repository: it resolves the platform configuration root (or `--config-dir`),
creates or explicitly imports owner-only recovery and daily P-256 credentials
without overwrite, persists the enrollment nonce so a crash/retry cannot mint
a different principal, and reports only public identifiers and credential
paths. Invalid aliases, insecure imports, conflicting keys, and a different
existing default fail closed; an identical retry is idempotent. OS-keychain
creation and hardware, agent, and external-signer execution remain, followed
by repository-connection configuration and current-authorship/default-write
cutover.

## Later public-protocol track: RFC 3

[RFC 3](../rfcs/3-authoritative-lexicon-publication.md) specifies authoritative
`tools.kan.*` Lexicon publication, immutable codec/lens bindings, and a portable
version-aware AppView. Its formal status is **Review** through
2026-08-20T00:50:11Z. The implementation issues below are the scoped roadmap;
they do not change the RFC's status or permit production publication before
the RFC process and acceptance gates are complete.

The tracking epic is [#29](https://github.com/kan-tools/kan/issues/29):

| Order | Workstream | Depends on |
|---|---|---|
| 1a | [#235 — `kan-atproto` wire boundary and claim-envelope migration](https://github.com/kan-tools/kan/issues/235) | shipped baseline |
| 1b | [#237 — `_lexicon.kan.tools` and `did:web:kan.tools` authority](https://github.com/kan-tools/kan/issues/237) | may proceed in parallel with #235 |
| 2 | [#236 — versioned Lexicons and append-only codec/lens registers](https://github.com/kan-tools/kan/issues/236) | #235 |
| 3a | [#238 — release-verified atomic publisher](https://github.com/kan-tools/kan/issues/238) | #236, #237 |
| 3b | [#239 — portable reference AppView](https://github.com/kan-tools/kan/issues/239) | #235, #236 |
| 4 | [#240 — Railway deployment and independent recovery](https://github.com/kan-tools/kan/issues/240) | #237, #238, #239 |
| 5 | [#241 — end-to-end release qualification and drift probes](https://github.com/kan-tools/kan/issues/241) | #235–#240 |

The issue dependency graph remains valid, but execution begins only after the
identity, local-URI, and hosted-kan milestones prove the model it will carry.
Production is not complete until #241 verifies the public route from DNS and
DID resolution through authoritative PDS records and normalized AppView
responses, including recovery and provenance evidence.

## Repository-family ownership

- `kan` owns RFCs, canonical claim codecs, normative lens semantics, and the
  `kan-atproto` wire boundary.
- public `kan-tools/kan-lexicon` owns Lexicon source, generated clients,
  immutable releases, and language-neutral fixtures.
- public `kan-tools/kan-appview` owns portable reference AppView code and its
  container artifact.
- private `kan-tools/kan-infra` owns Railway configuration, credentials,
  monitoring, deployment pins, and recovery procedures.

## Separate and deferred tracks

HostedRelay, its product/access model, firehose ingest, and additional AppView
selection policy are not silently folded into RFC 3. A permissioned hosted-kan
resolver is likewise distinct from HostedRelay's opaque encrypted backup. The
older `.design/sync-layer-architecture-and-staging.md` and ADR-35 remain useful
history for HostedRelay sequencing, but their `dev.kan.*`, `did:plc`, version,
and public-ATProto assumptions are superseded for RFC 3 by the RFC and the
issue graph above. Identity implementation and issue #30 now belong to the
active first milestone.

## Which document wins

1. `docs/SPEC.md` defines shipped kan semantics and invariants.
2. Accepted RFCs define public protocol and governance commitments; a Review
   RFC is a proposal until its review period completes and its status changes.
3. `.design/*.md` files specify bounded implementation work or preserve
   historical design context.
4. GitHub issues track execution and dependencies; they do not override the
   SPEC or RFC status.
