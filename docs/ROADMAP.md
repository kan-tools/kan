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
repository scope, admission, or URI semantics.

| Milestone | Outcome | Governing design |
|---|---|---|
| 1 — Identity | Stable principals, repository scopes, governance, delegated admission, and four separately reported read judgments | [RFC 1](../rfcs/1-identity-system.md) |
| 2 — Local URI application | Existing CLI and MCP reads compile to one RFC 2 resolution request and canonical `kan://local/...` URI | [RFC 2](../rfcs/2-kan-uri-scheme.md) |
| 3 — Hosted kan | A Railway-deployable kan-native authority resolves the same typed resources while keeping authenticated ingest separate | [identity-first roadmap](../.design/identity-first-uri-native-roadmap.md) |
| 4 — ATProto | RFC 3 codecs, publication, and AppView adapt the proven identity and URI model | [RFC 3](../rfcs/3-authoritative-lexicon-publication.md) |

Milestone 1 began in commit `4ad239a`. The implemented first slice is deliberately
compatibility-only: `src/identity.rs` defines RFC 1's cryptographic validity,
identity standing, repository admission, and view-trust results; applies the
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
order. Modern authorship and write cutover remain pending.
In parallel, the repository-inception slice now validates and
canonically orders the unsigned payload, derives the full `kan-repo:` SHA-256
multihash identifier, pins a deterministic vector, and
requires a valid static P-256 `did:key` proof from a listed governance root.
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
additive envelope fields through the lossless control boundary. Persistence and
write integration remain pending.

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
