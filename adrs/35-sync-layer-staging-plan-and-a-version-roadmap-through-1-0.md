# ADR 35: Sync layer staging plan, and a version roadmap through 1.0

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-35

## Context

Not recorded contemporaneously.

## Decision

Not recorded contemporaneously.

## Rationale

Not recorded contemporaneously.

## Consequences

Not recorded contemporaneously.

## Evidence

Not recorded contemporaneously.

## Alternatives considered

Not recorded contemporaneously.

## Supersession

Not recorded contemporaneously.

## Historical record

**Date:** 2026-07-20
**Decision:** `.design/sync-layer-architecture-and-staging.md` replaces
issue #29's placeholder epic with a concrete milestone sequence, now mapped
onto actual versions:
- **v0.4.0-beta.1**: unrelated small cleanup kept as its own release, not
  folded into the sync epic — #41 (`ClaimBody::Result` reachability), #26
  (`Workspace::open` full-rescan perf), and a subject-naming fuzzy-match
  nudge (validated by real beta-tester feedback, issue #47).
- **v0.5.0-beta.1**: Milestone 0 — formalize `docs/SPEC.md` §10's
  `Transport` trait, `LocalOnly` as its explicit first implementation.
  Pure additive refactor.
- *(no version)*: Milestone 1 — issue #7's E2EE `/design` pass. Design-only
  output (a `.design/*.md` doc), feeds Milestone 3's implementation
  directly rather than shipping its own release.
- **v0.6.0-beta.1**: Milestone 2 — issue #30, real per-agent cryptographic
  identity. Deliberately shipped *before* `HostedRelay`, as an independent
  parallel track — see the design doc's own sequencing rationale (the
  cross-human trust story is already cryptographically real via `did:key`/
  ADR-4; per-agent sub-identity matters more once multiple agents share a
  network-exposed relay).
- **v0.7.0-beta.1**: *(superseded — see ADR-48)* the **correctness
  release**. Not on this roadmap when it was written, because the defects
  it fixes were not known: three adversarial reviews of v0.6.0-beta.1 found
  ~20, about half destroying data. Everything below shifts one place.
- **v0.8.0-beta.1**: Milestone 2 — thread `Transport` through `Workspace`
  so a published tree is actually *read*, plus the `PeerContested` trust
  surface that makes another actor's claims visible at all. This is what
  makes kan genuinely multi-actor rather than merely capable of it.
- **v0.9.0-beta.1**: Milestone 3 — issue #30, real per-agent cryptographic
  identity. Deliberately shipped *before* `HostedRelay`, as an independent
  parallel track (the cross-human trust story is already cryptographically
  real via `did:key`/ADR-4; per-agent sub-identity matters more once
  multiple agents share a network-exposed relay). `KAN_AGENT` is not a
  prerequisite here — ADR-48 removed it rather than repairing something
  already scheduled for replacement.
- **v0.10.0-beta.1**: Milestone 4 — `HostedRelay` design + build, informed
  by Milestone 1's E2EE resolution.
- **v1.0.0**: a stability declaration, not new scope — local-only spine +
  `HostedRelay` + real identity + E2EE, with nothing left provisional (no
  more `KAN_AGENT`-style honest-but-temporary patches, no more mid-flight
  `ClaimBody`/`RelationKind` reshapes expected). Declared once that line
  is genuinely stable, not tied to a calendar date.
- **v1.x/v2**: Milestone 4 — `AtProto`/PDS/firehose transport. Deliberately
  *not* a 1.0 blocker.
**Why AtProto stays post-1.0:** `docs/SPEC.md` §10 frames the three
transports asymmetrically — `HostedRelay` is "private teams... **the
monetizable one**," `AtProto` is "public ecosystem; lexicons =
**evangelism**." `docs/HANDOFF.md` already calls the local-only spine "the
actual product." Reading those together: 1.0 is reasonably declared once
the core product (local-only + private-team sync, both hardened, real
identity, real encryption) is stable — the public-ecosystem/federation
story is expansion on a stable base, not a precondition for calling the
base stable. Requiring the entire original vision (including `AtProto`'s
external wire-protocol surface, confirmed during the sync design pass to
be entirely unbuilt — `atproto-repo`/`atproto-dasl` provide MST/CAR/CBOR
repository structure only, no PDS/XRPC/firehose client exists anywhere in
kan's dependency tree) before 1.0 would tie the stability declaration to
the single largest, least-derisked remaining piece of work, for no
product reason tied to what "stable" actually needs to mean here.
**Consequences:** `.design/sync-layer-architecture-and-staging.md`'s
staging table updated with this version mapping, so the design doc and
this ADR stay in sync as the single source of truth rather than the
roadmap living only in chat. Issue #29 gets a comment recording the
resolved plan, replacing its own "not a commitment, just what was
originally sketched" framing. v0.4 development starts next, via its own
`/design` pass.
