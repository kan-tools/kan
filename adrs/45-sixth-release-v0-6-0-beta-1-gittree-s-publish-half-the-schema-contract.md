# ADR 45: Sixth release: v0.6.0-beta.1 (GitTree's publish half + the schema contract)

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-45

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

**Date:** 2026-07-21
**Decision:** `Cargo.toml` bumps `0.5.0-beta.1` → `0.6.0-beta.1` — a minor
bump for new backward-compatible functionality (`GitTree`, `kan publish`,
`ClaimBody::Publication`, the schema-evolution contract), staying a semver
pre-release for the same reasons as ADR-28/34/39/41.
**Scope, stated honestly:** this ships **half a transport**.
`GitTree::publish` works and `kan publish` writes a subject's claims into a
tracked `.claims/`. `GitTree::subscribe` exists, compiles, is tested — and
**nothing calls it**. `Workspace` does not know about `Transport` at all, so
a clone's kan will never read a published tree; the fold still sees only the
local log. A repo can therefore *share* claims and cannot yet *consume*
shared ones. Wiring `Transport` through `Workspace` is M2 (v0.7.0-beta.1) in
`.design/sync-layer-architecture-and-staging.md`, and is precisely what M0
deferred until a second implementation existed. Releasing without it is
deliberate, not an oversight, and the release notes say so — ADR-43's claim
that `GitTree` "exercises the multi-actor path" describes the design, not
what is currently wired.
**Why ship now rather than after the wiring:** the schema-evolution contract
(ADR-44) is a **prerequisite for two other issues being safe to land**. #60
(an "in tension with" `RelationKind`) and #67 (a claim's time) are both
schema changes, and until unknown-kind tolerance is released, either one
strands older readers exactly as `Publication` just did. The wiring is
additive and does not get harder by waiting; the contract does, because every
release without it is another version that can be stranded. Delivering the
originating request — claims visible and reviewable in the repo — needs only
the publish half.
**One thing this release cannot fix:** v0.5.0-beta.1 in the wild has no
unknown-kind tolerance, so it cannot read a log containing any claim kind it
does not know. That is unfixable retroactively; v0.6 is the release from
which forward compatibility *starts*. Anyone on v0.5 should upgrade before
being handed a v0.6-written log.
**Consequences:** the staging table's version map shifts — M1.5 is inserted
at v0.6, `Workspace` wiring becomes M2 at v0.7, per-agent identity (#30)
moves to v0.8 behind #69 (keychain friction, which #30 would multiply), and
`HostedRelay` to v0.9. `cargo publish --dry-run` confirmed clean packaging
before tagging.
