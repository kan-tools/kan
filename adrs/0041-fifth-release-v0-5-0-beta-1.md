# ADR 0041: Fifth release: v0.5.0-beta.1

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-41

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
**Decision:** `Cargo.toml`'s version bumps `0.4.0-beta.1` → `0.5.0-beta.1` —
a minor bump (new backward-compatible functionality: `src/transport.rs`'s
`Transport` trait + `LocalOnly`, PR #56, ADR-40), staying a semver
pre-release rather than promoting to stable `0.5.0`, same reasoning as
ADR-28/34/39. Follows the same branch → PR → merge → tag workflow as the
prior four releases.
**Why beta again, not stable:** this milestone touches nothing about the
on-disk claim log or index format — `Transport`/`LocalOnly` is a new,
additive seam in front of the already-shipped `Log::append`/`iter_all`, not
a change to `src/claim.rs`, the CAR/MST format, or `store::index::Index`'s
schema, so a `v0.4.0-beta.1` `.kan/` directory opens cleanly under `v0.5`
code with zero migration. The project itself still isn't stable: issue #30
(real per-agent identity, staged as Milestone 2 in
`.design/sync-layer-architecture-and-staging.md`) remains open, and this
release only closes Milestone 0 of ADR-35's sync roadmap — Milestones 1
(E2EE design, issue #7), 2 (identity, v0.6.0-beta.1), and 3 (`HostedRelay`,
v0.7.0-beta.1) remain before v1.0.0 is anchored.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging before tagging.
