# ADR 0001: Repo/MST/CID/signing crate family: `atrium-rs`, not `atproto-repo`

- Status: Not recorded contemporaneously
- Date: 2026-07-15
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-1

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

**Date:** 2026-07-15
**Decision:** Use the `atrium-rs` family (`atrium-repo`, `atrium-crypto`,
`atrium-identity`, …) rather than Nick Gerakines' `atproto-repo` family, which
`docs/HANDOFF.md` had originally pointed at.
**Why:** `atrium-rs` is org-maintained, 420★/49 forks/204 releases, actively
developed, and backs `bsky-sdk` — the community-standard choice. `atproto-repo`
is single-maintainer, 32★, and tagged `0.15.0-alpha.2` on main. Bus-factor and
community vetting outweigh `atproto-repo`'s numerically higher crates.io
version for something this foundational.
**Caveat (resolved):** `atrium-repo` itself is the youngest crate in either
family (v0.1.8) — its fit for from-scratch local MST/CAR construction (vs.
reading an existing hosted repo) was unverified at the time of this ADR. See
ADR-8, which confirms the fit by reading the actual source.
