# ADR 39: Fourth release: v0.4.0-beta.1

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-39

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
**Decision:** `Cargo.toml`'s version bumps `0.3.0-beta.1` → `0.4.0-beta.1`
— a minor bump (new backward-compatible functionality: `kan result`,
`Workspace::open`'s index staleness check, the subject-naming nudge —
PRs #51–#53), staying a semver pre-release rather than promoting to
stable `0.4.0`, same reasoning as ADR-28/ADR-34. Follows the same branch →
PR → merge → tag workflow as the prior three releases.
**Why beta again, not stable:** confirmed (not assumed) data compatibility
with `v0.3.0-beta.1`: `src/claim.rs` has zero diff across this whole
milestone (`kan result` uses `ClaimBody::Result`, already present since
before v0.1's first release) — no claim-log/CAR format change at all.
`store::index::Index`'s SQLite schema gained a `meta` table, but the index
is explicitly a disposable projection, never a second source of truth
(`docs/SPEC.md` §10) — `CREATE TABLE IF NOT EXISTS` means an existing
`v0.3` `index.sqlite` file opens cleanly under `v0.4` code with no
migration, and even in the worst case (a mismatch on the very first
post-upgrade `Workspace::open`) the fallback is just one ordinary full
rebuild, exactly what every `Workspace::open` unconditionally did before
this release. The project itself still isn't stable: issue #30 (real
per-agent identity) remains open, and now issue #29's staged sync epic
(`.design/sync-layer-architecture-and-staging.md`, ADR-35) is the
explicit, versioned path to whatever "stable" ends up meaning for kan —
v1.0.0 is anchored to that plan (through Milestone 3 / v0.7.0-beta.1) now,
not left as a vague someday.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging (64 files, 615.0KiB) before tagging. Issues #41/#26/#47 closed
with comments pointing at the merging PRs, matching the v0.2/v0.3 pattern
— #47 in particular gets a direct reply to the original beta-tester
feedback, including an explicit note that the structured-data point
raised there is a real, unresolved, bigger question deliberately not
addressed by this release.
