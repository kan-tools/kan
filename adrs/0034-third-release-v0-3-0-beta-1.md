# ADR 0034: Third release: v0.3.0-beta.1

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-34

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
**Decision:** `Cargo.toml`'s version bumps `0.2.0-beta.1` → `0.3.0-beta.1` —
a minor bump (new backward-compatible functionality: the relation surface
and `Rejects` reshape, `Subject`/`SubjectKind` construction plus the
`issues` correctness fix, `--status` generalization, the four-phase verb
reorg, and `GitAncestry` caching — PRs #42–#46), staying a semver
pre-release rather than promoting to stable `0.3.0`, same reasoning as
ADR-28. Follows the same branch → PR → merge → tag workflow as the prior
two releases (ADR-19, ADR-28's PR #40).
**Why beta again, not stable:** confirmed (not assumed) data compatibility
with `v0.2.0-beta.1`: `RelationKind` losing its unused `Rejects` variant and
`ClaimBody`/`ClaimKind` gaining a new `Rejects` variant are both safe for
existing logs — `serde`'s default derive (no `#[serde(tag = ...)]` or
custom impl on any of these three enums) uses externally-tagged-by-name
representation, not ordinal-index, so removing/adding a variant doesn't
shift any other variant's encoding; and ADR-29 already confirmed (via `git
log -S 'RelationKind::Rejects'`, re-confirmed by this release's own
independent audit) that no shipped CLI/MCP path ever constructed the
now-removed variant, so no real log references it. The project itself
still isn't stable, though: issue #30 (real per-agent cryptographic
identity, deliberately kept out of v0.3's scope per
`.design/v0.3-milestone.md`'s Out of Scope section) remains open, and
`docs/SPEC.md`'s v1 scope fence still isn't fully closed. A pre-release
version keeps signaling that honestly.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging (61 files, 551.7KiB) before tagging. This release also follows an
independent adversarial post-implementation audit of the full v0.3 diff
(method adapted from `forecast-bio/crosslink`'s `architect` skill, dispatched
as a fresh subagent per issue #48) — verdict APPROVE, all 13 REQs/13 ACs
independently re-verified against code rather than trusting the ADRs' own
claims, full build/test/clippy/fmt gate re-run clean. That audit is a
one-off technique this release, not yet a repeatable skill in this repo
(tracked as future companion-tool work, issue #48).
