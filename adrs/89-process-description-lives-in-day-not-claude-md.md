# ADR 89: Process description lives in `day`, not `CLAUDE.md`

- Status: Accepted
- Date: 2026-08-06
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-89

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

**Date:** 2026-08-06
**Status:** Accepted

**Decision:** `CLAUDE.md` describes kan the artifact. How work proceeds —
designing, building, reviewing, opening a PR, cutting a release — is declared
as `day` process atoms, which are `atom/*` claims in kan's own log and are
injected into every session by day's hook.

**The duplication was real and was this project's own defect class.**
`atom/pull-request` already described the one-PR-per-milestone workflow, and
`CLAUDE.md` described it again in its own words; `atom/release` and
`CLAUDE.md` both described the release ritual. Two implementations of one
fact, with no shared definition — which is precisely what
`.design/identity-resolution.md` Consequence 3 says about identity
resolution's two resolvers, and those drifted in a different direction every
review round.

Atoms are also *checkable* in a way prose is not: `day doctor` verifies the
vocabulary composes and `day status` reports where work sits. Moving the
sections revealed that `atom/adversarial-review` and `atom/generative-build`
declared each other as `next`, forming a cycle day could not order — it had
been warning about this at every session start. `next` is forward-only; the
edge that sends you back is `revisits`. `day doctor` now reports
`composition: ok` for the first time.

**What stays in `CLAUDE.md`:** the fold invariant, the crate-trust rule, the
spine, the CLI vocabulary, the kan/`day` scope boundary, the smell test — all
statements about the artifact. 170 lines → 115.

---
