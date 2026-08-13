# ADR 0051: Seventh release: v0.7.0-beta.1, the correctness release

- Status: Accepted
- Date: 2026-07-22
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-51

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

**Date:** 2026-07-22
**Status:** Accepted

**What it is:** the release ADR-48 describes and ADR-49 corrects — roughly
twenty defects found by three adversarial reviews of v0.6.0-beta.1, about half
destroying data, plus nine more found by a fourth review of the release
candidate itself. 32 commits, 105 → 173 tests.

**Why beta again, not stable:** the format broke twice on purpose.
`ClaimContent` gained `recorded_at`, `KnownBody` gained
`deny_unknown_fields`, and the GitTree record format went to v2. The
coexistence rule (`docs/SPEC.md` §7.1) makes those survivable in one
direction only, and the asymmetry is worth stating precisely:

- **v0.7 reads a v0.6 log.** Verified against this repo's own: 14 subjects, 61
  `spine` claims, zero errors, and appending to that legacy log works.
  Pre-v0.7 claims keep their exact CIDs, because `recorded_at` is `Option`
  with `skip_serializing_if`.
- **v0.6 cannot read a v0.7 log**, and says so: *"this kan is older than the
  log it is reading… the log is not damaged."* That is the contract working,
  not a defect — but it means upgrading is one-way in practice, which is a
  beta property, not a stable one.

**Shipped ahead of a re-review, deliberately, and this is the honest part.**
The recommendation after ADR-49 was to re-run the adversarial review against
the fixes, on the reasoning that the last review found its worst defects in
the *previous* round's fixes. That recommendation stands and is not
withdrawn. It was overridden for a concrete cost: `day`'s CI is blocked, and
`day` cannot migrate off parsing kan's prose (day#42) until the `--json`
surface exists in a *published* version. Every BLOCK finding is fixed and
verified against the reviewer's own reproductions; what is being skipped is
prudence about the fixes, not a known defect.

**The re-review is therefore owed before v0.8**, and before anyone who is not
the author depends on this. Recorded here rather than left as an intention,
because "we'll re-check it later" is the shape of promise this whole release
exists to stop making.

**Also in this release, and not in the milestone doc:** ADR-50's structured
output. It was not planned; it exists because v0.7's own read-surface
improvements silently broke `day`, which revealed that kan's prose had been a
de-facto API all along. A release whose theme is unexamined guarantees
finding one more on its way out is fitting, if not comfortable.
