# ADR 86: v0.11.0-beta.1: the identity surface

- Status: Accepted
- Date: 2026-08-05
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-86

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

**Date:** 2026-08-05
**Status:** Accepted

**Decision:** cut v0.11.0-beta.1. `.design/identity-surface.md`'s ten
requirements ship; ADR-83, ADR-84 and ADR-85 record the substantive ones.

**Minor, not patch, and measured rather than assumed.** New CLI surface
(`--trust local|roles|role:<name>`, `kan identity authors`), a new `--json`
value (`trust.base: "Local"`), and changed default read semantics. Nothing
touches the on-disk claim format: `SCHEMA_VERSION` is unchanged, no field is
added or removed, and a v0.10 log opens and reads unchanged. Still beta
because the v1 scope fence has not closed.

**AC-1 was the gate, and it held.** A golden fixture of a single-author
workspace's `show`/`status`/`issues`/`context` output — human and `--json` —
was generated against the **pre-change binary**, committed on its own PR
before any behaviour changed, and has passed unmodified through every commit
since. That is what makes `Local` a behavioural change rather than a break.
Confirmed on real data too: this repo's own 30 subjects and 281 live claims
read byte-identically under v0.9.2 and v0.11.

**Reads got 2.7x faster and writes got faster too.** 42.0 → 15.5 ms per read
against a 2.2 ms bare process spawn — `genesis()`'s three `git` subprocesses
were ~70% of kan's fixed per-invocation cost, computing a value no read
consults. Writes regressed to ~2x mid-milestone and were fixed: an
unconditional #150 overlap check and a duplicated reprojection, measured back
down by interleaving two binaries rather than by a single A/B, which had
given the opposite answer.

**Five cold adversarial reviews, five blocking verdicts, and the loop is the
lesson.** Every blocking finding after the first round was introduced by the
previous round's fix, all in identity resolution.
`docs/POSTMORTEM-v0.11-review-loop.md` is the process write-up and
`.design/identity-resolution.md` the design cause — kan conflates "which
identity does this workspace have", "which should sign this write", and "may
kan create one" into one function, and answers them with side effects. The
reviews were not the expensive part; patching an unspecified space was.

**Known gaps, named rather than discovered:**
- **#170** — the read-side resolver skips the keychain, so `--trust me`
  reports no identity on the default macOS layout (`identity-id`, no key
  file, no seed) while `kan identity did` resolves fine.
- **REQ-6 is delivered at the level of authors, not claims** (ADR-83): a
  `.claims/` file whose author has also written to this log folds into the
  default view. The claim-level property is v0.12's, with #164.
- **`publish --all` produces a visible diff** on its first run after
  upgrading in a multi-role workspace, as files gain the other roles' claims.
  That is REQ-10 working, and it is announced here rather than found in a
  review.

**Next:** v0.12 takes `.design/identity-resolution.md` (opening with the
agent-pattern decision, since it determines whether `KAN_IDENTITY_FILE` is
still load-bearing), #164 retiring `.kan/overlay`, and the origin-aware fold.
