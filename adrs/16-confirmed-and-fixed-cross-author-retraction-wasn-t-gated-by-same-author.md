# ADR 16: CONFIRMED and FIXED: cross-author `Retraction` wasn't gated by same-author (or any trust)

- Status: Found by a dedicated software-review pass (a forked agent instructed
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-16

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
**Status:** Found by a dedicated software-review pass (a forked agent instructed
to audit the whole codebase against `docs/SPEC.md`/`docs/DECISIONS.md`/
`CLAUDE.md`, not a user report), fixed same day.
**Finding:** `fold::identity::excluded_by_retraction` (`src/fold/identity.rs`)
took no `TrustBase` and never checked that a `Retraction`'s author matched the
author of the claim it targeted. Any author's `Retraction` claim — trusted or
not, even a total stranger's — silently excluded *any other author's* claim
from *every* viewer's fold, including a `SoloTrust` viewer who never trusted
the retracting author at all. `docs/SPEC.md` §8 is explicit that this is
supposed to be structurally impossible ("Cross-author 'retraction' is NOT
possible — you can't write to another's log"), not merely trust-gated —
`excluded_by_retraction` is called once, trust-independently, at the top of
`fold::fold`, before either `merge_classes` or the trust filter ever runs, so
there was no later trust check that could have caught this either. Directly
undermines "provenance is sacred" (`CLAUDE.md`).
**Fix:** `excluded_by_retraction` now tracks each seen claim's author and only
lets a `Retraction { supersedes }` take effect — both the initial exclusion
and the "retracting a retraction" undo path (ADR-6) — when the retracting
claim's author exactly matches the target claim's author. An other-author
`Retraction` is simply inert: not an error, not excluded, just never entered
into `excluded`/`active_retraction_target` at all. The function still takes
no `TrustBase` — that absence is now the documented point, not an oversight:
self-retraction is a data-level invariant, unconditionally same-author-only,
completely separate from `Relation::Rejects`'s trust-gated cross-author
suppression.
**Verification:** new regression test
(`tests/identity_fold.rs::cross_author_retraction_is_not_honored_even_when_fully_trusted`)
uses `PeerContested` trusting *both* the owner and the stranger equally,
specifically so the test can't be satisfied by ordinary trust gating alone —
confirmed to fail against the pre-fix code (reverted via `git stash`, re-ran,
watched it fail with the exact predicted symptom) and pass against the fix,
per the same "verify, don't assume" discipline ADR-11/12 established.
