# ADR 0081: `show --all` is all-or-nothing, and a subject cannot leave the log

- Status: Accepted (states a contract ADR-71 left implicit)
- Date: 2026-08-01
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-81

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

**Date:** 2026-08-01
**Status:** Accepted (states a contract ADR-71 left implicit)

**Context.** #143, from the day side. Having adopted `kan show --all --json`
(ADR-71), day needs to know what happens when a subject cannot be read: a
whole-invocation failure, a silent omission, or something else. The three
answers require very different consumer behaviour, and under the per-subject
reads day used to make, silent omission was impossible — a failed `show` was
an error naming its subject.

**Decision, and it is a guarantee rather than a description: `--all` is
all-or-nothing.** If the read fails, the invocation fails. A subject is never
silently absent from `subjects[]`.

**The reason is structural, not diligence.** `show_all_json` performs exactly
one read — `ws.index.all_stored_claims()?` — and then maps over the folded
merge classes. There is no per-subject operation that could fail for one
subject and succeed for the others, so the only reachable outcomes are a
complete answer or a propagated error. A future change that introduced
per-subject reads would break this, which is why it is pinned by a test
(`tests/bulk_read.rs::show_all_never_omits_a_subject_that_status_reports`) rather
than left as a property of the current shape.

**The second guarantee day's mitigation rests on, also now stated: a subject
cannot become absent by retraction.** A subject exists by virtue of having
claims, and retracting the last one appends a `Retraction`, which is itself a
claim on that subject. Non-destruction (`CLAUDE.md`'s one non-negotiable
invariant) is what makes this true rather than incidental. Pinned by
`retracting_a_subjects_only_claim_does_not_remove_the_subject`.

**Consequences.** day can delete its unaccounted-for cross-check, which
compared `status --json`'s subject set against `show --all`'s and reported the
difference as partial. The check was correct and cost nothing, but it existed
to cover an outcome that cannot occur. A consumer defending against an
impossible case is a consumer that has been told too little.
