# ADR 27: Witness provenance surfaced through the fold; `kan show` gains a `GitSameFile` consumer

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-27

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

**Date:** 2026-07-17
**Decision:** `fold::SubjectView` gains a `witnesses: Vec<identity::SameAsWitness>`
field, populated straight from `identity::MergeClass::witnesses` in
`fold::fold`'s `MergeClass` → `SubjectView` conversion (previously
discarded there, REQ-18). `kan show`'s "merged with" line now also prints
each witness's author, direction, and claim CID (REQ-19/AC-11), not just
the flat merged subject list. Separately, `kan show` now also computes
`relations::compute_default` (REQ-20/AC-12) and, when any of the subject's
claims share a `GitSameFile` edge with a claim belonging to a *different*
merge-class, prints a "related subjects (same file)" line naming that
other class. Since a same-file relation is inherently cross-subject,
`compute_default` runs over every live claim in the fold (not just the one
subject's own claims, unlike `classify_subject`'s narrower usage for
`status`/`issues`) — O(n²) over the whole live claim set on every `kan
show`, the same accepted-cost trade `relations::GitAncestry` already
documents (correctness before performance, `CLAUDE.md`).
**Why:** `docs/SPEC.md` §4.3 is explicit: "the fold must carry its
factorization + witness set... NEVER silently promote a long weak chain to
strict identity" — silently dropping `MergeClass.witnesses` at the exact
point it was already computed correctly was a real violation of that
requirement, not just an unreached feature, since every `kan show` on a
merged subject was already hitting the discard. `GitSameFile` edges were
computed and threaded through `relations::compute_all` since M4b but had
zero consumer anywhere — this closes that gap with the smallest real
surfacing (a read-only line), not a new ranking or scoring mechanism.
**Consequences:** `tests/cli.rs` gained `show_on_a_merged_subject_names_a_witness`
(AC-11) and `show_lists_a_subject_sharing_a_file_anchor_as_related`
(AC-12, using the `--file` flag PR2/ADR-22 added to construct two
same-file-anchored claims under different subjects). No change to
`fold::fold`'s public signature or `TrustBase`/identity semantics — this is
additive data threaded through an existing conversion, not a new
computation.
