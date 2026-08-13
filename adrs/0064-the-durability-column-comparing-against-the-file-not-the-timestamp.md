# ADR 0064: The durability column: comparing against the file, not the timestamp

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-64

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

**Date:** 2026-07-30
**Status:** Accepted

**Decision:** `.design/v0.9-milestone.md` REQ-3
(`.design/durability-log-recovery.md` REQ-5). `kan status` reports a
per-subject durability state — `unpublished`, `published`, `stale` — inline on
the rendered line and as a `durability` field in `--json`. It answers, for each
subject: if `.kan/` disappeared right now, what would come back?

**Computed against the published *file*, not against the `Publication`
claim's timestamp.** This is the decision worth recording, because the obvious
implementation is wrong in a way that would have shipped. `kan publish --all`
refreshes a subject's file **without** appending a new `Publication` claim, so
a staleness check comparing the newest live claim's `rev` against the
publication's would keep reporting a gap the operator had *just closed*.
Nothing teaches someone to ignore a column faster than it being wrong right
after they act on it. The comparison is therefore claim-for-claim against the
set of CIDs actually present in the tree, which is also the literal question
durability asks.

**It costs no additional I/O.** `Workspace::open` already reads every record in
`.claims/` for ADR-59's ingest pass; the set is now recorded there, before the
author test, into `Workspace::published`. Durability asks "is this claim in the
tree", which is a question about the tree and not about who signed it — so
recording it before the author filter is correct rather than merely convenient.

**Over the view's claims, not one author's.** With several role identities in a
workspace, every one of their claims lives in the same `.kan/log` and every one
is lost together. So a claim absent from the tree makes its subject stale
whoever signed it. A class merged by `SameAs` counts a claim as durable if the
tree holds it under *any* of the class's names, since that is enough to restore
it.

**Shown for all three states, including the healthy one.** A column that
appears only when something is wrong is a nag; the point of REQ-5 is to make
the gap legible as *data*. Inline rather than a second line per subject,
because `kan status` with no argument lists every subject and doubling that
output is how a column becomes something people stop reading. The `--json`
field is likewise emitted always — a field that appears only on bad news cannot
be told apart from an older kan that never reports it.

**Consequences:** `durability` is additive, so `SCHEMA_VERSION` stays `1`
under ADR-60's rule, and `tests/json_contract.rs` pins it. Inverting the
staleness check fails exactly the three tests that depend on detecting it,
while the two that do not — an all-unpublished repo, and the post-restore
round trip — correctly still pass.

**The column's promise is checked against the actual restore**, not against its
own bookkeeping: after `rm -rf .kan` and `kan restore`, everything that comes
back reads as `published` and the unpublished subject is simply gone. That test
is what makes `published` mean *restorable* rather than *recorded as
published*.
