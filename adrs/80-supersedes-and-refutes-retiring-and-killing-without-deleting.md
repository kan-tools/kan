# ADR 80: `Supersedes` and `Refutes`: retiring and killing, without deleting

- Status: Accepted
- Date: 2026-08-01
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-80

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
**Status:** Accepted

**Context.** #116, from the same research loop that produced #60. Two edges
were being carried as naming conventions and `about` links, and both are
load-bearing enough that queryability matters.

**Decision.** Two directed `RelationKind` variants, read as projections in
`fold::relations`.

**`Supersedes`** — this subject replaces that one, which is retained. The
distinctions carry the weight: a `Retraction` says the claim was *wrong* and
removes it from the fold, supersession says it was right and has been
outgrown; `SameAs` would merge the two subjects and destroy the history
supersession exists to keep. Read forward by `live_members`.

**`Refutes`** — a substantive, citable result that kills a claim. Distinct
from `Rejects`, which is trust-local suppression that changes only what the
rejecting reader sees. Refutation is public and additive: the refuted subject
stays fully visible and the refutation stands beside it. That is why it is a
domain relation and not a fold control.

**Asserted subject-to-subject, though #116 describes `refutes` as
claim-to-claim.** `Relation` targets a `SubjectRef`. Rather than widen that for
one kind, the specific claim refuted is named the way this codebase already
names evidence — the refuting claim `cites` it. Same split ADR-46 made for
`InTensionWith`: the edge carries the assertion, `cites` carries the what and
the why. One shape for every relation beats two.

**`live_members` returns a frontier, not a tip.** A subject superseded by two
different subjects has genuinely forked, and answering with one would be the
fold resolving what the claims leave open. It is also **cycle-safe**, which is
not defensive programming: `a supersedes b supersedes a` is expressible, and
non-destruction means neither assertion can ever be removed, so the walk has to
survive a state the store cannot be cleaned of.

**The additive contract is now measured, not asserted.** ADR-44 promised that
an older binary meets an unknown variant gracefully. Checked against released
v0.9.1 reading a log containing both new kinds: it does not crash, and renders
`Unknown { kind: "Relation", raw: [...] }` — bytes preserved, semantics
honestly absent. Minor rather than patch, because that degradation *is* a
semantic loss for an older reader even though nothing breaks.

**Consequences.** The refuted register becomes a fold-time view instead of a
hand-kept file, which is the point: it cannot drift from the claims it is
derived from. `kan show` renders `superseded — live now:` and `refuted by:`,
because a projection no consumer can reach from the CLI is one that gets kept
by hand anyway.
