# ADR 46: `InTensionWith`: asserted directed, read as a projection

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-46

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

**Date:** 2026-07-21
**Context:** Tension between subjects is the central relation in `day`'s
telos model — several teloi normally apply to one project at once and pull
against each other, and that tension is information rather than a defect.
It had no representation: day recorded it as a `decide` claim citing both
subjects, which is attributable but not queryable (#60).
**Decision:** a sixth domain `RelationKind`, `InTensionWith`, **asserted
directed and read symmetric**. Tension is symmetric in *meaning* — if A
pulls against B then B pulls against A — while the *grounds* are
perspectival, because two actors can hold the same pair in tension for
different reasons. So the assertion keeps its direction in the store and
symmetry is applied on read (`fold::relations::in_tension_with`). Collapsing
at write time would discard which side observed what, which is exactly the
raw data a frames-aware reader needs.
**No degree field and no reason field**, both deliberately. The reason is
the claim the edge `cites` — `cites` is already the witness layer on every
claim, and a `reason` field would duplicate it while making one
`RelationKind` structurally unlike the other five. A degree, once anything
needs one, is *derived* by composing over those witnesses under a chosen
enriching base, exactly as §4.3 derives identity confidence. A stored degree
would assert a fold output as input and foreclose every other base — the
same category error as writing a status instead of letting the fold compute
one.
**The general rule, now stated:** `docs/SPEC.md` §4.5.1 — relation claims
are stored exactly as asserted and any symmetric, transitive, or weighted
reading is a projection computed on demand. `telos/raw-data-and-projections`
in this repo's own log (published to `.claims/`) states the principle
generally: raw attested data retained in full, every simplification a
determined projection parameterised by a viewer-chosen base, and therefore
swappable.
**What it surfaced (#72):** §4.3 already specifies identity as an enriched,
witness-retaining object with trust as the enriching base — and the other
five relation kinds get bare booleans. That asymmetry is the anomaly.
Enriched domain relations are therefore not an architectural shift but the
**completion of a pattern the spec already commits to**. Deferred because
nothing consumes domain edges today (the fold reads `SameAs` and `Status`
only), and day's frames work is the likely first real consumer — the
witnesses are already being recorded, so enrichment can be added over them
later without re-recording anything.
