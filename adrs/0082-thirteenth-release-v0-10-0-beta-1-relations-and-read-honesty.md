# ADR 0082: Thirteenth release: v0.10.0-beta.1, relations and read honesty

- Status: Accepted
- Date: 2026-08-01
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-82

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

**What it is:** `RelationKind::{Supersedes, Refutes}` with their fold
projections (#116, ADR-80), and three read-surface corrections — #144
(subject names that cannot have been meant), #141 (a repo with no commits),
#143 (the `--all` contract, ADR-81).

**Why minor.** #116 adds variants an older binary cannot interpret. Measured
rather than assumed: released v0.9.1 reading a log containing both renders
`Unknown { kind: "Relation", raw: [...] }` — no crash, bytes preserved,
semantics honestly absent. Nothing breaks, but an older reader loses meaning,
and that is what separates a minor from a patch.

**And this is the first release numbered under ADR-79**, which retired ADR-35's
reservation of `v0.10` for HostedRelay. The reservation was overtaken by the
design work it was reserving for: ADR-73 made M4 smaller, ADR-74 replaced the
ladder with media. Numbering by content is what let a blocked consumer ship
without a design pass standing in front of it.

**A pattern across the three fixes worth naming.** #144 and #141 were both kan
doing the work first and discovering the problem after, so the failure arrived
behind side effects that implied success — a claim recorded under an
impossible name, an identity minted before a git precondition was checked.
Both are now refused before anything is written. That is the same correction
ADR-77 made for the identity guard, which suggests the class is *ordering*:
kan has repeatedly validated after acting rather than before.

**Consequences.** day can delete its unaccounted-for cross-check (ADR-81) and
gains a `v0.10.0-beta.1` row in `kan-compat.tsv`. The research loop's
supersession chains and refuted register become fold-time views instead of
hand-kept files.
