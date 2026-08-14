# ADR 5: Body typing: structural/narrative split, `ClaimKind`+`Body` merged

- Status: Not recorded contemporaneously
- Date: 2026-07-15
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-5

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

**Date:** 2026-07-15
**Decision:** Accepts `docs/SPEC.md` §12.1's recommended default — closed
typed variants for `Subject`/`Status`/`Relation`/`Retraction`; opaque text for
`Observation`/`Plan`/`Decision`/`Result`/`Blocker`. Additionally, `ClaimKind`
and `Body` (two fields in SPEC.md §1's sketch) are merged into a single
`ClaimBody` enum, with kind exposed as a derived method.
**Why:** The fold only needs structured access to the four structural kinds;
narrative kinds are cited-but-not-parsed prose, so typing them would balloon
the fold's surface for no payoff. Merging kind+body into one enum makes an
invalid kind/body pairing unrepresentable in the type system — same
information as SPEC.md's sketch, safer representation.
