# ADR 0007: Hard-delete: storage-layer only in v1, no CLI verb

- Status: Not recorded contemporaneously
- Date: 2026-07-15
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-7

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
**Decision:** True erasure (no tombstone) stays possible at the storage layer
but v1 exposes no CLI verb for it (e.g. no `kan forget`).
**Why:** Keeps the CLI vocabulary exactly what `docs/HANDOFF.md` lists
(`observe|plan|decide|resolve|same|show|issues|status|session|context`).
Erasure is rare/dangerous enough to defer to a manual/scripted operation until
there's a concrete need.
