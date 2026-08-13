# ADR 78: Twelfth release: v0.9.2-beta.1, the corruption fixes

- Status: Accepted
- Date: 2026-08-01
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-78

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

**What it is:** a point release carrying two data-safety fixes — #146 (the
second-identity guard, ADR-77) and #150 (recovering a workspace whose overlay
was already poisoned) — plus the migration matrix's identity axis.

**Why patch, not minor.** Nothing touches the on-disk format and
`SCHEMA_VERSION` is unchanged. The behaviour changes are all *refusals and
repairs* on paths that previously corrupted or mis-minted: no new claim kind,
no new field, no new CLI surface. The same reasoning ADR-53 applied to v0.7.1
and ADR-72 to v0.9.1.

**And v0.10 stays reserved for the HostedRelay milestone** (ADR-35), which is
the naming trap ADR-72 already had to talk itself out of once. A release that
is not that milestone must not take that number.

**Why now rather than batched.** #150 makes a workspace unopenable — durably,
on a *read*, under the combination the v0.8 role work and the `publish`
boundary object point users toward together. On released v0.9.1 the only ways
out are deleting `.kan/overlay` by hand or running a build that does not exist
on crates.io. A recovery path that is not installable is not a recovery path,
which is a sharper version of ADR-72's "holding a release whose entire value
is to someone already paying the cost."

**Consequences.** Anyone on v0.9.1 who used a role identity in a workspace
that had published its own claims can upgrade and have the workspace repair
itself on the next read, loudly, without touching the log. `day` gains a
`v0.9.2-beta.1 ok` row in its `kan-compat.tsv`.

**A ritual change rides with it.** `tests/fixtures/migration-expectations.tsv`
now gains the rows for *the version being cut*, at cut time. v0.9.0 and v0.9.1
had no rows at all, so the matrix failed on the v0.9.1 tag push and stayed red
and unread for two days — the gate worked and nobody was looking. Adding the
rows while already in the file is the difference between a gate and a
formality.
