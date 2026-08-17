# ADR 85: The index's schema version lives in its table name

- Status: Accepted
- Date: 2026-08-04
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-85

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

**Date:** 2026-08-04
**Status:** Accepted

**Decision:** the disposable SQLite projection's table is named for its schema
version (`claims_v2`), with `built_from_root_v2` beside it. An older kan's
`claims` table is left exactly where it is.

**Reproduced against a released binary before choosing it.** Giving the
projection an `origin` column while keeping the table called `claims` makes
v0.9.2 die on its next write with `NOT NULL constraint failed: claims.origin`
— `CREATE TABLE IF NOT EXISTS` leaves the newer table in place and the older
binary's `INSERT` names no `origin`. A *disposable cache* made every command
fail: the store intact and unreachable, which is #150's shape.

**Not an exotic configuration.** `day` shells out to the installed `kan`
(ADR-42) while a checkout runs its own, so a repo under active development
sees both binaries against one `.kan/` routinely — including this one.

**The freshness key is versioned for the same reason as the table.** A shared
`built_from_root` would have each binary concluding that a projection the
*other* built was up to date, so each would read the other's shape — quieter
than the crash, and worse.

**Rejected:** a `DEFAULT 'log'` on the column. It keeps the old binary running
while silently marking its overlay rows as log-origin, putting overlay authors
into `TrustBase::Local` — the exact boundary ADR-83 draws. A compatibility
shim that breaks the invariant the change is about is not compatibility.

**Consequences.** A stale table per superseded version, which is disk in a
file that can be deleted at any time; cleaning them up would reintroduce the
breakage. Since the index is disposable there is no migration to write, and
the `origin` value is spelled for the *medium* (`log`, `git-tree`) rather than
for the store it lands in, so #164's per-medium work does not rename it.
