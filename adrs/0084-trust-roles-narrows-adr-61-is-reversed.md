# ADR 0084: `--trust roles` narrows; ADR-61 is reversed

- Status: Accepted (reverses ADR-61)
- Date: 2026-08-04
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-84

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
**Status:** Accepted (reverses ADR-61)

**Decision:** `--trust roles` expands to exactly the identities declared in
`.kan/roles`, and no longer injects the active identity. A new `role:<name>`
names one declared role without pasting a `did:key:…`.

**Why the reversal is safe now.** ADR-61 widened `roles` to include the active
identity because omitting it gave the wrong answer to the obvious question —
"show me everything this workspace's own identities wrote" would quietly drop
the caller's own claims. Under ADR-83 the *default* answers that question, so
`roles` is free to mean what its name says without being a trap.

**What it buys.** `local` minus `roles` becomes the set of authors present in
this log but never declared — the #90/#136 anomaly as data rather than as an
absence — and is reachable as `kan identity authors`. The concrete behaviour
change: an identity nobody declared, reading `--trust roles`, no longer
silently counts itself as a role.

**Noted while testing, because it corrects a stated premise:** `kan identity
role add` registers the *primary* too, under the name `primary`. An existing
test asserted `roles` included the active identity and explained that the
primary "is not itself a declared role", which was never true. The
auto-declaration is what carries ADR-61's concern going forward.
