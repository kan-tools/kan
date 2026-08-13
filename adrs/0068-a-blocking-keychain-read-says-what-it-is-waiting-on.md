# ADR 0068: A blocking keychain read says what it is waiting on

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-68

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

**Decision:** #90's fourth ask. A keychain call that has not returned within
1.5s prints one line to stderr naming what it is waiting on, why it happens,
and both escape hatches (`KAN_IDENTITY_FILE`, `KAN_NO_KEYCHAIN`). The hang
itself is unchanged — that is #96/#69, and #30's per-agent identity work is
the real fix. What changes is that it stops being *silent*.

**Why this and not something larger.** #90 named it precisely: "a hang, not a
failure, which is the worst shape — a caller cannot tell it from slowness."
Building v0.9 hit it three times in one day: once dogfooding the durability
column against kan's own repo, twice from tests exercising fresh-workspace
creation without `KAN_IDENTITY_FILE`. Each time the symptom was a command that
never returned and said nothing, and each time it cost minutes of wondering
whether the fold had gone quadratic. `day` shelling out cannot tell the
difference either. Making the hang legible is a fraction of the work of fixing
it and removes most of the confusion.

**The negative control is the half that decides whether it can ship.** A
warning that fired on every keychain read would be noise on the common path,
and noise on the common path is precisely how a warning stops being read —
the same failure mode the durability column (ADR-64, a column that would have
been wrong right after you acted on it) and the migration matrix (a table that
would have scored a working guard as data loss) were each shaped to avoid.
`tests/keychain_visibility.rs` asserts both directions: a slow call warns, a
prompt one is silent.

**Tested through a seam rather than a wedged keychain.** The watchdog is
exercised directly via `SlowKeychainWarning::fired_after`, because a test
needing a genuinely stuck keychain could not run on Linux CI (no keychain at
all) and should not require a developer to arrange one. The seam is the
watchdog, which is the thing under test; the keychain call it wraps is not.

**Consequences:** the thread is detached and sleeps in 50ms increments,
checking a flag the guard sets on drop — so a prompt call leaves nothing
behind and a process exiting early costs nothing. #90's remaining ask (item 3:
do not persist a minted account until it is known-good) is still open, and now
applies to `seed-id` as well as `identity-id`.
