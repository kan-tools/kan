# ADR 0053: Eighth release: v0.7.1-beta.1

- Status: Accepted
- Date: 2026-07-23
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-53

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

**Date:** 2026-07-23
**Status:** Accepted

**What it is:** the point release v0.7.0-beta.1's four unreviewed commits were
building toward, cleared by two further adversarial reviews (ADR-52 and the
third-round deletion-guard audit). Contents:

- **Wave 1 ergonomics** — the subject argument accepted both positionally and
  as `--subject` on every write verb (ending the failed-command/lost-write
  class two independent sessions hit); `kan --version`; the recovery phrase
  read from stdin instead of argv (a private key was reaching shell history
  and `ps` output); and removal of a lingering, unencrypted plaintext key copy
  on the keychain-hit path.
- **The `.claims/` migration path** (#107) so existing repos upgrade without
  orphaned, diverging files — and the REDIRECT fixes that made it safe
  (ADR-52): retirement and the keychain deletion guard both stopped keying
  destructive operations on lossy derived values.

**Why patch, not minor:** unlike v0.7.0, nothing here breaks the on-disk
format. `ClaimContent`, the CID computation, and the GitTree record format are
all unchanged; a v0.7.0 log and a v0.7.1 log are byte-identical in shape. The
change is ergonomics, one security fix, and migration handling — additive and
compatible in both directions with v0.7.0. This is the first non-minor release
(ADR-19's scheme allowed it; nothing had qualified until now).

**Why it matters operationally:** this is the release the *other* repos
upgrade to. It carries the phrase-off-argv security fix and the `.claims/`
migration handling, without which an upgrading repo leaks a key on restore and
accumulates duplicate published files. v0.7.0 should be treated as
superseded for any repo that publishes.

**The review chain that produced it, recorded because it is the point:**
v0.7.0 shipped ahead of a re-review (ADR-51) under schedule pressure. That
re-review (ADR-52) returned REDIRECT and found the migration fix reintroduced
the very class it fixed. Its fixes got their *own* review, which returned
APPROVE. Three rounds, each finding real defects in the prior round's fixes
until the last — which is the empirical case for ADR-49's rule that a round of
fixes to a BLOCK/REDIRECT is reviewed before it is trusted, not presumed
correct. Two non-blocking follow-ups remain filed (#111, #112).
