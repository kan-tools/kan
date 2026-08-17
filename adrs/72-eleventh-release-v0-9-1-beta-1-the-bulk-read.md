# ADR 72: Eleventh release: v0.9.1-beta.1, the bulk read

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-72

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

**What it is:** a point release carrying `kan show --all --json` (#123,
ADR-71) and the L1 encryption design (ADR-70, docs only).

**Why patch, not minor.** Nothing touches the on-disk format, `SCHEMA_VERSION`
is unchanged, and the change is additive in both directions: an older consumer
ignores the new envelope, and a newer one asking for `--all` against an older
binary gets clap's rejection rather than a silently narrow answer. The same
reasoning ADR-53 applied to v0.7.1.

There is also a naming reason to be explicit about it. The branch was called
`v0.10-bulk-read`, which was wrong: **v0.10 is reserved for the HostedRelay
milestone** (ADR-35). Releasing this as a minor would have taken that number
for something that is not that milestone and left the roadmap's own numbering
lying about what shipped.

**Why now rather than batched.** `day` has been paying 1.99s of its 2.76s
`day status` inside 41 kan invocations, and the fix is on `main` but not
installable. Holding a release whose entire value is to a consumer already
paying the cost is the wrong trade — kan's own dependency being the reason to
ship is the same coupling ADR-42 recorded when `day` first shelled out.

**Consequences:** closes the last item on `.design/kan-read-contract.md`. day
can upgrade and collapse its whole-log read to one invocation.
