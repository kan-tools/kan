# ADR 79: Retire the v0.10 reservation; number by content

- Status: Accepted (supersedes the reservation in ADR-35, reaffirmed in ADR-72)
- Date: 2026-08-01
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-79

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
**Status:** Accepted (supersedes the reservation in ADR-35, reaffirmed in ADR-72)

**Context.** ADR-35 reserved `v0.10` for the HostedRelay milestone, and ADR-72
defended it — v0.9.1's branch was misnamed `v0.10-bulk-read`, and releasing it
as a minor would have taken that number for something that was not that
milestone.

The reservation has since been overtaken by the design work it was reserving
for. ADR-73 moved L1's wire to object PUT/GET and deferred the wire protocol
to M5, which **made M4 smaller**; ADR-74 replaced the publicness ladder with
media entirely. The thing "v0.10 = HostedRelay" named no longer exists in that
shape, and is now plausibly several releases rather than one.

**Decision.** Retire the reservation. Releases are numbered by what they
contain, under the patch/minor test ADR-53 and ADR-72 already apply. HostedRelay
lands on whatever numbers its staging actually needs.

**Why not keep it and re-scope.** Re-scoping requires re-deriving HostedRelay's
staging post-ADR-73/74 before the next cut — a design pass standing between a
blocked consumer (#116) and a release. Holding shipping work behind a numbering
question is the wrong trade, and the numbering question is the smaller one.

**Why not stay in 0.9.x until then.** That was the alternative, and it fails on
its own terms: #116 adds `RelationKind` variants and the identity surface
changes when workspaces come into existence. Shipping those as patches would
make "patch" stop meaning what ADR-72 said it means, which costs more than a
version number does.

**Consequences.** A reserved-but-unclaimed version number is a promise about
work not yet designed, and this is the second time it has had to be defended
rather than used. kan does not reserve version numbers again; the roadmap says
what is next, and the version says what shipped.
