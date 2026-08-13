# ADR 0070: L1 encryption: whole-CAR per workspace, padded, on a fixed cadence

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-70

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

**Decision:** `.design/e2ee-hosted-relay.md`, resolving the fork ADR-55
deferred to the #7 pass. The L1 encrypted backup stores **one opaque object per
workspace**, replaced whole on each push, **padded to a size bucket**, pushed
on a **fixed cadence** regardless of activity.

**Three of #7's four questions were already answered**, by passes that ran for
other reasons — which is most of what made this tractable. The separate derived
encryption key: ADR-55 decided it, ADR-65 built it. Whether the relay sees
plaintext: rung-dependent, and ADR-54 already records L1-blind versus
L2-reading as a genuine fork rather than one server in two modes. The key
primitive: HPKE to per-space-epoch keys, named by ADR-55. Only the structure
question was open.

**Segments were considered and rejected on privacy grounds.** Append-only
encrypted segments would have bought incremental transfer at most of
whole-CAR's opacity, but an ordered list of segment sizes and arrival times is
a *time series of how much was written and when*. Not a residual worth
accepting to save bandwidth on a 4 MB payload, for users whose metadata is
itself sensitive.

**Whole-CAR alone is only blind-looking, and this is the part that would have
been missed.** A server recording each push's size can difference consecutive
sizes and recover very nearly the series segments would have handed it
outright. **Padding to buckets** is what makes it genuinely blind, and it is
affordable for the same reason whole-CAR was: kan's logs are small, and
rounding one object costs one rounding where rounding every segment would
dominate small deltas.

**Fixed cadence is free here, and only here.** Because every push replaces the
whole padded object, a decoy push is byte-indistinguishable from a real one, so
pushing on a schedule closes the timing channel at no cost beyond bandwidth
already committed. Segments could not have done this — a decoy segment is empty
and obvious. The strongest property in the design is a *consequence* of the
choice made for other reasons.

**Per workspace, not per account, and this was forced rather than chosen.** One
account-wide object would hide the project count, and does not survive a real
setup: one account is routinely used from several machines with **different
projects checked out**, so machine-scoped pushes overwrite each other. The only
repair — every machine fetching, decrypting, merging and re-uploading the whole
account — makes every machine transiently hold every project's plaintext
(undoing deliberate scoped checkout) and turns concurrent pushes into lost
updates. Differing checkouts mandate per-workspace scope.

**So project count leaks, and kan says so rather than hiding it behind a
promise it cannot keep.** Per-workspace credentials would make an account's
projects unlinkable, and kan *supports* that — but does not claim it, because
the unlinkability is defeated by things kan does not control: same IP, same
push cadence (the timing fix actively works *against* it: N accounts pushing on
the same tick from one address is louder than the count), and billing.
Promising unlinkability a server defeats with two queries is worse than a
disclosed leak, because it changes what someone would risk storing there.

**The doc carries a "what this does not protect against" list** as prominently
as the "what the server learns" one — network origin, compromised endpoint,
retroactive revocation, and a hostile operator withholding data. A design read
by people deciding what to trust it with owes them the second list as plainly
as the first, and this is the same standard the doc applies to itself when it
says a server-blind claim that has not enumerated its leakage is marketing.

**Consequences:** nothing in the local format changes — `log/repo.car` stays
what v0.8/v0.9 made it, and the migration matrix's nine green cells stay
meaningful. Restore is `kan restore` with a different source, feeding the same
`Log::ingest` primitive (ADR-59/ADR-63). The server retains the last N pushes
per workspace so a corrupt upload is not a destroyed backup. Bucket sizing is
the one open question, deliberately left to Milestone 4 to settle against a
measured growth curve rather than a guess.
