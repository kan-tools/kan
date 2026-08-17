# ADR 74: Media replace the publicness ladder

- Status: Accepted — supersedes ADR-54's ladder
- Date: 2026-07-31
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-74

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

**Date:** 2026-07-31
**Status:** Accepted — supersedes ADR-54's ladder

**Decision:** `.design/medium-architecture.md`. kan's model is a **set of media
with capabilities**, not an ordered ladder of publicness. An identity writes to
one medium — its own log — and replicates to others; what a user sees is
`fold(⋃ readable claim media, trust)`. "Promotion" is sugar over *post to a
medium* plus *aggregate and filter*.

**The ladder was describing a different architecture than the one kan has.**
The README's thesis is "many local truths, glued into a shared picture,
parameterized by whom you trust" — a set with a filter. ADR-54's ladder said
"one truth escalating through ordered publicness", and the two do not agree.
v0.8 had already implemented the set-with-a-filter version without naming it:
`Transport` is a medium connection, `Workspace.log ∪ overlay` is the aggregate,
`TrustBase` is the filter, the fold is the projection.

**What proves the ladder wrong is L1 and GitTree, from opposite directions.**
L1's encrypted backup *discloses to nobody* — putting it between Local and
relay on a publicness ladder asserts it is more public than local, which is
false. And `GitTree`, the shipped transport, has no rung at all: its reach is
whatever the git remote's is, spanning "only me" to "the world, irreversibly",
which kan neither controls nor knows. A ladder indexed by mechanism cannot
express a reach that is not a property of the mechanism.

**What survives:** reach and reversibility, as properties of a medium
*instance*. Reversibility is what ADR-54 was really tracking when it marked
one-way rungs, and it is real — a relay you control is reversible, a public git
remote is not.

**Conflict resolution is not a problem kan has.** The log is a grow-only set of
content-addressed signed claims — retraction is another claim, and
content-addressing makes adds idempotent. That is a G-Set, union is the merge,
and convergence is guaranteed by the data type rather than the protocol. No OT,
no transformation, no ordering, no locks, no consensus, at any layer.

**The rule for background processes falls out of granularity, not direction:**
workspace-granular media (archive, mirror) *require* one, because a whole-store
operation cannot ride on a claim write; claim-granular media *forbid* one,
because `kan publish` being a deliberate act is ADR-43's curation boundary.

**Every hosted service is blind, and that was not the design goal — it fell
out.** The archive holds encrypted whole objects; the replica holds an MST of
encrypted records, learning cardinality and not the citation graph. Plaintext
access becomes a grant to a **named service** (an indexer joins as a member
holding a wrapped epoch key) rather than a property of the substrate.

**Two of atproto's three reasons for choosing access control over encryption do
not apply here**, which is why kan can encrypt where permissioned spaces do
not. Key management is easier because the encryption key is per-*identity* and
derived from one seed (ADR-55/65), so every device derives the same key and
recipients' keys come from their identity. And kan's groups are teams, not the
50k-member case that strains group encryption. The third — backends must read
to index — is handled by the named-member grant above. atproto's design
explicitly permits applications to layer encryption on the permissioning
protocol, so this is compatible rather than divergent.

**Membership is host-authoritative**, matching atproto's Arbiter and for the
same reason: membership held in members' repos is circular, since you need
membership to read the repos that declare it. kan adds that membership
*changes* are recorded as claims for audit — the ACL enforces, the claims say
who added whom, and divergence between them is visible rather than silent.

**Identity across kan and atproto: the repo is a carrier.** Claims stay
authored by `did:key`; the atproto repo holds a complete self-signed claim
exactly as `.claims/` does. Making `did:plc` authoritative would tie provenance
to the carrier, which is the coupling kan exists to avoid — and it would have
required author-level identity merging, a fold change this avoids entirely.

**Consequences:** ADR-54's ladder is superseded; its wire reasoning survives
scoped to media where the server may read. ADR-70's stated reason for rejecting
structure-preserving encryption is corrected in place — it overstated the leak,
and the corrected version is what lets the replica be encrypted. `Layer` stays
in the claim (the kind is what kan knows), the address stays in the mount
manifest (URIs move, signed content does not). The durability column's
publicness vocabulary must be replaced; that is a shipped `--json` field and
therefore a schema change.
