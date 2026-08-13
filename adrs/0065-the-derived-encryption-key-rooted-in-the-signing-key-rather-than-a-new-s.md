# ADR 0065: The derived encryption key, rooted in the signing key rather than a new seed

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-65

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

**Decision:** `.design/v0.9-milestone.md` REQ-5 (ADR-55's Q2). Every identity
now has an X25519 encryption key, derived through HKDF-SHA256 from the
identity's own root material under the label `kan/v1/encrypt`, exposed as
`kan identity encryption-key`. Nothing encrypts anything yet: the key exists so
ADR-54's L1 encrypted backup and #7's HPKE protocol have a recipient to
address.

**Derived, never converted.** The Ed25519→X25519 footgun is reusing one key's
*scalar* on two curves. Running the root through a KDF under a distinct label
avoids it by construction — the encryption key is a one-way function of the
root rather than a re-encoding of the signing key, so compromising it yields
nothing about the signing key.

**The root is the existing signing key material, not a newly-escrowed seed —
and that is a change from how the milestone doc described this.** ADR-55's
migration says existing identities become `{grandfathered signing key + new
seed}`, which reads as two secrets. Taking it literally would mean every
existing workspace has a *second* thing to write down, and an operator holding
only the 24 words they were told to keep would find their encrypted backup
unrecoverable. Deriving from the signing key material instead means **the
existing recovery phrase already reproduces the encryption key**, so this
deploys to every workspace that exists today with no migration and no new
escrow. `.design/durability-log-recovery.md` IREQ-2's "one escrowed secret
reproduces the identity" now covers both slots rather than one.

**What that costs, stated rather than buried:** the signing key dominates the
encryption key — whoever holds the former can derive the latter. That is the
same *shape* as the seed-rooted scheme (a root that dominates both slots) with
the signing key playing the root's part for identities that predate the seed.
It is strictly weaker than independent escrow and strictly stronger than the
status quo, which had no encryption key at all. For new identities the
seed-as-root form ADR-55 describes is still the target, and it lands with the
new-identity path (REQ-6's grandfathering PR) — where the choice between
"derive everything from a seed" and "grandfather this key" is actually made.

**Scope, honestly:** this PR delivers REQ-5 and the derivation machinery REQ-4
needs. REQ-4's *file-resident seed as root* is only meaningful where a new
identity is being created, so it belongs with the migration work rather than
here. Splitting it this way keeps the one genuinely dangerous change — touching
how a signing key is resolved — isolated in its own PR with its own negative
control, per ADR-52's rule.

**The crates were spiked before being built on** (`tests/key_derivation_spike.rs`),
per CLAUDE.md's rule from ADR-11/12. Three findings worth keeping:

- `x25519-dalek 2.0.1` shares the `curve25519-dalek 4.1.3` already in the tree
  via `ed25519-dalek`; version 3 pulls a **second** copy (v5). Sharing chosen.
- `hkdf 0.12` was already present transitively through `elliptic-curve`, so
  promoting it to a direct dependency costs nothing compiled.
- The real hazard — deriving a **P-256** scalar from arbitrary bytes, which
  must lie in `[1, n-1]` — is **detectable**: `P256Keypair::import` rejects
  zero and over-order scalars rather than coercing them. That is what makes a
  retry-based derivation safe for the new-identity path, and it is exactly the
  kind of "documented vs actual" question ADR-11 was about. `StaticSecret::from`
  clamps internally, so kan does no bit-twiddling of its own.
