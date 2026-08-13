# ADR 0075: Agents are derived roles; scope lives in the attestation

- Status: Accepted (design); the fold change is its own later pass
- Date: 2026-07-31
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-75

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
**Status:** Accepted (design); the fold change is its own later pass

**Decision:** an agent identity is `HKDF(seed, "kan/v1/agent/" + label)`,
vouched for by a signed claim from the root identity, enrolled as a space
member in its own right. Delegation *scope* — time-bounds, per-subject limits —
is expressed as constraints on the vouching claim and honoured at fold time,
not encoded in keys.

**This rests on a correction.** The design looked blocked because handing an
agent decryption appeared to mean handing it the seed, since ADR-65/66 derive
everything from one root. That is wrong: **HKDF is one-way**. An agent holding
`HKDF(seed, label)` can derive neither the root nor any sibling. The property
that made "one escrowed secret reproduces everything" work is the same property
that makes bounded delegation work, and the apparent conflict was mine.

**Why derived rather than randomly generated.** Determinism means an agent key
is recoverable from the root by label, so nothing needs escrowing per agent —
which is what makes minting one per container, worktree, or task affordable
rather than a provisioning burden.

**Why scope belongs in the claim rather than in keys.** Per-subject scoping at
the crypto layer needs per-subject keys, which defeats the whole-space epoch
model. At the ACL layer it is crude and unauditable. In the attestation it is
signed, retractable, attributable, and composes with the trust base already
built. The cost is that `TrustBase` generalizes from `author -> weight` to
`claim -> weight` — a fold change, which `CLAUDE.md` permits only for a
measured reason. This is one, and it lands as its own pass with its own
negative controls.

**One-step expansion, to avoid a fixpoint.** Vouching claims live inside the
fold whose trust base they modify. Only claims from **explicitly trusted**
authors are honoured, and expansion never recurses: Alice's vouching grants
conditional trust to her agents; her agents' vouching grants nothing. Bounded
and decidable, and consistent with v0.8's rule that transitive trust is never
automatic — `--trust roles` expands a registry rather than inferring a chain.

**Time-bounds are weaker than they look, and are shipped saying so.**
`recorded_at` is signed but self-attested, so a compromised agent can backdate
past its own expiry. Per-subject constraints have no equivalent weakness. The
fix is a **notary** — an attestation that a claim was seen at a time, or
equivalently a replica recording server-observed arrival, which is the same
claim wearing a different name. That is #67, and it stops being a curiosity
here: it is what makes time-bounded delegation enforceable rather than
advisory.

**Consequences for #30.** It narrows to non-extractability — an enclave-held
sub-key an agent cannot exfiltrate — which derivation cannot provide and which
ADR-55 already accepted as residual at the root. The useful half (many
attributable agents, cheap to mint, revocable by membership change) needs **no
fold change** and mostly reuses v0.9's role registry: `kan identity role add`
already mints, registers, and expands under `--trust roles`. The delta is a
derived-key mode and the vouching claim.
