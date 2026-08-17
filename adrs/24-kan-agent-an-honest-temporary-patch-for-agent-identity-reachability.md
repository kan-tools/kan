# ADR 24: `KAN_AGENT`: an honest, temporary patch for agent-identity reachability

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-24

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

**Date:** 2026-07-17
**Decision:** `Workspace::my_author()` now reads the `KAN_AGENT` environment
variable; if set, `AuthorId.agent` becomes `Some(sha256(KAN_AGENT))` instead
of always `None`. This is explicitly a placeholder — `derive_agent_key`'s
doc comment says so directly — not a real per-agent keypair: `sign::verify`
is unchanged and still checks only the human's DID-embedded signature, never
anything derived from `KAN_AGENT`. This repo's own `.mcp.json` sets
`"env": {"KAN_AGENT": "claude-code"}` on the bundled server entry, so MCP
usage gets a sensible default agent tag with zero configuration (standard
MCP server `env` config, no kan-specific protocol). `Workspace::solo_trust`
now reads as narrower than it looks: it trusts exactly *this process's*
`AuthorId` (did + current `KAN_AGENT`, if any), so a `KAN_AGENT`-tagged
write is only visible back to a read made in that same `KAN_AGENT` context
— unchanged default behavior when `KAN_AGENT` is unset (still just the
human identity), but new behavior once it's in play.
**Why:** Before this, `AuthorId.agent` was never `Some(...)` anywhere
outside hand-constructed library tests — real signed claims never carried a
distinct agent identity, so `TrustBase::PeerContested` (fully built and
tested, `fold::trust`'s own doc comment) had nothing genuine to
distinguish. A real per-agent-keypair design (separate signing keys,
signature verification against an agent-embedded pubkey) is real,
non-trivial design work of its own — plausibly its own problem domain
outside kan entirely, worth checking existing workload-identity-style
standards against before inventing one from scratch. Shipping a hash-based
placeholder now, honestly labeled as such, closes the *reachability* gap
(agents can be told apart at all) without pretending to close the
*security* gap (nothing stops an agent from claiming any name) — the
dishonest alternative would be silently treating `derive_agent_key`'s
output as if it were a real key, which `claim::AgentKey`'s own doc comment
("compressed public key bytes of the signing agent") would then be lying
about for real claims, not just aspirationally for as-yet-unused ones.
**Consequences:** Filed as its own explicitly-not-v0.2 follow-up issue: the
real per-agent cryptographic identity design (see `.design/v0.2-milestone.md`
Out of Scope). AC-8 is proven end-to-end in `tests/kan_agent.rs`: two real
`kan observe` subprocess invocations under different `KAN_AGENT` values
produce two distinct, real signed `AuthorId`s (not hand-typed structs), and
a `PeerContested` `TrustBase` built from those real values can tell them
apart, while a `Solo` trust of just the untagged identity stays exactly as
narrow as before this patch.
