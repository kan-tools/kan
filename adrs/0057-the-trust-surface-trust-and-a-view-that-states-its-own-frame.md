# ADR 0057: The trust surface: `--trust`, and a view that states its own frame

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-57

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

**Decision:** `.design/v0.8-milestone.md` REQ-3. `TrustBase::PeerContested` —
built and tested since M4a, reachable from no surface — is now selected
per-read by a repeatable `--trust AUTHOR[=WEIGHT]` argument on `show`,
`status`, `issues`, and `context`, on both the CLI and MCP. `AUTHOR` is a
`did:key:…` or the literal `me`; `WEIGHT` defaults to `1.0` and must lie in
`[0,1]`. No arguments means the `Solo` default, unchanged.

**Weights, not a set of authors.** `PeerContested` is defined over per-author
weights and an author with no entry is invisible rather than down-weighted.
The consumer driving this (day's frames) expresses a role hierarchy —
"verdict claims authoritative only from the director's key" — which is a
weighting, so a surface accepting only a *set* of authors would have been a
narrower thing wearing the same name.

**Per-invocation, never workspace state.** Nothing in `Workspace::trust_from`
reads or writes stored state. Comparing one subject under two frames is the
entire point of frames, and a global setting would make that a sequence of
mutations — racy under concurrent sessions, and a durable side-channel in a
tool whose consumer keeps no store of its own.

**Two things the response now says about itself**, which is the part that did
not come from kan's own spec. Both were asked for by the consumer while the
shape was still open (`.design/kan-read-contract.md`, kan-tools/day), which is
the right time to hear from one:

1. **The view names the trust base that produced it** (`trust: {base,
   authors:[{did, weight}]}`). Without it a consumer can only *assume* kan
   honoured the frame it requested; with it, the assumption becomes a read.
   `Solo` reports its single author at weight `1.0` so both variants parse
   identically. Costs a field, not a design.
2. **A read discloses what the trust base excluded** (`excluded_by_trust`, a
   count — never the hidden content, which would ask kan to defeat the trust
   semantics it was just told to apply). `fold::excluded_by_trust` is a second
   pure pass over the same inputs, so the fold itself stays exactly as
   deterministic as it was.

**Why the count is keyed on the claim's own subject, not a merge class.** A
subject whose every claim is untrusted forms no class at all — `merge_classes`
filters by trust too — so a class-keyed count would report `0` for precisely
the case a consumer most needs told, and `no claims` would stay
indistinguishable from `no such subject`. `tests/trust_surface.rs` asserts
both directions, and the negative control (a subject genuinely holding one
claim reports no exclusion) is what makes the signal mean *filtered* rather
than firing unconditionally.

**This is disclosure, not a change of default.** Whether `Solo` should remain
the default once a workspace holds several role identities is #121 and stays
open. The two are separable on purpose: whatever the default, a consumer must
be able to tell that the view it was handed was partial. The human surface
carries the same note as `--json`, because the dogfooded failure was that
`1 live claim(s)` read identically through both channels.

**A malformed selector fails; it is never accepted and ignored.** clap already
rejects unknown arguments, and a bad weight or a non-DID is a hard error
(`invalid_params` on MCP) rather than a skipped entry. Silently dropping one
`--trust` argument would return a view narrower than the one asked for with an
exit code saying it succeeded — the exact class this surface exists to end.
Asserted in `tests/trust_surface.rs` so the property cannot later be traded
away for a tolerant parameter.

**Consequences:** `actions::{show,status,issues,context}` and their `_json`
counterparts take a `&TrustBase`; `publish` deliberately still folds under
`solo_trust` (publishing another author's claims under your own publication is
worse than merely wrong). The `kan://claims/<subject>` MCP resource stays the
default view — a URI has nowhere to put a selection. Schema fields are
additive, so `SCHEMA_VERSION` stays `1`.
