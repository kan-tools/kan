# ADR 0054: The sync remote and the publicness ladder

- Status: Accepted
- Date: 2026-07-28
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-54

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

**Date:** 2026-07-28
**Status:** Accepted

**Context:** the durability design pass (`.design/durability-log-recovery.md`,
#93/#88) asked, as its one open question (Q3), whether the complete-durability
answer is a machine-only complete mirror or just the curated `.claims/` plus a
visibility column. Pulling on that surfaced the larger question kan had
deferred: what is kan's version of a *git remote* — the "server-side,
non-atproto component" — and how does it relate to the eventual atproto/social
layer. This ADR records the shape resolved in that session
(`.design/sync-remote-and-publicness-ladder.md`).

**The realization that organizes everything: encryption dissolves the
durability-vs-sharing tension #93 treated as permanent.** #93 posed durability
(complete, automatic, no judgement) and sharing (curated, deliberate, judgement
is the point) as wanting opposite defaults. They conflict *only in plaintext*.
An end-to-end-encrypted backup carries **zero privacy cost**, so durability can
be total-by-default while sharing stays a separate, deliberate act — the two
are distinguished by *encryption state*, not *completeness state*. The wall #93
saw was a plaintext wall.

**The complete-durability answer is a personal encrypted backup remote, not an
in-repo mirror.** The CAR is pushed to a remote over an API and never enters the
git tree — which sidesteps the durability doc's REQ-6 (a plaintext complete
dump either destroys `.claims/`'s curation or reintroduces the binary-in-git
merge conflict ADR-3 rejects) entirely. `.claims/` stays purely the sharing
layer. This supersedes the durability pass's Q3.

**The remote is `HostedRelay` at N=1** (`.design/sync-layer-architecture-and-staging.md`
M4, ADR-35), the multi-actor fold turned off. "Private teams" is the N>1
deployment of the identical server and sync protocol, reached by subscribing to
other authors' logs. So the personal backup is not a new epic — it is
HostedRelay's first and simplest deployment, designable and shippable ahead of
the hard multi-actor story.

**The wire shape is atproto repo-sync, not a git-remote protocol, and this is
what makes it lighter than git.** The log is an append-only Merkle Search Tree
with no history rewriting (the non-negotiable invariant). Git's remote weight is
mutable refs and history rewriting — force-push, rebase, pack negotiation over a
rewritable DAG — none of which kan has. Two MSTs reconcile by comparing root
CIDs and descending only where subtrees differ, which is exactly what
`com.atproto.sync` already does and what kan's on-disk artifact (already an
atproto repo) is already shaped for. The eventual atproto/PDS transport (M5) is
therefore a continuation of the same wire, not a rewrite.

**The publicness ladder** — every downward rung an explicit, user-controlled
escalation, riding kan's existing publish/curate boundary (ADR-43) extended one
notch (publishing already means "legible to others"; escalation extends *to
whom*):

- **L0 Local** ↔ **L1 encrypted backup** (server-blind) — fully reversible,
  total, the durability answer.
- **L2 kan server / permissioned relay** — server reads escalated subjects;
  mostly reversible (the user controls the relay).
- **L3 atproto permissioned** → **L4 atproto public** — practically
  *irreversible* (cached, indexed, federated externally). kan retracts in its
  own model but cannot un-ring an external bell; the escalation surface must
  mark the one-way rungs as distinct from the reversible ones.

**The two server postures are a genuine fork, not one server in two modes.** A
blind backup (L1) wants the server to hold opaque bytes; an AppView relay (L2+)
must read plaintext to fold. They pull opposite directions on E2EE and may be
different services; the HostedRelay design pass must state which it is at each
rung rather than assume a single posture.

**What this hands the identity pass (#105).** The rungs need *different*
encryption capabilities — L1 encrypt-to-self, L2/L3 encrypt-to-a-recipient-set,
L4 plaintext-signed — so #105's master-seed derivation must yield recipient/group
encryption, not only self-encryption (`.design/durability-log-recovery.md`
IREQ-5). A remote holding the log is also a new threat-model actor
(curious/malicious provider) #105 must enumerate. This is the point the
durability, identity, and sync/remote passes merge, recorded so #105 designs
against it from the start rather than discovering it (the #107 failure mode).

**Deferred to future passes, deliberately:** the fully-blind-whole-CAR vs.
structure-preserving-E2EE choice (kan's tiny logs make whole-CAR viable, unlike
git — resolved in the HostedRelay pass); and whether multi-device under one
identity is a sync problem or handled entirely by per-device sub-identities
(#30) plus the fold (the preferred shape — multi-device becomes multi-agent
becomes a fold). Pricing and infra remain out of scope (`kan-infra`); this ADR
records only the architectural consequences *for* monetization — that L1 is a
trust/privacy product and L2+ is a collaboration/intelligence product, and kan
can credibly be both because the user draws the line per-subject.
