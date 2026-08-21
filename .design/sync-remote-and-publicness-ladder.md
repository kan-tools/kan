# Feature: The sync remote and the publicness ladder

## Summary

kan's source of truth is one gitignored directory on one machine (#88/#93).
This doc records the product/architecture shape that answers "what is kan's
version of a git remote" without importing git's weight: a **personal sync
remote** that is `HostedRelay` at N=1 — the multi-actor fold turned off —
storing the log as an end-to-end-encrypted backup, and a **user-controlled
publicness ladder** whose every downward rung is an explicit escalation the
user controls, from a server-blind encrypted backup up through a permissioned
relay and eventually atproto public. The organizing realization is that
**encryption dissolves the durability-vs-sharing tension #93 treated as
permanent**: the two conflict only in plaintext. This is a staging/vision
document — it commits the shape and sequences future `/design` passes; it does
not specify a wire protocol or authorize a build.

## Requirements

- REQ-1: The complete-durability answer is a **push to a personal encrypted
  backup remote**, not an in-repo mirror. The CAR leaves for a remote over an
  API and never enters the git tree, sidestepping `.design/durability-log-recovery.md`
  REQ-6's binary-in-git conflict and keeping `.claims/` as purely the sharing
  layer. This supersedes that doc's Q3 by naming where the complete mirror
  actually lives.
- REQ-2: The default backup rung (L1) is **server-blind (E2EE)**: the remote
  stores ciphertext the provider cannot read, encrypted under the user's
  encryption key. Because an encrypted backup carries no privacy cost,
  durability at L1 is **total and automatic** (every subject, no curation),
  while sharing stays a separate deliberate act — the two are distinguished by
  *encryption state*, not *completeness*.
- REQ-3: The remote is `HostedRelay` (`.design/sync-layer-architecture-and-staging.md`
  M4) **at N=1** — the same server and sync protocol with the cross-actor fold
  disabled. "Private teams" is the N>1 deployment of the identical mechanism,
  reached by *subscribing* to other authors' logs. The personal backup is
  therefore not a new epic but HostedRelay's first and simplest deployment,
  designable and shippable ahead of the hard multi-actor story.
- REQ-4: The sync wire shape is **atproto repo-sync semantics** (`com.atproto.sync`:
  root/blocks-since-cursor), not a git-remote protocol. kan's log is an
  append-only Merkle Search Tree with no history rewriting (the non-negotiable
  invariant), so the sync problem is Merkle-diff — descend only where subtree
  CIDs differ — which is *lighter* than git precisely because git's weight is
  mutable refs and history rewriting, both of which kan lacks. This makes the
  eventual atproto/PDS transport (`sync-layer-architecture-and-staging.md` M5)
  a continuation of the same wire, not a rewrite.
- REQ-5: Escalation up the ladder is **monotonic and per-subject/space**, and
  the rungs past the user's own trust boundary are a **one-way ratchet** that
  the escalation surface must mark as distinct from the reversible rungs:
  - **L0 Local** ↔ **L1 encrypted backup** (server-blind) — fully reversible.
  - **L2 kan server / permissioned relay** — server reads escalated subjects;
    mostly reversible (the user controls the relay).
  - **L3 atproto permissioned** → **L4 atproto public** — practically
    *irreversible* (cached, indexed, federated externally). kan can retract in
    its own model but cannot un-ring an external bell.
- REQ-6: The ladder's rungs require **different encryption capabilities**, and
  this is a hard requirement handed to the identity pass (#105,
  `.design/durability-log-recovery.md` IREQ-5): L1 is encrypt-to-self, L2/L3
  permissioned is encrypt-to-a-team/recipient-set, L4 public is
  plaintext-signed. #105's master-seed derivation must yield an encryption
  capability supporting recipient/group encryption, not only self-encryption,
  or the permissioned middle of the ladder cannot be built.
- REQ-7: The two server postures are a genuine fork the future passes must not
  blur. A **blind backup** (L1) and an **AppView relay** (L2+) pull opposite
  directions on E2EE — the backup wants the server to hold opaque bytes, the
  AppView must read plaintext to fold. They may be different services, not one
  server in two modes; the HostedRelay design pass must state which it is at
  each rung rather than assume a single posture.

## Acceptance Criteria

- [ ] AC-1: `.design/durability-log-recovery.md` Q3 is resolved to point here,
      and this doc's REQ-1 names the encrypted backup remote as the
      complete-mirror answer (checkable: the durability doc's Open Questions
      section reads "None," and its Q3 resolution references a separate
      sync/remote pass).
- [ ] AC-2: The publicness ladder is stated with all five rungs (L0–L4), the
      L1 backup is committed as server-blind/E2EE with total-by-default
      durability, and each rung's reversibility and encryption capability is
      named — mechanically: REQ-2 fixes L1 as blind/total, REQ-5 enumerates
      L0–L4, and REQ-6 maps each of {self, recipient/group, plaintext} to a
      rung.
- [ ] AC-3: The identity pass (#105) receives REQ-6 as a hard input — checkable
      by `.design/durability-log-recovery.md` carrying IREQ-5 and the #105
      design doc, once opened, citing it in its threat-model/requirements.
- [ ] AC-4: The staging plan's HostedRelay milestone is annotated with the N=1
      personal-backup framing, the atproto-sync (not git) wire shape, and the
      blind-backup-vs-AppView fork (REQ-3, REQ-4, REQ-7), so a later HostedRelay
      `/design` pass starts from this shape rather than rediscovering it —
      checkable by a cross-reference added to
      `.design/sync-layer-architecture-and-staging.md`.
- [ ] AC-5: An ADR records this shape (the ladder, the N=1 remote, the
      encryption-dissolves-the-conflict realization, the atproto-sync wire) so
      it is discoverable outside this file — checkable: `docs/DECISIONS.md`
      contains the ADR and this doc references its number.

## Architecture

This doc changes no source. It records a shape and sequences future passes; the
concrete build surfaces it points at are all staged, not authorized here.

**Where it sits relative to existing work.** `.design/sync-layer-architecture-and-staging.md`
(ADR-35) already stages `Transport`/`LocalOnly` (M0, shipped), `GitTree` (M1.5,
shipped publish-half), the Workspace wiring (M2, the current v0.8 build), and
`HostedRelay`/`AtProto` (M4/M5). This doc **sharpens M4**: HostedRelay's first
deployment is the N=1 personal backup, and its design pass must resolve the
blind-backup-vs-AppView fork (REQ-7) rather than assume a posture. It also
**supersedes `.design/durability-log-recovery.md` Q3**: that pass stays scoped
to local-only restore-from-`.claims/` plus the visibility column (its REQ-5),
and the complete mirror it deferred is this doc's REQ-1.

**Why the wire is atproto-sync and not git.** The log is an append-only MST
(`store::log::Log`, `src/store/log.rs`); HEAD only advances and nothing rewrites
history (the invariant CLAUDE.md protects). Git's remote weight — pack
negotiation over a rewritable DAG, mutable refs, force-push/rebase — is exactly
the part kan does not have. Two MSTs reconcile by comparing root CIDs and
descending only where subtrees differ, which is what `com.atproto.sync` already
does and what kan's on-disk artifact (already an atproto repo, ADR-1/11/12) is
already shaped for. The `Transport` trait (`src/transport/mod.rs`) is the seam
this remote implements, alongside `LocalOnly` and `GitTree`.

**How the ladder maps onto machinery kan already has.** The escalation boundary
is kan's existing **publish/curate** distinction (ADR-43), extended one notch:
publishing already means "I decided to make this legible to others." L1→L2 is
"legible to the relay's AppView"; L3/L4 is "legible on atproto." The
per-subject `Publication` claim (`src/claim/v1.rs:261`) is the natural carrier for
which rung a subject sits at — a rung is a property the fold can already read,
not new enforcement. This keeps the whole model affordance-not-enforcement:
escalation is data, and the one-way rungs (REQ-5) get a surface that says so.

**The identity coupling.** A remote that holds your log is a new threat-model
actor for #105 (curious/malicious provider), and the L1 backup needs the
encryption key #105 derives. So this road is downstream of #105's key-derivation
decision, and REQ-6 is the concrete requirement it hands back. This is the point
the durability pass, the identity pass, and the sync/remote pass genuinely
merge — recorded so #105 designs against it from the start rather than
discovering it (the #107 failure mode).

## Resolved Questions

**The E2EE fork (from this session):** not a global either/or. The blind
backup (L1) and the AppView relay (L2+) coexist as rungs of one ladder, with
the user drawing the boundary per-subject using the publish distinction kan
already ships. Encryption-by-default with explicit escalation is also the
atproto-native model (public records world-readable; private/permissioned data
a separate encrypted story), so the synthesis is the alignment, not a detour.

**Durability-vs-sharing (from #93):** dissolved, not balanced. They want
opposite defaults only in plaintext; an E2EE backup makes "complete and
automatic" free of privacy cost, so durability is total-by-default (L1) while
sharing stays a separate escalated act (L2+). Different encryption states, not
different completeness states.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Fully-blind whole-CAR backup, or structure-preserving E2EE?

L1 can be **fully blind** — the server holds one opaque encrypted CAR replaced
wholesale each push, learning nothing, with no incremental diff. This is
genuinely viable *for kan specifically* because logs are tiny (~2 MB at 175
claims); git could never "encrypt the whole repo and re-PUT on a timer," kan
can. The alternative is **structure-preserving E2EE** — encrypt record contents
but leave the MST shape and CIDs visible so the server ships only new blocks,
at the cost of leaking metadata (claim counts, timing, DAG shape, sizes).

**To resolve** in the HostedRelay design pass, not here: whether L1's simplicity
(whole-CAR, zero metadata leak) outweighs its bandwidth cost, given kan's log
sizes. The answer likely starts fully-blind and adds structure-preserving sync
only if log sizes ever make whole-CAR pushes painful.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Is multi-device under one identity a sync problem or an identity problem?

Two machines appending to "one" append-only log under one identity produces two
HEADs — divergence — the classic multi-device problem atproto has too. kan's
architecture implies an answer that is *not* multi-writer sync: give each device
a **derived sub-identity** (#30's per-agent sub-keys), let each append to its
own sub-log, and let the **fold merge them**. Multi-device becomes multi-agent
becomes a fold — no CRDT, no merge-conflict resolution on the log itself.

**To resolve** across the #105 identity pass and the HostedRelay pass: whether
multi-device is handled entirely by per-device sub-identities + fold (preferred,
reuses existing machinery) or needs any sync-layer support at all. If the former,
it is another reason #105 must produce derivation paths, not a single key.
<!-- /OPEN -->

## Out of Scope

- The HostedRelay wire protocol itself (auth, endpoints, cursor semantics,
  blob encoding) — staged as its own `/design` pass (`sync-layer-architecture-and-staging.md`
  M4), informed by this shape and by #7's E2EE pass.
- The identity/key-derivation mechanism (#105) — this doc hands it REQ-6/IREQ-5
  but does not design the enclave/escrow/derivation scheme.
- The atproto/PDS transport and lexicon separation (M5) — a continuation of the
  same wire, its own far-future pass.
- The v0.8 Workspace-wiring build (M2) — unchanged and unblocked by this doc;
  it proceeds against `.design/durability-log-recovery.md` REQ-1/REQ-4.
- Pricing, infra deployment, and the `kan-infra`/hosting company mechanics —
  a different kind of decision than codebase architecture (`sync-layer-architecture-and-staging.md`
  already scopes `kan-infra` out); this doc records only the architectural
  consequences *for* monetization, not a business plan.
