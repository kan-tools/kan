# Feature: HostedRelay — the client transport, and where the server begins

## Summary

ADR-35's Milestone 4. Its stated gate — the E2EE decision — was cleared by
ADR-70, and clearing it turned out to change more than expected: **the wire
shape ADR-54 assumed for this transport is incompatible with the encryption
posture ADR-70 chose.** Resolving that is this pass's first job, and most of
what follows falls out of it.

Two further things narrow the scope before any design happens:

- **The server is not kan's.** `.design/sync-layer-architecture-and-staging.md`
  puts `kan-infra` (deploy, `did:plc`, domains) explicitly out of scope. So M4
  in *this* repo is a client transport plus a stated interface, not a service.
  Saying where the boundary sits is a deliverable, because kan-infra has to be
  buildable against it independently.
- **The first deployment is N=1** (ADR-54): one person backing up their own
  repos, with the cross-actor fold off. The multi-actor relay is a later rung
  and a different threat model.

## Requirements

- REQ-1: Resolve the **wire-shape contradiction** between ADR-54 (atproto
  repo-sync: "two MSTs reconcile by comparing root CIDs and descending only
  where subtrees differ") and ADR-70 (whole-CAR blind, padded). These cannot
  both hold: descending into differing subtrees requires the server to see the
  MST, which is precisely the structure-preserving posture ADR-70 rejected.
- REQ-2: State the **client/server interface** concretely enough that
  `kan-infra` can be built against it without reading kan's source — the
  operations, their shapes, and what the server must never require.
- REQ-3: An **auth model** that proves a client may write to an account
  without leaking more than ADR-70 permits, and that supports the
  per-workspace-credential path ADR-70 described (kan enabling unlinkability
  without promising it).
- REQ-4: The **N=1 personal backup** works end to end: push, retain, restore,
  with the cross-actor fold off.
- REQ-5: **Failure is local-first.** An unreachable, slow, or hostile server
  must never block a local write. kan works offline (`README`) and a backup
  that can stop you recording a claim has inverted the product.
- REQ-6: No local format change, inheriting ADR-70's REQ-5. `log/repo.car`
  stays what v0.8/v0.9 made it, and the migration matrix's nine green cells
  stay meaningful.

## Acceptance Criteria

- [ ] AC-1: The doc records the ADR-54/ADR-70 resolution, says which decision
      yields and why, and states what becomes false in the superseded one so
      the ADRs do not silently disagree. (REQ-1)
- [ ] AC-2: The interface is written as operations with request/response
      shapes and error cases, in a form kan-infra can implement without
      consulting kan's source. (REQ-2)
- [ ] AC-3: The auth model states what the server learns about the client, and
      is checked against ADR-70's "what the server learns" list rather than
      adding to it silently. (REQ-3)
- [ ] AC-4: A walkthrough covers push → retain → restore at N=1, including
      restore onto a machine with no `.kan/` and only a recovery phrase.
      (REQ-4)
- [ ] AC-5: The doc states what happens on every failure mode — unreachable,
      timeout, auth rejected, stale response, corrupt object — and in each case
      that the local write path is unaffected. (REQ-5)

## Architecture

### The contradiction, and which decision yields

ADR-54 said the wire is atproto repo-sync, and gave a good reason: kan's log is
an append-only MST with no history rewriting, so two MSTs reconcile by
comparing root CIDs and descending where subtrees differ — much lighter than
git's mutable-ref and pack-negotiation machinery, and a continuation of the
same wire M5's atproto transport would use.

**That reasoning is sound and no longer applies to L1**, because reconciling
MSTs requires the server to *see* the MST. Descending into differing subtrees
is structure-preserving synchronisation by definition, and ADR-70 rejected
structure-preserving encryption for L1 on the ground that kan's `cites` graph
is the provenance, and the provenance is the product.

**ADR-70 wins, and ADR-54's wire claim is rescoped rather than reversed.**
ADR-70 is the later and more specific decision, made against a stated threat
model and an explicit product judgement about these users. ADR-54's wire
argument holds exactly where the server is *permitted* to read: **L2+ and M5**,
where an AppView must index to be an AppView at all. What becomes false is the
"L1 is a continuation of the same wire" implication — L1 is a different, much
simpler wire, and the atproto continuity begins at the rung where reading
starts.

**The consolation is that L1 gets easier, not harder.** With no reconciliation
there is no sync protocol: the client PUTs an opaque object and GETs it back.
No MST negotiation, no diff, no pack format, no partial-fetch semantics. Nearly
all of ADR-35's "net-new wire-protocol build surface" for M4 evaporates —
what remains is an object store with auth, which is the most boring thing on
the internet and can be a signed-URL bucket if kan-infra wants.

### The interface

Four operations. Deliberately small, and deliberately *not* kan-shaped: nothing
here mentions claims, subjects, CIDs, or MSTs, because the server must be
unable to act on them even if it wanted to.

```
PUT    /v1/{account}/{slot}      body: opaque bytes      -> {version, size}
GET    /v1/{account}/{slot}      ?version=N (optional)   -> opaque bytes
LIST   /v1/{account}                                     -> [{slot, version, size, at}]
DELETE /v1/{account}/{slot}/{version}                    -> ok
```

- **`slot`** is an opaque client-chosen identifier, one per workspace. The
  server never learns it names a workspace, and must not derive meaning from
  it — a client is free to use random identifiers, which is what the
  unlinkability path (ADR-70) does.
- **Versions** are server-assigned and monotonic. The server retains the last
  N per slot (ADR-70) and expires older ones; `DELETE` is for a client
  reclaiming space, not part of the normal path.
- **`size`** is the padded size. The server sees no other length.
- **What the server must never require:** the ability to decrypt, any
  claim-shaped field, any ordering relationship between slots, or that a slot
  be pushed at any particular time.

**Errors that matter:** auth rejected, slot unknown, version expired, quota
exceeded, and unavailable. Each is a distinct response, because a client that
cannot distinguish "expired" from "unavailable" cannot decide whether to fall
back to an older version or simply retry.

### Auth

A bearer credential per `account`, presented on every request. Not a signature
over the object, because the object is opaque and the server cannot verify
anything about it — signing it would prove only that the holder of a key
uploaded bytes, which the credential already proves.

**This deliberately does not use the kan signing identity.** Two reasons: it
would tie backup access to the key that signs claims, so revoking a leaked
backup credential would mean rotating a signing DID and moving every claim's
author — the exact failure #90 and #107 are about. And it would hand the server
a `did:key` that is also a public, correlatable identifier across every rung.
A backup credential is a capability, not an identity.

Per-workspace credentials are supported by giving each its own `account`, which
is what makes ADR-70's unlinkability path real rather than notional — and, as
that ADR states, is not promised, because same-IP and same-cadence defeat it.

### Local-first failure (REQ-5)

Every failure mode resolves to the same place: **the local write path is never
affected.** kan works offline; a backup that can stop you recording a claim has
inverted the product.

| failure | client behaviour |
|---|---|
| unreachable / timeout | push skipped, retried next cadence tick; nothing surfaces unless it has failed for long enough to matter |
| auth rejected | surfaced loudly and immediately — this is the one a user must act on, and silently retrying a rejected credential forever is how a backup quietly stops existing |
| quota exceeded | surfaced; pushes stop, local writes do not |
| stale/expired version on restore | fall back to the previous retained version **and say so loudly** — a silent fallback to older data is worse than a failed restore |
| corrupt object (fails to decrypt or verify) | same: try the previous version, report both attempts |

The "has failed for long enough to matter" threshold is the interesting one,
and it is the same problem as the durability column (ADR-64): a backup that
has silently not run for three weeks is indistinguishable from one that ran
five minutes ago, unless something says otherwise. `kan status`'s durability
column is the natural place for it, which is a pleasing reuse rather than a
new surface.

### What kan builds, and what it does not

**kan builds:** the `HostedRelay` `Transport` implementation — an HTTP client,
the encrypt/pad/decrypt path, credential storage, the four operations above,
and the restore path feeding `Log::ingest` (ADR-59/63, already built).

**kan does not build:** the server. That is `kan-infra`, and the interface
above is the whole of what it owes. It can be a bucket behind signed URLs; kan
neither knows nor cares.

**kan also does not build a daemon** — see Q1.

## Resolved Questions

**Does M4 still need atproto repo-sync machinery?** No, and this is the main
practical consequence. ADR-35 listed the wire protocol as M4's dominant
net-new build surface, confirmed by reading crate source: no PDS/XRPC client
exists in kan's dependency tree. With L1 reduced to object PUT/GET, that
surface is deferred to M5, where the atproto rungs need it and where the server
is permitted to read anyway.

**Does #30 gate this?** No, per ADR-35: it gates HostedRelay *shipping to real
multi-agent use*, not starting, and N=1 has no second agent. It remains a
release gate for the multi-actor rungs.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: What runs the fixed cadence?

ADR-70's timing obfuscation depends on pushing on a schedule regardless of
activity — which requires *something* to run on a schedule. kan has no daemon,
and "one surface: CLI + MCP" (`CLAUDE.md`) argues strongly against growing one.

The alternative is that `kan backup push` is an ordinary command and the
cadence is the user's scheduler — cron, launchd, systemd timer. That keeps kan
daemonless, makes the decoy-push behaviour something the user can see and
verify, and is consistent with affordance-not-enforcement. Its cost is that the
strongest privacy property in the design depends on the user configuring
something correctly, and a half-configured cadence leaks the timing it was
meant to hide.

**To resolve** before the build. Lean: a command plus documented scheduler
recipes, and `kan status` reporting when the last successful push happened so a
misconfigured cadence is visible rather than silent — the same "make the gap
data" move as the durability column.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Where does the backup credential live?

It is a secret, and kan already has two storage answers with known trade-offs:
the OS keychain (ADR-25, and #96's hang) and a `0600` file
(`KAN_NO_KEYCHAIN`, ADR-66). Reusing that machinery is obvious; what is not
obvious is whether a *capability* deserves the same protection as a signing
key, given losing it costs a re-issue rather than an identity.

**To resolve** in the build. Lean: same machinery, lower ceremony — no
recovery phrase, since a lost credential is re-issued rather than recovered,
and pretending otherwise would put a second 24-word phrase in front of users
for something that does not need one.
<!-- /OPEN -->

## Out of Scope

- **The server implementation** — `kan-infra`, per ADR-35.
- **L2+ / AppView postures** — ADR-54 records these as a genuine fork; this
  pass is L1.
- **The atproto rungs (L3/L4) and M5's wire** — where ADR-54's repo-sync
  reasoning still holds.
- **Two-layer signing / per-device sub-keys** — ADR-55's later milestone; they
  change who signs, not who can decrypt.
