# Feature: end-to-end encryption for the L1 encrypted backup

## Summary

Issue #7 asked four questions in 2026. Three have been answered since, by
passes that ran for other reasons, and saying so is most of what makes this
tractable:

- **"Is the same identity key used for E2EE, or a separate encryption
  keypair?"** — Separate, derived, never converted. ADR-55 decided it, ADR-65
  built it: every identity has a derived X25519 key today, reproducible from
  the same recovery phrase.
- **"Does `HostedRelay` see plaintext claims at all?"** — Rung-dependent, and
  the rungs are ADR-54's ladder. **L1** (encrypted backup) is server-blind by
  definition; **L2+** (permissioned relay / AppView) reads escalated subjects
  because that is what an AppView is *for*. ADR-54 already records that these
  are "a genuine fork, not one server in two modes".
- **"Key management: per-trust-relationship vs per-workspace?"** — Per
  *space-epoch*, wrapped to each member's derived key via HPKE (RFC 9180).
  ADR-55 named the primitive.

What is left is the question ADR-55 explicitly deferred *to this pass*:
**fully-blind whole-CAR encryption versus structure-preserving encryption**,
and the epoch/membership protocol that follows from it. That is #7's second
question — what happens to the `cites`/`SameAs` graph — asked precisely.

The answer is **whole-CAR, per workspace, padded to buckets, pushed on a fixed
cadence**. It turns on this product's users being ones for whom metadata is
itself sensitive — *how much you wrote and when*, and *which projects are
live*, are not acceptable things to hand a backup server merely to save
bandwidth on a 4 MB payload. One residual is deliberately left open and stated
rather than papered over: an account's **project count** is visible, and the
unlinkability that would hide it depends on network behaviour kan does not
control, so kan enables it rather than claiming it.

This pass is design-only. It produces a `.design/` doc and an ADR; the
implementation is Milestone 4's (ADR-35), and nothing here is on v0.10's
critical path until that decision is made.

## Requirements

- REQ-1: **DECIDED — whole-CAR blind, with bucketed padding.** Each push
  replaces one opaque, padded object. Append-only segments were considered and
  rejected on privacy grounds: an ordered list of segment sizes and times is a
  time series of how much was written and when. See "The decision" in
  Architecture for what the losing options buy and what would reopen this.
- REQ-2: The pass states **exactly what an L1 server learns**, and equally
  what the design does **not** protect against. A "server-blind" claim that has
  not enumerated its own metadata leakage is marketing, not a threat model —
  and a design read by people deciding what to trust it with owes them the
  second list as plainly as the first.
- REQ-2b: Metadata obfuscation is a **first-class requirement**, not a
  nice-to-have: for this product's users, *how much you wrote and when* and
  *which projects are active* are themselves sensitive. Volume, growth, and
  timing must be closed by construction rather than noted as residuals.
- REQ-2c: The design works for **one account across several machines with
  different projects checked out**, without any machine gaining access to a
  project it does not hold locally.
- REQ-3: The epoch mechanic is specified concretely enough to implement: what
  starts a new epoch, what a member joining mid-history can and cannot read,
  and what "revocation" means given that kan's claims are immutable and
  sharing is therefore monotonic (ADR-55: revocation is future-only **by
  construction**, and that is stated as kan's stance rather than hidden).
- REQ-4: The design says how a restore works against an L1 server — because
  durability is the *reason* L1 exists (ADR-54), and an encrypted backup that
  cannot be restored from is a worse answer than no backup, which is a mistake
  worth not making twice after #88.
- REQ-5: Nothing in the design requires the local log format to change.
  `log/repo.car` stays what v0.8/v0.9 made it — claims I authored, byte-stable,
  restorable — and encryption applies at the transport boundary. A design that
  reaches back into the store would invalidate the migration matrix's nine
  green cells for no gain.

## Acceptance Criteria

- [ ] AC-1: The doc records the whole-CAR / structure-preserving decision with
      the losing option's advantages stated in its own terms, and names the
      evidence that would reopen it. (REQ-1)
- [ ] AC-2: The doc contains an explicit "what the server learns" list *and* a
      "what this does not protect against" list, each covering timing and
      volume rather than only content. (REQ-2)
- [ ] AC-2b: Volume, growth, timing, and per-workspace activity are closed by
      construction, and the doc says by what mechanism for each rather than
      asserting the property. (REQ-2b)
- [ ] AC-2c: The design is walked through for one account on two machines with
      overlapping-but-different checkouts, showing that neither overwrites the
      other and neither gains access to a project it does not hold. (REQ-2c)
- [ ] AC-3: An epoch walkthrough covers three membership events — add, remove,
      and a member joining after history exists — and states for each what is
      readable and what is not. (REQ-3)
- [ ] AC-4: A restore walkthrough covers the case that matters: the local
      `.kan/` is gone and the operator has only their recovery phrase and the
      server's blobs. (REQ-4)
- [ ] AC-5: The design is expressible without changing `store/log.rs`'s on-disk
      format, and says so explicitly. (REQ-5)
- [ ] AC-6: An ADR records the decision and its threat-model justification.

## Architecture

**Where encryption sits.** At the `Transport` boundary (`src/transport/`),
which is exactly the seam v0.5's Milestone 0 formalized for this. `LocalOnly`
and `GitTree` are unencrypted by construction — one is a local disk, the other
a git tree whose whole point is that a human can read it. `HostedRelay` is the
first transport where the substrate is someone else's computer, and therefore
the first where encryption means anything.

**What is already built and can be assumed.** Every identity has a derived
X25519 encryption key (`Identity::encryption_key`, ADR-65), reproducible from
the recovery phrase, independent of the signing key. HPKE is the named
primitive. The recipient side of the problem is done; this pass is about what
gets wrapped.

**The decision: whole-CAR blind, per workspace, padded to buckets, pushed on a
fixed cadence.** Each workspace has one opaque object; each push replaces it
entirely; the size is rounded to a bucket; pushes happen on a schedule whether
or not anything changed.

Three things fall out of that combination, and the third was not obvious.

**Whole-CAR over segments (rejected on privacy grounds).** Append-only
encrypted segments would have given incremental transfer at most of whole-CAR's
opacity — but "most" was doing real work: an ordered list of segment sizes and
arrival times is a *time series of how much you wrote and when*. Not a residual
worth accepting to save bandwidth on a 4 MB payload.

**Padding, because whole-CAR alone is only blind-looking.** A server recording
each push's size can difference consecutive sizes and recover very nearly the
same write-volume series segments would have handed it outright. Rounding each
object up to a bucket turns that into a step function that moves only when the
log crosses a boundary — rarely, for a typical log. This is affordable for
exactly the reason whole-CAR was: kan's logs are small (day's whole 40-subject
log is 4.2 MB), and padding one object costs one rounding where padding every
segment would cost a rounding per push and dominate small deltas.

**Fixed cadence, which whole-CAR makes free.** Because every push replaces the
entire padded object, **a decoy push is byte-indistinguishable from a real
one** — same size, same shape, same operation. Pushing on a schedule regardless
of activity therefore closes the timing channel completely, at no design cost
beyond bandwidth already committed. Segments could never have done this: a
decoy segment would be empty or tiny and stand out immediately. The option
exists *because* of the whole-CAR choice.

### Scope: one object per workspace, and why not per account

The tempting next step is one object per *account* covering every workspace,
which would hide how many projects exist. It does not survive contact with a
real setup, and the reason is worth recording so it is not re-proposed.

One account is routinely used from several machines with **different projects
checked out** — a laptop with three, a desktop with five, two of them shared.
With a single account-wide object, each machine knows only its own workspaces,
so their pushes **overwrite each other**. The only repair is for every machine
to fetch the account object, decrypt it, merge its local projects in, and
re-upload — which buys two things nobody asked for:

- **Every machine transiently holds every project's plaintext.** Checking out
  only some projects on a laptop is often deliberate; this quietly undoes it.
- **Concurrent pushes become lost updates.** Two machines on the same tick, one
  wins.

So differing checkouts **mandate per-workspace scope**. That is forced by the
deployment, not chosen for convenience.

### Project count leaks, and why unlinkability is supported but not promised

Per-workspace objects mean a server can count them: an account with five
objects backs up five projects. Fixed cadence hides *which* is active, but not
how many exist.

The obvious fix is per-workspace credentials — each project under its own
account, so the server sees N unrelated accounts rather than one with N
projects. kan **supports** this: nothing in the design assumes one credential
per person.

kan does **not promise** it, and the reason is the standard REQ-2 sets. That
unlinkability is defeated by things kan does not control:

- **Same IP.** N accounts from one address correlate instantly.
- **Same cadence.** Having just mandated fixed-schedule pushes to close timing,
  N accounts pushing *on the same tick from the same address* is a louder
  signal than the count ever was. The timing fix actively works against the
  unlinkability fix.
- **Billing**, if this is ever a paid service.

Promising unlinkability a server defeats with two queries is worse than a
disclosed leak, because it changes what someone would risk storing. So: the
default is strong on everything kan can actually deliver, the residual is
stated, and the user whose threat model needs more has a documented path —
separate credentials, separate network paths, staggered cadence — that kan
enables rather than claims.

**What the losing options buy, so this can be reopened on evidence.**
Structure-preserving is the only option letting an L1 server grow into an L2
AppView without a format change; if the product decides one server must do
both, this is wrong and should be revisited — though ADR-54 records those as a
genuine fork rather than one server in two modes. Segments buy incremental
transfer, which matters only if logs grow orders of magnitude beyond today's;
the evidence to reopen is a user whose push cost actually hurts, not an
anticipated one.

### What the server learns

**It sees:**

- That an account exists, and its authentication identity.
- How many workspaces that account backs up — one object each.
- Each object's **padded** size: a bucket, not a byte count, and therefore only
  a coarse lower bound on a log's size.
- That a push happened on schedule. Not whether it contained anything: a decoy
  is byte-indistinguishable from a real push, and the padded size is unchanged
  unless the log crosses a bucket boundary.
- Access patterns: when a restore happens.

**It does not see:**

- Any claim text, subject name, or status value.
- How many claims exist, or their distribution across subjects.
- The citation DAG — what cites what — or any `SameAs`/relation edge.
- Which subjects are contested, dense, abandoned, or recently touched.
- How much was written in any session, or whether *anything* was written.
- **Which workspace is active**, or whether a project has been dormant for
  months.
- Author DIDs within an object.
- Which machine pushed, beyond what the network layer reveals.

### What this does not protect against

Stated as plainly as the list above, because a design like this is read by
people deciding what to trust it with (REQ-2).

- **That you use kan, and how many projects you back up.** Irreducible without
  per-workspace credentials, which kan supports and does not promise — see
  above.
- **Your network origin.** IP, TLS fingerprint, and connection timing are
  visible to the server and to anyone on the path. kan avoids *adding* signal
  (no telemetry, minimal user agent) but cannot hide that you connected. Tor or
  a VPN is the user's layer.
- **A compromised endpoint.** Everything here protects bytes in transit and at
  rest on someone else's disk. A local attacker with your seed has your log —
  that is T1, and ADR-55's threat model accepted it as residual at the root.
- **Retroactive revocation.** Removing a member stops future access only; see
  Epochs below. Claims are immutable, so this is by construction.
- **A malicious server withholding data.** Blindness is not availability. A
  server can refuse to serve, or serve stale objects. Retention of the last N
  pushes (below) bounds the damage of a *corrupt* push, not of a hostile
  operator. Detecting that is out of scope for L1 and belongs with whatever
  L2's trust model turns out to be.

### What the server stores

A backup that keeps exactly one object per workspace is one bad push away from
being no backup — and since each push *replaces* the object, a corrupted or truncated
upload would otherwise destroy the only copy. The server keeps the **last N
pushes** (N configurable, defaulting to something small like 5) and expires
older ones.

This costs padded-size × N — for a typical log, one bucket times five. That is
the concrete price of whole-CAR's simplicity, and it is small enough to pay
without thinking. It also means a restore can fall back to the previous object
if the most recent one fails to decrypt or verify, which is the failure a
single-object design has no answer to.

### Two machines, different checkouts

The case that killed the per-account design, walked through on the one that
replaced it (AC-2c).

Alice's laptop holds `kan` and `day`. Her desktop holds `kan`, `day`, and three
client projects. Both push on the hour.

- The laptop pushes two objects: `kan` and `day`. The desktop pushes five.
  Nothing overwrites anything, because an object belongs to a *workspace*, not
  to a machine.
- `kan` and `day` are pushed by both. Last writer wins **per workspace**, which
  is correct: both machines hold the same workspace, and the loser's content is
  a prefix of the winner's if they were in sync, or a genuine divergence if
  they were not — the same situation two clones of a git repo are in, and out
  of scope here for the same reason.
- The laptop never fetches, decrypts, or holds the three client projects. It
  has the key material to do so if it were handed their ciphertext, but it is
  never handed it, because it never asks for objects it has no workspace for.
- The server sees five objects on a fixed cadence and cannot tell which machine
  wrote which, nor that two of them have two writers.

The one thing it *can* tell is that this account has five workspaces. That is
the disclosed residual.

### Epochs and membership

An epoch is a content key. A segment is encrypted under the current epoch key,
and that key is wrapped via HPKE to each member's derived X25519 key (ADR-55,
ADR-65). A segment records which epoch it belongs to; nothing else about it is
readable.

**At L1 the mechanism is degenerate, and that is the point.** The personal
backup is N=1 — you are the only member — so there is never a membership
change and never more than one epoch in practice. The mechanism is specified
now anyway so that L2 adds members to something already correct, rather than
retrofitting multi-recipient encryption onto a single-recipient format, which
is the shape of migration that has hurt before (#107).

Three events, and what each means (AC-3):

- **Add a member.** A new epoch begins. The new member is a recipient of the
  new epoch key and every future one. They *cannot* read prior epochs unless
  the operator explicitly re-wraps that history to them — an opt-in "grant
  history" act, never the default, because silently backfilling access to
  everything ever written is not what "add a collaborator" should mean.
- **Remove a member.** A new epoch begins without them. They keep the ability
  to decrypt every epoch they already held. This is **future-only revocation,
  by construction** — claims are immutable and content-addressed, so anyone
  who could decrypt an epoch keeps that ability forever. It is stated here
  because "end-to-end encrypted" invites the assumption that removal is
  retroactive, and a design that lets that assumption stand misleads.
- **A member joins after history exists.** Same as add: forward access by
  default, past access only by explicit grant. Their first readable segment is
  the first one written under the epoch they joined.

### Restore

The case that matters, since durability is why L1 exists at all and #88 is the
issue it answers (AC-4). The operator has their recovery phrase and nothing
else — no `.kan/`, no key file, possibly a different machine.

1. The phrase reproduces the seed, which derives both the signing key and the
   X25519 encryption key (ADR-65, ADR-66). One escrowed secret, both slots —
   which is exactly why that property was worth insisting on when the
   encryption key was built.
2. Authenticate to the server and list the stored objects (the latest, plus
   the retained previous few).
3. Fetch the most recent object; unwrap its epoch key with the derived X25519
   key; decrypt and strip the padding. If it fails to decrypt or verify, fall
   back to the previous retained object and say so loudly — a silent fallback
   to older data would be a worse failure than no restore.
4. Replay the decrypted records through `Log::ingest` — the verbatim-insert
   primitive v0.8 built (ADR-59) and `kan restore` already uses (ADR-63).
   Same content, same CIDs, same signatures; nothing is re-signed.
5. The index rebuilds from the log on open, as it always does.

The pleasing part is how little of this is new: steps 4 and 5 are `kan restore`
with a different source. The encrypted backup is another transport feeding the
same primitive, which is what REQ-5 is protecting — the local format staying
put is what makes the restore path already exist.

Whole-CAR makes this simpler than segments would have: there is one object to
fetch and one decryption to get wrong, rather than an ordered list where a
missing element is a silent hole in the middle of a log.

## Resolved Questions

**Does the local format change?** No, and REQ-5 makes that a requirement rather
than an expectation. `log/repo.car` is what v0.8 and v0.9 made it, and the
migration matrix now has nine green cells asserting this build reads every
released version's workspace. Reaching into the store for a transport concern
would put that at risk for nothing — encryption belongs at the boundary where
the bytes leave the machine.

**Is revocation possible?** Not retroactively, by construction, and this is
kan's stance rather than a limitation to work around. Claims are immutable and
content-addressed; a reader who could decrypt an epoch keeps that ability
forever. Removing a member starts a new epoch and stops *future* access. ADR-55
settled this and the same truth governs the L3/L4 ratchet — it needs restating
here only because "end-to-end encrypted" invites the assumption that removal is
retroactive, and a design doc that lets that assumption stand is one that
misleads.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Bucket size, and what a push costs when the log outgrows the first one

Padding is what makes whole-CAR genuinely blind, and the bucket size sets both
the strength of that and the price. Too small and the step function tracks the
log closely enough to leak growth; too large and every push moves a padded
object far bigger than the data.

The relevant measurements do not exist yet: how large a real kan log gets over
a year of daily use, and how that interacts with push cadence. day's is 4.2 MB
after months, which suggests a first bucket in the single-digit MB holds most
users indefinitely — but that is one log.

**To resolve** in the Milestone 4 build, against a measured growth curve rather
than a guess. Lean: a small number of geometric buckets (4 MB, 16 MB, 64 MB, …)
so the step function is coarse at every scale, rather than linear buckets that
leak proportionally more as a log grows.
<!-- /OPEN -->

## Out of Scope

- **The L2+ AppView posture.** ADR-54 already records that a blind backup and a
  reading relay are a genuine fork rather than one server in two modes. This
  pass specifies L1; L2's protocol is its own work and its own threat model.
- **The wire protocol and server implementation** — Milestone 4 (ADR-35),
  informed by this.
- **`did:plc` and the atproto rungs (L3/L4)** — ADR-35's M5.
- **Two-layer signing / enclave-held per-device keys** — ADR-55 deferred these
  as their own milestone because they touch the fold; they change *who signs*,
  not who can decrypt.
