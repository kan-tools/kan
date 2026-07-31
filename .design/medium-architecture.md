# Feature: media, connections, and the services that host them

## Summary

kan had a *publicness ladder* (ADR-54): L0 Local → L1 encrypted backup → L2
relay → L3/L4 atproto, each rung a downward escalation. Walking the full
deployment — several clients, a paid kan-hosted layer, and a user's own PDS
with kan's reference appview — showed the ladder is the wrong shape, and that
kan had already built the right one without naming it.

**There is no linear order.** There are **media**; an identity writes to one of
them and replicates to others; and what a user sees is a **projection** — the
aggregate of the media they are connected to, through a filter. "Promotion" is
sugar over *post to a medium* plus *aggregate and filter*.

That model is already in the code. `Transport` is a medium connection,
`Workspace.log ∪ overlay` is the aggregate, `TrustBase` is the filter, and the
fold is the projection. v0.8's reader work implemented it; the ladder was
bolted alongside and describes something else.

This doc replaces the ladder with the medium model, names the connection types
and the services that host them, and records what the walkthrough settled.

## Requirements

- REQ-1: The model is a **set of media with capabilities**, not an ordered
  ladder. Anything the ladder expressed that survives — reach, reversibility —
  becomes a property of a medium *instance*, since neither is derivable from
  the medium's kind.
- REQ-2: **Local is privileged for writes only.** kan appends to exactly one
  medium — its own log — and everything else is replication. Read symmetry,
  write asymmetry.
- REQ-3: The **projection** is `fold(⋃ readable claim media, trust)`. Media
  selection is a *mount-level* decision; author trust is a *fold-level* one.
  They compose and are never conflated.
- REQ-4: **Durability is separate from reach.** Which media hold a current copy
  is a different question from who can read them, and the vocabulary must stop
  answering one with the other.
- REQ-5: Every service kan-tools operates must be **unable to read the data it
  holds**, unless a user has explicitly authorised a named service as a reader.
- REQ-6: The design must be **compatible in shape** with atproto's permissioned
  spaces, so that migrating the access-control substrate later is a swap behind
  an interface rather than a redesign.

## Acceptance Criteria

- [ ] AC-1: The doc states, for each connection type, its granularity,
      direction, whether it contributes to the projection, and whether it
      requires a background process. (REQ-1)
- [ ] AC-2: A worked example shows one write reaching every medium it should,
      and one read drawing from several. (REQ-2, REQ-3)
- [ ] AC-3: The durability vocabulary is defined without publicness words, and
      the migration from the shipped `unpublished`/`published`/`stale` column
      is stated. (REQ-4)
- [ ] AC-4: Each hosted service has an explicit "what it can read" line, and
      any plaintext access is shown as a grant to a named service rather than a
      property of the substrate. (REQ-5)
- [ ] AC-5: The membership and access-control seam is identified as the point
      where an atproto Spaces/Arbiter client would later attach. (REQ-6)

## Architecture

### Media, and what a connection is

A medium connection carries:

- **kind** — `Local`, `GitTree`, `Replica`, `Archive`, `AtProto`. This is what
  `claim::Layer` already is, and its discipline holds: *"a layer kan cannot
  serialize to is not a layer it can honestly claim to publish to."*
- **address** — a URI. `file:///path/.kan`, `git+https://…`, `kan+https://…`.
- **declared reach** — who reads plaintext there. **Not derivable from kind**:
  `.claims/` in a private repo and in a public one are the same kind and
  entirely different disclosures.
- **reversibility** — can this be unpublished? A relay you control, yes; a
  public git remote, practically never. This is what the ladder was really
  tracking when it marked "one-way rungs".

`Layer` stays in the claim (the kind is what kan knows for certain, having done
the writing); the address stays in the mount manifest, because URIs move and
signed content is forever.

### The connection types

| | read-only | write-only | read-write |
|---|---|---|---|
| **claim-granular** | **library** | **drop** | **peer** (incl. own local log) |
| **workspace-granular** | **restore source** | **archive** | **mirror** |

- **Claim media** contribute to the projection. Foreground, deliberate,
  per-subject. Must **not** be daemonized — `kan publish` being an act is
  ADR-43's curation boundary.
- **Archives** and **mirrors** are workspace-granular and **require** a
  background process: a whole-store operation cannot ride on a claim write, and
  ADR-70's cadence needs a clock.

**The rule that falls out:** *workspace-granular media require a background
process; claim-granular media forbid one.* That is checkable against a design,
where "should kan have a daemon" was not.

### Conflict resolution: there isn't any

kan's log is a **grow-only set** of content-addressed signed claims. Claims are
never removed — retraction is another claim — and content-addressing makes adds
idempotent. That is a G-Set, and **union is the merge**.

So convergence is guaranteed by the data type rather than by the protocol. No
OT, no transformation functions, no operation ordering, no causality tracking,
no locks, no consensus, at any layer:

- **claim layer** → union, always safe
- **semantic layer** → the fold, which surfaces disagreement as `Contested`,
  i.e. as data
- **medium layer** → atomic writes, no coordination

Two devices under one identity produce divergent *commit chains* over the same
claim set. That is bookkeeping, not data — the same resolution ADR-58's Q2
reached for multi-role, where no read consults a commit signer.

### The services

| service | holds | can read | operated by |
|---|---|---|---|
| **archive** | whole-workspace encrypted objects | **nothing** | kan-tools (paid), or any object store |
| **replica** | per-author logs, encrypted records | **nothing** | kan-tools (paid) |
| **appview** | index of **public** claims | public data only | kan-tools (reference) |

The archive needs no kan software at all — ADR-73's interface is PUT/GET/LIST/
DELETE over opaque bytes, which is S3. kan's side is a thin client so that
backup and restore are seamless, not a service.

**"relay" is not used.** In atproto it means the firehose aggregator that
crawls PDSs; reusing it would be actively misleading. `appview` *is* reused,
because the role matches exactly.

### The replica

A replica holds **N logs, one per author** — never one shared log, because
every author has their own append-only log signed by their own key. "Sharing"
is *you may read my log here*. That makes a replica structurally a small PDS
for kan claims, which is why the eventual atproto migration is a wire change
rather than a restructuring.

**Records are encrypted; the replica is blind.** An MST of encrypted records
gives incremental sync — compare roots, transfer missing CIDs — while the
server learns only *cardinality*. It does **not** learn the citation graph:
`cites` lives inside `ClaimContent`, which is inside the ciphertext.

The per-space-epoch key is wrapped via HPKE to each member's derived X25519 key
(ADR-55, shipped in ADR-65). The **member list** is the only input that was
missing, and an access-control service supplies it.

**Two of atproto's three reasons for choosing access control over encryption do
not apply to kan.** Key management is easier here because the encryption key is
*per-identity and derived from one seed*, so every device derives the same key
and recipients' public keys come from their identity. And group scale is teams,
not the 50k-member case that strains group encryption. The third reason —
backend services must read to index — survives, and is handled by making an
indexer **a member** rather than by making the substrate readable.

### The appview

Aggregates **raw claims**, never summaries. Every claim it serves is signed and
verified per-claim exactly as a `.claims/` record is, so its failure mode is
**omission or staleness, never fabrication**.

Public claims are plaintext by definition, so the reference appview needs no
keys. A *team* appview over encrypted data would be a member holding a wrapped
epoch key — an explicit grant to a named service.

### Identity across kan and atproto

kan claims stay authored by `did:key`. The atproto repo is a **carrier**, the
same way `.claims/` is: a container holding a complete, self-signed claim whose
authorship is independent of who hosts it. Making `did:plc` authoritative would
tie provenance to the carrier, which is the coupling kan exists to avoid.

The **binding** between the two is one artifact, signed both ways:

- **outer** — the record sits in `did:plc:abc`'s repo, whose commit is signed
  by the atproto key
- **inner** — the claim is signed by `did:key:xyz` over `{ plc_did: abc }`

Verification rule: **the binding must name the repo it is found in.** Without
that check a binding could be lifted into someone else's repo; with it, a
lifted binding fails immediately. This is the same defence as ADR-43's REQ-13,
where the filename is authenticated against the records inside it.

Three tiers, and the user chooses:

| location | authenticated by | permanent | third party |
|---|---|---|---|
| PLC `verificationMethods` entry | rotation key | **forever** | none |
| **dual-signed claim in the repo** | commit + kan sig | deletable | none |
| replica-hosted, access-controlled | same signatures | deletable | kan-tools |

The middle is the default. PLC's `verificationMethods` is an open map accepting
any valid `did:key` (max 10, no server-side validation), so the strong tier is
available — but everything in PLC is permanent and public, unredactable even
after deactivation, so a public key is the only thing that belongs there.

**kan's key goes in `verificationMethods`, never `rotationKeys`.** Rotation
keys control the identity; a leaked kan signing key should cost kan claims, not
an atproto account. The malleable-deputy attack is what shared rotation keys
buy.

Because bindings can be private, **"verified" means different things to
different viewers**. A client must never show a bare badge — it names its
source: *verified via PLC*, *via her repo*, *via your replica*.

## Resolved Questions

**Is `mirror` distinct from archive plus restore?** Yes. `kan restore` already
unions rather than clobbers (`Log::ingest` is idempotent), so the merge exists
— but an archive is whole-object replace, so two devices sharing one slot lose
updates. A mirror is incremental, symmetric, and continuous, with both
endpoints holding plaintext. Different protocol, different trust assumption,
different process model.

**Where does membership live?** With the **host**, not in members' repos —
atproto's Arbiter reaches the same answer for the same reason: membership held
in members' repos is circular, since you need membership to read the repos that
declare it. kan's addition is that membership *changes* are also recorded as
claims for audit. The ACL enforces; the claims say who added whom, attributably.
When they diverge, the ACL wins and the divergence is visible.

**Does the archive hold foreign claims?** No — `log/` only. The overlay is
reconstructible from its source media (ADR-59), and archiving it would store
another author's data in a private backup for no durability gain.

**Whose durability does the column report?** Yours. Foreign claims are as
durable as their source medium, which is their author's problem. If a shared
replica dies, everyone keeps their own claims and loses everyone else's — and
nothing is globally destroyed.

### Appview scope, and where opinion begins (T3, resolved)

An appview must select — it cannot hand a client the network. But the two query
shapes differ in a way worth building on rather than papering over:

| query | completeness | response carries |
|---|---|---|
| *give me repo R* | **verifiable** | R's commit root, so the client checks the MST itself |
| *claims about X, network-wide* | **not verifiable, ever** | an explicit "this is a selection", plus scope and cursor |

There is no object that commits to the set of all repos, so cross-repo
completeness cannot be proven by anyone, by any protocol. **The mitigation is
pluralism, not proof** — the format is open and the inputs are obtainable, so
anyone can run their own appview. This is how Bluesky handles the same problem,
and cross-repo queries are the acknowledged boundary of where an appview is
opinionated.

Three rules follow.

**Opinionated about selection, never about folding.** An appview may rank,
filter, and choose what a subject query returns. It must never return a
*folded* result — no settled status, no merged identity, no "current" value.
Claims in, claims out; the client folds. Selection can be opinionated safely
because the client sees every claim it was handed and verifies each one;
interpretation cannot, because a fold output is unattributable and
un-refoldable.

**Never assert completeness you cannot back.** Per-repo responses carry the
commitment. Cross-repo responses are labelled selections. A client can then
treat a sound answer and a plausible one differently, which matters when a
downstream tool concludes something from the result.

**Staleness is a third property, separate from both.** Even a verifiable
per-repo answer is *as of* a commit, so the root travels with its timestamp. A
verifiably-complete but months-old answer passing as current is the durability
column's failure mode in a new place.

**Forkability is only a real mitigation if the format is documented and the
inputs are obtainable.** Both hold: `docs/SPEC.md` §7.1 fixes the claim
contract, the record and MST layouts are specified, public claims are on the
firehose, and a team's claims are held by its members. A closed core over an
undocumented format would make "run your own" a fiction.

**The honest residual:** most users will use kan-tools' appview and get
kan-tools' opinions. Forkability protects structurally rather than practically.
That is equally true of Bluesky, and it is recorded rather than left to sound
stronger than it is.

### Withdrawal, deletion, and update (T6, resolved)

An appview that indexes claims but does not serve retractions shows withdrawn
content as live. That is **misrepresentation rather than incompleteness** — a
different severity from T3's selection, which can honestly say what it is.

**The rule splits by kind**, because the two withdrawal mechanisms differ in
whose they are:

- **`Retraction`** — the author's own, in the author's own repo. An appview
  serving a repo **must** serve its retractions. Omitting one misstates that
  repo's own position, and it is cheap because the commitment already covers
  both.
- **`Rejects`** — another author's, trust-local. Serve it as a claim and apply
  nothing: honouring rejections centrally would be the appview applying
  *someone's* trust base, which is precisely the folding it must not do
  (`docs/SPEC.md` §8 — honoured only by folds that trust the rejecter).

**T3's commitment already enforces the first.** A client verifying a per-repo
response against its commit root *notices* a missing retraction, because the
root will not verify. The mechanism built for completeness makes
retraction-dropping detectable rather than a promise.

The gap it does not cover is cross-repo selections, which have no commitment.
Spec rule: **if you return a claim, you return its retractions.** Cheap for an
appview that is indexing them anyway, and it is the difference between being
opinionated about what you see and being wrong about what you saw.

### Three operations where kan has one

atproto repos are CRUD. kan has one withdrawal mechanism and no notion of the
other two.

| | atproto | kan |
|---|---|---|
| retract | — | a *claim*; preserves what was withdrawn |
| delete | `deleteRecord` | **no concept** — "no operation destroys a subject" |
| update | `putRecord` | **incoherent** — claims are content-addressed |

**Update is preventable structurally: key kan records by their content CID.**
Then `putRecord` with different content under the same key is a detectable
contradiction — the key states CID X, the content hashes to Y. This is the
third instance of one pattern, after `.claims/`'s filename authentication
(ADR-43 REQ-13) and the rule that an identity binding must name the repo it is
found in. Worth stating generally: **the key authenticates the content.**

**Delete is not preventable, and should not be.** The rule is that **deletion
at a medium is a medium event, never a claim event.** A claim's existence is
not a property of any medium — it is a signed object, and a log, a `.claims/`
tree, and a PDS are all places it happens to be. A record vanishing means *no
longer published there*, not *withdrawn*. Treating absence as retraction would
let deletion silently perform a fold-affecting operation kan says it is not.

kan already behaves this way: `git_tree`'s `missing_records` reports removed
records as an **anomaly** ("N of M present, M−N removed since publication"),
not as a retraction. This generalizes #92 from `.claims/` to every medium.

**The honest part.** kan's non-destruction invariant is **local**. Inside
`.kan/` it holds absolutely; at any medium kan does not control it is a
*convention*, and deletion there is genuinely destructive — retraction
preserves what was withdrawn, deletion removes it, and if that medium was a
reader's only source the claim is gone for them.

That is not merely a leak to tolerate. **Right to erasure likely requires it**:
a hosted service that cannot delete cannot operate in most jurisdictions. So
atproto's CRUD is not careless about immutability — it answers a requirement
kan meets the moment it hosts anything.

For the services:

- **archive** — trivial; drop the object.
- **replica** — delete the record, but other members have already synced it.
  **Erasure at a service is not erasure globally**, and promising otherwise
  would be false.
- **appview** — must honour deletion from its index, and must **not** re-derive
  from its own cache afterwards, which would quietly resurrect deleted data.

## Open Questions

<!-- OPEN: Q2 -->
### Q2: Scoped delegation is a fold change (T4, mostly resolved)

**Agents are derived roles.** An agent identity is
`HKDF(seed, "kan/v1/agent/" + label)` — deterministic, so recoverable from the
root without escrowing anything per-agent, and **one-way**, so an agent holding
its key can derive neither the root nor a sibling. Minting is free: one per
container, per worktree, per task. Alice vouches by claim; the agent is
enrolled as a space member with its own wrapped epoch key; it signs as itself,
so its claims are attributable rather than laundered through her.

Most of this shipped in v0.9 — `kan identity role add` already mints,
registers, and `--trust roles` already expands the registry. The delta is a
derived-key mode plus the vouching claim.

**Scope belongs in the vouching claim, not in the key model.** Time-bounds and
per-subject limits are expressed as constraints on the attestation and honoured
at fold time. That keeps keys from proliferating, makes the constraint itself
signed, retractable, and auditable, and composes with the trust machinery
already built.

The cost is that `TrustBase` generalizes from `author -> weight` to
`claim -> weight`, since the decision now depends on the claim's subject and
time. That is a **fold change**, and `CLAUDE.md` requires a measured reason for
one. This is a measured reason — scoped delegation is unbuildable at the key
layer without per-subject keys, and unbuildable at the ACL layer without losing
auditability — but it wants its own pass with its own negative controls rather
than riding the agent work.

**Two constraints on the design:**

*One-step expansion only.* To know whom to trust you fold, but vouching claims
live in the fold. Resolved by honouring vouching claims only from **explicitly
trusted** authors, and never expanding further: Alice's vouching grants
conditional trust to her agents; her agents' vouching grants nothing. Bounded,
decidable, and consistent with transitive trust never being automatic.

*Time-bounds are only as strong as the timestamp.* `recorded_at` is signed but
**self-attested**, so a compromised agent can backdate a claim to before its
authorization lapsed. Per-subject constraints have no such weakness — the
subject is inside signed content. The fix for time is a **notary** attesting
"seen at T", or equivalently a replica recording server-observed arrival, which
is the same claim by another name. Until then, time-bounds bind an honest agent
and a compromised one only after it is noticed. This is #67.

**What remains of #30:** non-extractability — an enclave-held signing sub-key
an agent cannot exfiltrate. Derivation cannot give that, and ADR-55 already
accepted T5 at the root, so it protects nothing today either. The useful half
of #30 — many attributable agents, cheaply, revocably — falls out of derivation
plus the role registry, with **no fold change**.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: The enforcement departure

`CLAUDE.md` says "affordance, not enforcement". A multi-tenant replica must
enforce. The resolution is a layer distinction — the claim model stays
affordance-only, the service boundary enforces — and encryption shrinks it
further, since the check is on ciphertext rather than on readable data. It
still needs recording as a deliberate departure rather than being decided by
whoever implements first.
<!-- /OPEN -->

## Out of Scope

- **The server implementations** — `kan-infra`, per ADR-35. This doc specifies
  what kan's clients need and where the seams are.
- **Streaming/firehose consumption** — the appview aggregates; kan mounts the
  appview. Deferred entirely.
- **`did:web`** — a real alternative for orgs (you control the document, no PLC
  involvement) at the cost of PLC's recoverability. Noted, not specified.
- **Two-layer signing / per-device sub-keys** — ADR-55's later milestone.
