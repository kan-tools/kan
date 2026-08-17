# Design Spec — Agent Memory Substrate (crosslink rewrite)

*Working name TBD (see §11). A local-first, provenance-preserving claim log for multi-agent development. Rust. This spec fixes the hard data-model and algorithmic decisions; two mechanical choices are flagged OPEN for the design flow to resolve (§9).*

---

## 0. Why this exists / what killed v1

v1 (crosslink) treated the **issue as the primitive** and knowledge as a bolted-on subsystem, with **two sources of truth** (SQLite + git coordination branches) reconciled by **distributed locks over an eventually-consistent log**. The result: sync pain, integrity/hydration/compaction machinery, clock-skew hacks, lock-stealing policy. All of it is the tax paid for maintaining **shared mutable state** across actors.

**The rewrite deletes shared mutable state.** Each actor writes only to its own append-only signed log. Nothing is ever mutated by anyone else. Therefore: nothing to lock, no write conflicts, no clock reconciliation. **Conflicts stop being write-time errors and become read-time information.** The intelligence moves entirely into the *fold* — a deterministic reduction from (logs + subscriptions + trust policy) to a view.

**v1's core sin, named:** it computed identity and status by **quotient** — collapsing "these are the same" and "this is the status" to flat values, discarding the witnesses. This rewrite refuses the quotient: identity and status are **objects** (path-spaces / posets), collapsed to flat values only at the *display boundary*, never in the store.

---

## 1. Primitives

The only primitive is the **signed, content-addressed Claim**. Everything else (issues, sessions, knowledge pages, status) is a *view* computed by folding claims.

```rust
struct Claim {
    // identity of this assertion:
    //   (implicit) global address = repo DID + record key. No explicit id field.

    // authorship / provenance
    author: AuthorId,          // = (Did, Option<AgentKey>)  — see §2
    sig: Signature,            // signs the CID (see §3)

    // scope
    workspace: Anchor,         // the project scope; an Anchor (§5), coordination-free

    // subject
    subject: SubjectRef,       // Local | Anchor  (§4, §5)

    // the assertion
    kind: ClaimKind,           // §7
    body: Body,                // §7, kind-tagged

    // the mesh — the ONLY graph structure beyond per-author logs
    cites: Vec<Cid>,           // references to concrete prior claim CIDs
    artifacts: Vec<ArtifactRef>, // commit sha, file@sha, line-range@sha, tool-output hash
}
```

**Write-time primitives are exactly two:** `append claim to my own log`, and (as a kind of claim) `cite`. There is no `assign`, `close`, `lock`, or `merge`. Everything social/stateful is computed in the fold from `cites`, typed `Relation` claims, and subscription/trust.

---

## 2. Identity of actors

```rust
type AuthorId = (Did, Option<AgentKey>);
```

- **`Did`** = the *publishing container* (the human account whose PDS/log carries the claim). The "driver," in crosslink terms.
- **`AgentKey`** = the signing key of the agent that authored the claim; `None` for a human acting directly.

**Ordering/supersession keys on the full `AuthorId`.** A human-direct claim `(did, None)` and an agent claim `(did, Some(k))` are different authors.

> **Implementation note (v0.12.0-beta.3): `AgentKey` is legacy; the shipped
> multi-actor mechanism is roles.** The `agent` field remains in the struct
> (a claim written before v0.7 may carry one, and `AuthorId` still keys
> ordering on it), but no modern write sets it — `KAN_AGENT` was removed in
> v0.7. The way one workspace hosts several distinct authors today is
> **roles**: a `ClaimBody::RoleDeclaration { did, name }` declares a separate
> DID as a named role, and folds trust those DIDs as ordinary peers
> (`ADR-58`, `.design/role-declarations.md`; `src/roles.rs`). The default
> trust base is `Local` — every DID that has written into this log (`ADR-83`).
> This paragraph describes intent; the mechanism is in `src/roles.rs` and
> `src/fold/trust.rs`, which are the artifacts to verify against.

---

## 3. Content addressing (CID)

- The CID is over the **canonical CBOR of the claim content, excluding the signature and the CID itself**. Author, workspace, subject, kind, body, cites, artifacts are all IN. Signature signs the CID (so it's OUT of the hashed bytes). Mirrors atproto's content→CID→sign layering.
- **Canonicalization: adopt atproto's DAG-CBOR** (map-key ordering etc.) wholesale. Makes the future atproto transport a serialization no-op. (Rust: `atproto-repo` crate provides MST/CAR/CID.)
- **`cites` holds CIDs of already-finalized claims** ⇒ citation edges point strictly backward ⇒ **the CID-DAG is strictly acyclic**, even though the *subject graph* may cycle (mutual `SameAs`, §4). Do not conflate: acyclic at CID level, cyclic at subject level.

---

## 4. Subjects & the identity model (HARD — fully specified)

### 4.1 SubjectRef

```rust
enum SubjectRef {
    Local(Rkey),     // resolves within THIS log only; cheap, no consensus
    Anchor(Anchor),  // content-addressed fact about the substrate; see §5
}
```

- **`Local`** ids are shared freely among an actor's own agents (one trust domain, coordination free). A `Local` ref is **meaningless outside its origin log** and MUST NEVER appear as a cross-log reference.
- **Cross-log linkage is exclusively via `cites` (to CIDs) and typed `Relation` claims.** The fold never resolves a *foreign* `Local` ref.

### 4.2 Identity is a morphism, not a predicate

The v1 quotient is banned. Identity between subjects is carried by a **directed, authored `Relation::SameAs` morphism**:

```
sameAs : subjectA ⟶ subjectB      (authored, witnessed, contestable, retractable)
```

- **`SameAs` is the ONLY identity-conferring edge.** `cites`, `About`, `Blocks`, `DependsOn`, `Accepts`, `InTensionWith`, `Supersedes`, `Refutes` never merge subjects. (This is the guard against the transitive "mega-merge" collapse: non-identity relations live in different hom-sets and simply do not compose into identity.) `Rejects` is not in this list because it is not a `RelationKind` at all (§7): it is a claim-level, trust-local suppression, not a subject-to-subject edge.
- A **single** `SameAs` = a *situated* identity claim (one perspective). A fold may honor it if it trusts the author (directed, trust-gated merge).
- A **mutual** `SameAs` (A→B and B→A) = a **weak equivalence**: invertible up to coherence, NOT on-the-nose equality. The two subjects remain distinct objects with a distinguished iso.

### 4.3 The identity object M(A,B) — categorical, witness-retaining

Identity between A and B is **not a boolean** but **M(A,B): the path-space of attested `SameAs` equivalences between them**, retaining witnesses.

- **π₀(M)** = distinct grounds for identity (independent `SameAs` chains).
- **higher structure** = how those chains cohere.
- **weak-through-weak stays weak:** a transitive identity A↔C via B is itself only a weak equivalence, and **the fold must carry its factorization + witness set** (which authors, which arrows, chain length). NEVER silently promote a long weak chain to strict identity.
- **Trust structure = the enriching base** (Lawvere). Per-viewer, per-fold:
  - enrich over `Bool` → "any trusted path?" → flat merge (SoloTrust).
  - enrich over `[0,1]`/quantale → trust-weighted confidence (tropical composition: min along path, max across paths). *This is Willerton's semi-tropical nucleus as the merge algorithm.*
  - enrich over spaces → full witness homotopy type retained.
- **Same `SameAs` set + different trust base ⇒ different identity.** Individuation is viewer-relative by construction.

### 4.4 Fold identity algorithm (NOT plain union-find)

Plain union-find is the quotient (loses witnesses, can't un-merge). Instead:

```
- Maintain a directed graph of TRUSTED SameAs arrows: nodes = subjects, edges = witnessed arrows.
- A "merge-class" = a connected structure in this graph, BUT retain per class:
    * direction of each arrow
    * author + CID of each witnessing claim
    * per-pair: mutually-witnessed (weak equiv) vs one-directional (situated)
    * factorization/witness chain for transitive identities
- Merge is a VIEW-LEVEL interpretation of the arrow graph, never a rewrite of subjects.
- Un-merge = retraction/removal of a witnessing arrow → re-derive components from the
  RETAINED edge set (union-find can't delete; keep the edge list, re-run component-finding
  on the affected component only).
```

**INVARIANT: the fold reads morphisms; it never mutates objects. Subjects in logs are immutable and forever distinct. "Sameness" lives entirely in the morphism layer + the fold's reading of it.** This is what makes v1's hole structurally unreachable: no operation destroys a subject.

### 4.5 Caching & performance (HARD — specified)

Two-tier invalidation:

```
tier 1 (identity / M-objects): invalidated ONLY by Δ(SameAs ∪ trust ∪ their retractions)
tier 2 (per-subject state):    invalidated by any claim on subjects in that merge-class
```

- The `SameAs` graph is empirically **sparse and clique-separating** (disjoint small dense clusters). A `SameAs` change recomputes **only its connected component**; path-space enumeration is bounded by **component size, not graph size**.
- A `SameAs` bridging two components → recompute the union. A retraction may **split** a component → re-derive from retained witness edges (per §4.4).
- **Guardrail:** component size > N (config, default ~25) → **flag to user as probable erroneous identity assertion; do not silently enumerate.** (The perf cliff and the correctness smell are the same event; the cost function is the anomaly detector.)

---

## 5. Anchors (HARD — fully specified)

An **Anchor** is a subject named by a **content-addressed fact about the shared substrate**, constructed identically and independently by every actor.

```rust
enum Anchor {
    Workspace(GenesisCid),          // hash of git genesis / origin — the project scope
    Commit(Sha),
    Blob(Cid),
    FileAt(Path, Sha),
    LineRangeAt(Path, Sha, Span),
}
```

### 5.1 Admissibility INVARIANT

> A subject may be an Anchor **iff** its identity is a pure function of the shared substrate, requiring **zero attestation**. Anchor equality is **DECIDED (computed), never ASSERTED.**

- **Anchors carry STRICT identity:** M(anchor, anchor') is a point, no witnesses.
- **Rationale (safety, not just semantics):** strict identity has **no witness layer to absorb error** — a wrong strict identification is welded into the global topology and cannot be retracted. Therefore strict identity is permitted **only where error is impossible by construction** (computed from bytes). Everything requiring a *judgment* stays Local + weak + retractable.
- **`SameAs` between two anchors is a TYPE ERROR, not a claim.** Anchor identity is settled by construction.

### 5.1.1 Domain relations are stored as asserted, read as projected

*(Numbered 4.5.1 through v0.12.0-beta.2, which placed it inside §5 between
§5.1 and §5.2; renumbered to §5.1.1 in v0.12.0-beta.3, review REQ-9.)*

`SameAs` is enriched (§4.3). The other domain kinds — `Blocks`, `About`,
`ManifestsAt`, `DependsOn`, `Accepts`, `InTensionWith`, `Supersedes`,
`Refutes` — are **not**, yet, and that asymmetry is a known gap rather than a
decision (#72).

What holds for all of them now: a relation claim is stored exactly as
asserted — directed, attributed, carrying its `cites` — and any symmetric,
transitive, or weighted reading of it is a **projection computed on demand**
(`fold::relations`). `InTensionWith` is the clearest case: tension is
symmetric in meaning, so "what is X in tension with" reads both directions,
while the *grounds* are perspectival and stay directed in the store, because
two actors can hold the same pair in tension for different reasons and
collapsing that at write time destroys which side observed what.

A relation carries **no degree and no reason field**. The reason is the claim
it cites. A degree, once anything needs one, is derived by composing over
those witnesses under a chosen enriching base — exactly as §4.3 derives
identity confidence — never stored, because a stored degree asserts a fold
output as input and forecloses every other base.

### 5.2 Fact vs. interpretation cut

- **Anchors = computable facts** about the substrate (git objects). Strict identity.
- **Interpretive subjects** (bugs, tasks, ideas) = `Local`, weak identity.
- Interpretive subjects **ATTACH to anchors** via relations (`About` / `ManifestsAt`), **never via `SameAs`** (different kinds; you relate across kinds, `SameAs` only within the interpretive kind).
- Anchors thus serve as the **stable spine** interpretive subjects hang off of, AND as a **conduit** (§6).

---

## 6. Computable relations (HARD — specified; high-value)

Relational structure has **two sources**, and the fold consumes their union:

```
Relational inputs = Attested ⊔ Computable
```

1. **Attested** — `cites`, `SameAs`, `About`, … deliberately authored. Carries intent; can be wrong.
2. **Computable** — edges *derivable from the shared substrate with zero attestation*. Free, correct-by-construction, abundant.

### 6.1 Provider interface (pluggable, default-on)

```
trait RelationProvider {
    fn relations(&self, claims, substrate) -> Vec<ComputedEdge>;
}
```

v1 providers:
- **GitAncestry** — claims anchored to git objects inherit git's DAG ordering ⇒ supplies **causal/supersession edges for the Status poset that attestation left concurrent.**
- **GitSameFile / GitBlameOverlap** — claims touching the same file/lines are auto-related (`About`-strength), linking otherwise-disconnected cross-author work.
- (future) call-graph, type-graph, etc.

### 6.2 How it plugs in

- **The anchor layer pipes git's computable structure UP into the interpretive graph:** interpretive claims anchored to git objects inherit computable relations among those objects for free. ⇒ **Client norm: agents should anchor claims to the tightest git object they can.** (State this in the doc as a client-side behavior.)
- Computed edges carry provenance "computed by provider P"; they are **high-trust by default** (decided, not asserted) but remain a **named input** a policy can down-weight/disable.
- **`trust` records can weight computable providers exactly like authors.** Attested and computed relations live in ONE graph, weighted by ONE enrichment mechanism. ("We trust git-ancestry for supersession" is structurally identical to "we trust Ada's SameAs.")

---

## 7. Kinds & bodies

> **Implementation note (v0.12.0-beta.3).** This section drifted behind
> `src/claim.rs` and was corrected against it; the enum below now mirrors
> `ClaimKind` and `RelationKind` as shipped. Where this spec and the code
> disagree in future, the code is the artifact under review — re-derive this
> block from `src/claim.rs`, do not re-assert it.

```rust
enum ClaimKind {
    Subject,          // declares a subject exists (title, subject-kind)
    Observation,      // a finding
    Plan,             // intended approach
    Decision,         // a choice made
    Blocker,          // impediment
    Resolution,       // claims a subject resolved
    Result,           // outcome / artifact
    Status,           // explicit state assertion
    Relation,         // typed edge, see RelationKind below
    Retraction,       // supersedes a prior claim of the SAME author (§8)
    Rejects,          // trust-local suppression of ANOTHER author's claim (§8; ADR-29)
    Publication,      // marks a subject shared into a transport layer (ADR-43)
    RoleDeclaration,  // declares a DID as a named role of this workspace (ADR-58)
    Unknown,          // a kind a newer writer used that this build cannot read (ADR-44)
}

enum RelationKind {
    SameAs,        // the ONLY identity-conferring edge (§4.2)
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
    InTensionWith, // two subjects pull against each other (ADR-46)
    Supersedes,    // this subject replaces target, which is retained (ADR-80)
    Refutes,       // a citable result kills target, which stays visible (ADR-80)
}
```

**`Relation` subtypes** are the semantic edges. Only `SameAs` confers
identity (§4.2). Note that `Rejects` is **not** a `RelationKind`: it is not a
domain edge between two subjects but `Retraction`'s cross-author-aware
sibling, citing a specific claim CID, so it lives in `ClaimBody::Rejects`
(ADR-29).

**Body typing — RECOMMENDED default, flagged OPEN in §9:**
- **Closed typed union** for *structural* kinds the fold must read: `Subject`, `Status`, `Relation`, `Retraction`.
- **Opaque markdown/text payload** for *narrative* kinds: `Observation`, `Plan`, `Decision`, `Result`, `Blocker`.
- Rationale: the fold only needs to *understand* the handful of kinds that affect view state; everything else is attributed prose. Keeps the fold small.

---

## 7.1 Schema evolution (HARD — the compatibility contract)

A CID *is* a claim's identity, and the log is append-only. Both together mean
**kan cannot migrate**: a claim can never be rewritten in place, because
rewriting it produces a different claim. What kan does instead is
**permanent coexistence** — readers tolerate every historical shape, forever.
Only the disposable SQLite index is ever rebuilt. A log-rewriting migration
tool is not a deferred feature but a rejected one: history you can alter is
not what this is.

**Frozen.** `ClaimContent`'s existing fields — their names, order, types, and
encoding — may never change. Each is an input to every CID kan has ever
computed, so changing one silently invalidates all of history.

**Additive only.** A new field may be added *only* as `Option<T>` with
`skip_serializing_if = "Option::is_none"`. Measured: that produces
byte-identical encoding when the field is absent, so every claim written
before the field existed keeps its exact CID. `ClaimContent::recorded_at`
(v0.7.0-beta.1) is the first field added under this rule and is the worked
example.

**`deny_unknown_fields` applies at every level that decodes a claim, not just
the outermost.** It was originally placed on `ClaimContent` alone, and
`ClaimBody`'s `KnownBody` mirror was missed — so a claim of a *known* kind
carrying a field from a newer kan deserialized successfully, silently dropped
the field, re-encoded to different bytes, and was then reported as **altered
since it was signed**. That is precisely the failure this contract exists to
prevent, surviving one level below where the fix was applied. Any future type
that participates in decoding a claim must carry the attribute, and the test
that proves it must construct a *known* kind with an unknown field, not only
an unknown kind (ADR-48).

**Unknown kinds are preserved, not rejected or dropped.** A reader
encountering a `ClaimBody` kind it does not recognize decodes it as an opaque
claim retaining its original bytes, so it stays CID-verifiable and
signature-checkable. It may be counted, cited, and retracted; it may not be
interpreted, and it carries no status or relational meaning into the fold
(§9) — an uninterpretable claim must not influence a classification nobody
can reason about. Dropping it instead would make a newer actor's claims
silently vanish from an older actor's view of a shared tree, which is the
precise divergence §10's sharing layers exist to avoid.

**Failure must be honest.** `ClaimContent` is `deny_unknown_fields`, so an
older reader meeting a newer record fails with `unknown field` rather than
silently discarding it and then reporting a CID mismatch. The second
behavior — measured, and the reason this section exists — accuses a
legitimate claim of having been *altered since it was signed*. A tool one
version behind must say so, not impugn the record.

## 8. Retraction (RECOMMENDED default, flagged OPEN in §9)

**Option B — retraction-as-claim (palimpsest):**
- A `Retraction` claim **cites the CID it supersedes**.
- In the fold, a superseded claim is **excluded from state reduction but retained in history** (status computed as if gone; a view CAN show "X retracted Y").
- **Self-retraction is global** (an author supersedes their *own* prior claim — keyed on full `AuthorId`, §2).
- **Cross-author "retraction" is NOT possible** (you can't write to another's log). Instead, `Relation::Rejects` citing the target = a **local suppression** honored only by folds that trust the rejecter.
- True hard-delete (atproto record delete leaves *no tombstone*) remains available for genuine erasure; folds tolerate **dangling cites** (normal; handled at view layer). Distinction preserved: *overwriting* (retraction, legible) vs *erasing* (delete, gone).

---

## 9. The fold (HARD — core algorithm)

```
fold(claims: Set<Claim>, enrichment: TrustBase) -> View
```

**Properties (INVARIANTS):**
- **Deterministic:** same claim set + same enrichment ⇒ same view. (Makes SQLite index disposable, fold testable against fixtures.)
- **Input is a set (unordered); ordering is derived internally.** Intra-author order = log rev (strict, free). Cross-author order = policy over attested ⊔ computable edges (NOT an imposed global clock).
- **Reads morphisms, never mutates objects** (§4.4).

**Composition order (CORRECTNESS-CRITICAL): identity fold FIRST, then state fold over the merged class, BOTH under the SAME enrichment.**

```
render(enrichment E):
  1. IDENTITY FOLD under E → merge-classes (M-objects), cached per §4.5
  2. for each merge-class:
       STATE FOLD under E over all status-bearing claims attached to the class:
         a. order per-AuthorId by log rev
         b. build causal poset across authors:
              edges = (attested cites among status claims) ⊔ (computable edges, §6)
         c. live-set = maximal antichain (elements unsuperseded under E)
         d. classify: Settled{x} | Confirmed{x, by:[...]} | Contested{resolved:[…], open:[…]}
  3. DECATEGORIFY → FlatView for display  (late, lossy, policy-controlled;
     NEVER collapses the store — only the render)
```

**Status is an object (a poset → antichain), not a value.** Contested-vs-settled is **relative to the viewer's enrichment** (SoloTrust linearizes ⇒ never contested; PeerContested surfaces disagreement). Store keeps the full poset; render collapses under policy.

**Supersession vs contestation (from Q1/Q2 resolution):**
- **Intra-`AuthorId`:** later claim supersedes earlier (mind-changed). Strict.
- **Cross-author:** three policy tiers over the SAME poset, none intrinsic —
  1. **Contest** (default): symmetric, surface both.
  2. **Computably-ordered**: git-ancestry says one is later on the relevant object ⇒ ordered (high-trust-by-default, disableable).
  3. **Trust-ranked supersession** (opt-in): a privileged trust network lets high-trust dominate. Never baked in.

**Decategorification caching:** re-render only on `Δ(SameAs ∪ trust)` (identity) or a status-bearing claim on the class (state). Recompute is **per-merge-class, local.** Reference impl: categorical fold + late render, correctness-first; caching per above; incremental optimization is post-correctness.

---

## 10. Storage & transport

- **Source of truth:** per-author signed claim log = an atproto-style **signed MST over CBOR records**. Your own on local disk; others' arrive read-only via sync. *Local-only and atproto-ready are the SAME on-disk artifact* — not two backends.
- **SQLite = pure disposable projection** of the union of subscribed logs, folded. Delete and rebuild anytime. **This deletes v1's integrity/hydrate/compact entirely** — there is one truth and the index isn't it.
- **Transport trait (build order matters):**
  ```
  trait Transport { fn publish(&self, &[Claim]); fn subscribe(&self, &[Did]) -> Stream<Claim>; }
  ```
  - `LocalOnly` (no-op) — **BUILD FIRST, SHIP FIRST.** Sync killed v1; do not start there.
  - `GitTree` — the repo's own committed tree as a sharing layer. No server, no wire protocol, no network: signed claims are written into a tracked `.claims/` and arrive from other actors by an ordinary `git pull`. The cheapest possible first non-local transport, and the first thing to exercise the multi-actor fold with zero infrastructure (ADR-43).
  - `HostedRelay` — private teams, E2E-able. The monetizable one.
  - `AtProto` — PDS + firehose; public ecosystem; lexicons = evangelism.
- **AppView = the fold.** Choosing which actors to index = choosing the covering family = the Grothendieck topology. Different AppViews over the same claims = different topoi.

### 10.1 Read/write surface and authority

Authority, source, medium, scope and projection are independent axes. “One
source of truth” above rejects SQLite as authority; it does **not** mean there
is one privileged physical file. A signed kan claim remains authoritative kan
data when carried in the local CAR, a tracked `.claims/` tree, a replica, or an
atproto repository. Those are different substrate connections with different
availability and ownership, not derived copies of one privileged medium.

Every input to a kan view belongs to exactly one authority class:

- **`authoritative-kan`** — values whose semantics and validation kan owns:
  signed claims on any claim substrate, identity roots and selectors, and
  repository- or system-scoped kan configuration.
- **`authoritative-other`** — values kan reads whose semantics another system
  owns. Git commits, objects, ancestry and filesystem facts are the current
  example. Their provider remains attributed at the boundary.
- **`derived`** — deterministic outputs over declared authoritative inputs:
  overlay and SQLite rows, folds, caches, computed edges, and rendered views.
  Persisting one for performance never makes it evidence for itself.

Git crosses this boundary in two roles. Git's own objects and relationships
are `authoritative-other`. Signed kan CBOR claims published inside `.claims/`
are `authoritative-kan`; Git is only their carrier. When kan discovers a Git
repository it automatically supplies the GitTree substrate connection as
repository-scoped kan configuration. Future connection manifests may add
replica or atproto media without changing the authority of the claims they
carry.

The exhaustive machine-readable declaration is
`tests/fixtures/read-write-surface.tsv`. Structured storage is declared per
persisted field or column; an opaque container may use `*` only where an
independent format oracle already exists. Each row names status, authority,
source kind, scope, artifact, value, writer, reader, validation/selection/
derivation rule, lifecycle, and governing design. Planned connections prove
the vocabulary can represent future media but do not count as implemented.

`tests/surface_conformance.rs` constructs the implementation inventory
independently and compares it with the committed table in both directions. It
introspects SQLite at runtime, takes filesystem/keychain artifact facts from
their persistence-owning modules, requires every concrete filesystem mutation
site to name its catalog artifact, and recomputes disposable projections from
authoritative inputs. The mutation-site check is path-syntax-independent: a
literal, constant, formatted path, or helper call cannot introduce a write
without declaring its surface. Compiler-resolved policy confines raw mutation
APIs to the persistence facade, including when an import is aliased. An
invocation of that facade requires a typed surface capability whose artifact
set is checked against the catalog. An implemented value with no row and a row
with no implemented owner are both errors. The oracle is semantic
recomputation from raw inputs, never agreement between two caches.

Reference recomputation is intentionally correctness-first. If it becomes too
expensive even for the bounded CI fixtures, that is the event requiring a new
recorded independent-oracle decision. The check must not be ignored, weakened
to trust the projection, or silently moved off the ordinary test path; this is
the operational boundary of the tension between
`telos/performance-at-scale` and `telos/raw-data-and-projections`.

### 10.2 Public Lexicons and version-aware views

[RFC 2](../rfcs/2-kan-uri-scheme.md) defines the implemented
`kan-claim-v1` conversion and five draft Lexicons. [RFC 3](../rfcs/3-authoritative-lexicon-publication.md),
currently in Review, proposes the next public contract: stable
`tools.kan.claim`, an explicit codec discriminator, an open typed-content
union, append-only `tools.kan.codec` and `tools.kan.lens` registers, and a
portable version-aware AppView.

Until RFC 3 is accepted and implemented, RFC 2 and the shipped
`kan-claim-v1` behavior remain current. Implementation order, repository
ownership, and release qualification are tracked in
[`docs/ROADMAP.md`](ROADMAP.md); planning issues do not override RFC status.

---

## 11. v1 scope fence

**BUILD (the spine):**
- Claim model, CID/DAG-CBOR, signing.
- `LocalOnly` transport. One human, one or more local agents, one repo.
- Categorical identity fold (M-objects, witness-retaining, clique-cached) + `SoloTrust` and `PeerContested` reference enrichments.
- Anchors (git-derived) + admissibility invariant.
- `GitAncestry` + `GitSameFile` computable providers.
- State fold (poset → antichain → classify) + late decategorify render.
- CLI + MCP server. **Budgeted context assembly** (the actual product: query the claim graph under a token budget → maximal-value claim set for an agent's window).
- SQLite disposable index.

**NOT PART OF THE LOCAL SPINE:**
- Sync of any kind (HostedRelay, AtProto), lexicons, firehose.
- TUI, web dashboard, VS Code extension.
- More trust *enrichments* than the two reference bases (`Solo` and `PeerContested`). Language rule-files. Config presets. Enforcement hooks (prefer affordance over control — legibility, not blocking).
- Incremental/streaming fold (reference recompute first).

This is a boundary around the local-spine milestone, not a permanent ban.
Separately governed follow-on work is listed in `docs/ROADMAP.md`, and public
protocol commitments remain subject to the RFC lifecycle.

> **Implementation note (v0.12.0-beta.3).** This bullet used to read ">2
> trust policies". `TrustBase` now has three variants — `Solo`,
> `PeerContested`, and `Local` (the default since v0.11, `ADR-83`) — but that
> is not a third *enrichment*: `Local` is `PeerContested` over "every author
> in this log", i.e. a way of populating the same [0,1]/quantale base, not a
> new base of the kind §4.3 caps. The fence is unchanged in spirit (two
> reference enrichments); the wording was corrected so the count matches the
> code. `src/fold/trust.rs` is the artifact of record.

**Paradigm note:** replace v1's **enforcement** (hooks that BLOCK actions without an issue) with **affordance** (let agents act; make the record complete and legible; surface drift in the graph as data). Control-for-stability is the freeze.

---

## 12. Two OPEN choices for the design flow

1. **Body typing (§7):** closed union for {Subject, Status, Relation, Retraction} + opaque markdown for narrative kinds. *Recommended; confirm or override.*
2. **Retraction (§8):** Option B (retraction-as-claim, palimpsest; self-retraction global; cross-author = local Rejects), hard-delete reserved for true erasure. *Recommended; confirm or override.*

---

## 13. Glossary of the load-bearing invariants (for review scanning)

- **No shared mutable state.** Each actor appends only to its own log.
- **Conflicts are read-time information, not write-time errors.**
- **The fold reads morphisms; never mutates objects.** No operation destroys a subject.
- **Identity is a witnessed weak-equivalence object M(A,B), enriched by per-viewer trust.** Never a quotient.
- **Strict identity (anchors) only where error is impossible by construction.**
- **Attested ⊔ Computable relations; git structure is a free, high-trust, default-on input.**
- **Identity fold before state fold, same enrichment; decategorify only at the render boundary.**
- **One source of truth (the signed log); SQLite is a disposable projection.**
- **Local-only first. Sync never reintroduces shared mutable state.**
