# kan — Design Handoff Brief

> **Historical — this is the original bootstrap brief**, written before any
> code existed, and kept as the record of what the project looked like at the
> start. Its "first build", "two OPEN choices", and "deliverables expected
> from the initial design pass" sections were all resolved years of decisions
> ago; it predates the `Transport` layer, the sharing layer, the schema
> contract, and the companion tool `day` entirely.
>
> **For current orientation read `docs/SPEC.md` (authoritative), then
> `adrs/README.md` (why things are the way they are), then `.design/` for
> in-flight work.** For current *state* rather than design, `kan show spine`
> in this repo is the entry point.

*Hand this to the initial Claude Code design session, together with `agent-memory-substrate-spec.md` (the full data-model + algorithm spec, which is authoritative). This brief orients the session, fixes vocabulary, and scopes the first build.*

---

## What kan is (one paragraph)

**kan** is a local-first, provenance-preserving memory substrate for AI coding agents (and the humans driving them). Where `git` versions the *code*, `kan` accumulates the *reasoning* — every observation, plan, decision, and result an agent produces — as an append-only log of signed, content-addressed **claims**, and folds those claims into views (issues, sessions, knowledge, status) on demand. It is the successor to `crosslink`, rebuilt to eliminate the shared-mutable-state that made crosslink's multi-agent sync brittle. **Rust. CLI-first. MCP server for agents.** The name is the Kan extension: the tool's core act is reconstructing the best global view from the local fragments you have.

## Why it exists / what it replaces

crosslink (the predecessor) treated the **issue** as primitive and maintained **two sources of truth** (SQLite + git coordination branches) reconciled by **distributed locks over an eventually-consistent log**. That produced chronic sync pain, plus integrity/hydration/compaction machinery and clock-skew hacks — all the tax of shared mutable state. **kan deletes shared mutable state:** each actor appends only to its own signed log; nothing mutates anyone else's; conflicts become *read-time information* rather than *write-time errors*. All intelligence moves into the **fold** (a deterministic reduction from logs + subscriptions + trust policy → view).

## The one non-negotiable invariant

> **The fold reads morphisms; it never mutates objects. No operation in the system destroys a subject.** Identity and status are computed *objects* (path-spaces / posets), collapsed to flat values only at the display boundary, never in the store.

This is the property whose absence sank crosslink. If a design choice would let one actor's write mutate or destroy another actor's data, it is wrong.

---

## Reading order for the session

1. **This brief** — orientation + scope + vocabulary.
2. **`agent-memory-substrate-spec.md`** — authoritative data model, identity model, anchors, computable relations, the fold algorithm, storage, and the v1 scope fence. Sections marked HARD are settled; §12 has two OPEN mechanical choices to resolve during design.
3. Everything below in this brief is *supporting* — if it conflicts with the spec, the spec wins.

---

## Vocabulary / naming map (make the code speak one language)

Use these names consistently in the code. The CLI verb-space should feel like `git`.

| Concept | Name in code | CLI |
|---|---|---|
| The atomic assertion | `Claim` | — |
| Author = (human account, optional agent key) | `AuthorId { did, agent: Option<AgentKey> }` | — |
| A thing claims are about | `Subject` (`Local` \| `Anchor`) | — |
| Computable, coordination-free subject (git object) | `Anchor` | — |
| The one identity-conferring edge | `Relation::SameAs` | — |
| The identity path-space between two subjects | `IdentityObject` / `M(a,b)` | — |
| Per-viewer trust / enriching base | `TrustBase` / `Enrichment` | — |
| The reduction logs+trust → view | `fold` | — |
| Rendering the folded (categorical) view to flat display | `render` | — |
| Append a claim | — | `kan claim` / typed: `kan observe`, `kan plan`, `kan decide`, `kan resolve` |
| Assert identity | — | `kan same <a> <b>` |
| Inspect a subject / issue | — | `kan show <subject>` |
| List the folded view | — | `kan issues`, `kan status <subject>` |
| Session lifecycle | — | `kan session start` / `kan session end --notes` |
| Context assembly for an agent | — | `kan context [--budget N]` |

CLI design principle: **terse, git-like, verb-first.** Agents call these; humans read them. Favor `kan observe "..."` over ceremony.

---

## The first build (spine only — do NOT build the cathedral)

Target for the initial pass, in dependency order:

1. **Claim model + content addressing.** `Claim` struct (spec §1), DAG-CBOR canonicalization, CID over content-excluding-sig, signing. `cites` holds CIDs (backward-only ⇒ CID-DAG acyclic).
2. **Local append-only log** = the source of truth (an atproto-style signed record collection on local disk). One human, one-or-more local agents, one repo.
3. **Disposable SQLite index** = pure projection of the log; rebuildable from scratch; nothing can be "out of integrity."
4. **The fold** (spec §9) — categorical, deterministic, testable against fixtures:
   - identity fold (witness-retaining, NOT plain union-find; clique-cached per spec §4.5) with `SoloTrust` and `PeerContested` reference enrichments;
   - state fold (poset → maximal antichain → classify `Settled | Confirmed | Contested`);
   - identity **before** state, same enrichment; decategorify only at `render`.
5. **Anchors** (git-derived: Workspace/Commit/Blob/FileAt/LineRangeAt) + the admissibility invariant (strict identity only where error is impossible by construction).
6. **Computable relation providers** `GitAncestry` + `GitSameFile` (default-on, high-trust, named/disableable).
7. **CLI** (verb-space above) + **MCP server** exposing claim-append and **budgeted context assembly** (the actual product: query the claim graph under a token budget → maximal-value claim set for the agent's window).

**Explicitly OUT of the first build** (spec §11): all sync (HostedRelay, AtProto, firehose, lexicons); TUI; web dashboard; VS Code extension; >2 trust policies; enforcement hooks (prefer affordance over control); incremental/streaming fold (reference-recompute first).

**Sanity check the session must preserve:** the local-only, single-actor path must be *dramatically simpler* than the multi-actor path — one log, all subjects `Local`, no `SameAs` stitching, no contest stage, `SoloTrust`, latest-wins. If local-only isn't trivial, the abstraction is wrong.

---

## The two OPEN choices (spec §12) — resolve during design, recommended defaults given

1. **Body typing:** RECOMMEND closed typed union for the structural kinds the fold reads (`Subject`, `Status`, `Relation`, `Retraction`) + opaque markdown payload for narrative kinds (`Observation`, `Plan`, `Decision`, `Result`, `Blocker`). Keeps the fold small.
2. **Retraction:** RECOMMEND Option B (retraction-as-claim, palimpsest): a `Retraction` cites the superseded CID; superseded claims are excluded from state reduction but retained in history; self-retraction is global (keyed on `AuthorId`), cross-author "retraction" is a `Relation::Rejects` honored only by folds that trust the rejecter; hard-delete reserved for true erasure (folds tolerate dangling cites).

---

## Design constraints / house rules for the session

- **Rust.** Editions/toolchain per the repo. Prefer `atproto-repo` crate (MST/CAR/CID) so local-only and future atproto are the *same on-disk artifact*, not two backends.
- **Correctness before performance.** The reference fold recomputes; caching (spec §4.5 two-tier invalidation) and incremental folds are follow-ups. Optimize only against passing fixtures.
- **The fold must be a pure, deterministic function of (claim set, enrichment).** This is what makes the SQLite index disposable and the whole thing testable. Guard it.
- **Affordance, not enforcement.** Do not port crosslink's blocking hooks. Agents act; the record is made complete and legible; drift surfaces in the graph as data.
- **Ship one surface.** CLI + MCP. No second/third UI in v1.
- **Provenance is sacred.** Every claim carries author + cites; `cites` is the mesh; never fabricate or drop provenance edges.

---

## Deliverables expected from the initial design pass

- A crate layout / module plan (`kan` core lib + CLI bin + MCP server; note where `atproto-repo` and SQLite sit).
- Concrete Rust types for `Claim`, `AuthorId`, `SubjectRef`, `Anchor`, `ClaimKind`, `Relation`, `TrustBase`.
- The `fold` signature + the four-stage pipeline (gather → order → reduce → contest) with the identity/state split and the `render` boundary.
- The `RelationProvider` trait + `GitAncestry`/`GitSameFile` stubs.
- A fixtures-based test plan for the fold (local-only trivial case first; then a two-actor contested-status fixture; then a `SameAs` merge + retraction-split fixture).
- Resolutions (or explicit deferrals with rationale) for the two OPEN choices.
- The `kan` CLI command surface (subcommands + flags) matching the vocabulary map.

---

## Provenance note (context the session should have)

This is a clean-room successor to crosslink, built on a fresh namespace with no dependency on the prior org. Design *forward* from this spec; consult crosslink only as a source of lessons-learned (what its sync model got wrong), not as a codebase to port. The claim taxonomy (observation/plan/decision/blocker/resolution/result) is inherited from crosslink's typed comments — that instinct was good and is promoted to the core ontology here.
