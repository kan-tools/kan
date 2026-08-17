# kan — agent working notes

You are building `kan`: a local-first, provenance-preserving memory substrate for
AI agents, in Rust. This file orients you; the authoritative design is in `docs/`.

## Read first, in order
1. `docs/HANDOFF.md` — **historical**: the original bootstrap brief, kept as
   a record of the starting point. Useful for the vocabulary map; its scope
   and open-choices sections are long resolved. Read it for background, not
   for current state.
2. `docs/SPEC.md` — AUTHORITATIVE data model, identity model, anchors, computable
   relations, the fold algorithm, storage, and the v1 scope fence. If anything
   here conflicts with SPEC.md, SPEC.md wins.
3. `docs/ROADMAP.md` — the current shipped baseline, active RFC 3 issue graph,
   repository boundaries, and document precedence.
4. `docs/SETUP-TODO.md` — the historical bootstrap checklist, with its active
   network phases redirected to the current roadmap.

## The one non-negotiable invariant
The fold reads morphisms; it never mutates objects. **No operation destroys a
subject.** Identity and status are computed objects (path-spaces / posets),
collapsed to flat values only at the display boundary, never in the store.
If a change would let one actor's write mutate or destroy another's data, it's wrong.

## What to build first (the spine — do NOT build the cathedral)
Local-only, one human, one-or-more local agents, one repo, no sync:
Claim + DAG-CBOR CID + signing → local append-only log (source of truth) →
disposable SQLite index → the fold (identity-before-state, same enrichment,
decategorify only at render) → git anchors + computable relation providers →
CLI + MCP server with budgeted context assembly.

Explicitly OUT for the local spine: sync/atproto/lexicons, TUI, web dashboard,
editor extensions, >2 trust enrichments, enforcement hooks, incremental fold.
The local-only spine shipped through v0.3.0-beta.1. Do not treat that historical
scope fence as an open-ended ban or use ADR-35's old version table as the
current plan. Read `docs/ROADMAP.md` first for sync-adjacent work; public
ATProto publication is governed by RFC 3 (currently Review) and issues
#235–#241 under epic #29. The older sync staging design remains context for the
separate HostedRelay track.

## House rules
- Rust. Use `atproto-repo` + `atproto-dasl` for MST/CAR/CID (`atrium-crypto`
  for signing), so local-only and future atproto are the same on-disk
  artifact. **Not** `atrium-repo` — ADR-1 originally picked it, but ADR-11
  found a confirmed data-loss bug in its MST (filed upstream:
  atrium-rs/atrium#343) and ADR-12 records the switch. Before trusting any
  storage-layer crate here again, run **both** checks before building on it,
  not after:
  1. **Reachability** (ADR-11/12) — sequential inserts, check full
     reachability after every single one, not just at the end.
  2. **Conformance** (ADR-90) — compare the artifact against an *independent
     implementation*, not against our own reading of the spec. Reachability
     alone is not enough: `atproto-repo` 0.14.5's MST never split, losing
     nothing while writing a repo no conformant implementation agrees with
     (kan#204) — a quadratic write cliff and a wrong root CID that the
     reachability rule passes cleanly. `tests/mst_conformance.rs` is the
     working example; `src/mst/` is what it cost — kan now owns the MST
     outright, because a `[patch.crates-io]` fix reaches CI but never reaches
     `cargo install kan`.
- Correctness before performance. The reference fold recomputes; caching and
  incremental folds are follow-ups, optimized only against passing fixtures.
- A persistence change is also a surface-contract change. Update
  `tests/fixtures/read-write-surface.tsv`, the typed capability at the mutation
  site, and `tests/surface_conformance.rs` together; derived media never become
  authority merely because they are persisted or fast.
- The fold is a pure, deterministic function of (claim set, enrichment). Guard this.
- Affordance, not enforcement — agents act; the record is made legible; drift
  surfaces in the graph as data. Do NOT port crosslink's blocking hooks.
- One surface: CLI + MCP. No second/third UI.
- Provenance is sacred: never fabricate or drop `cites` edges.

## Smell test
The local-only path must be *dramatically* simpler than the multi-actor path
(one log, all subjects Local, no SameAs stitching, no contest stage, latest-wins).
If it isn't, the abstraction is wrong — stop and reconsider.

## CLI vocabulary (git-like, verb-first)
Declared in four AX-driven phases ([`ADR-0032`](adrs/32-verb-lexicon-reorganized-by-ax-phase-mcp-tool-surface-catches-up-to-the.md)) — `kan --help`
reflects this order directly, so treat it as the source of truth over this
line if they ever drift:
- Recording: `observe | plan | decide | block | resolve | result`
- Structuring: `same | relate | mark`
- Correcting: `retract | reject`
- Recalling: `show | status | issues | context [--budget N]`
- Sharing: `publish <subject>` — writes the subject's signed claims into the
  tracked `.claims/` directory (ADR-43). Writes files; never runs git.
- Outside the four phases (setup/tooling, not a claim-graph verb): `mcp [install]`

## Scope boundary: kan vs. `day`, the companion tool
kan owns a feature iff it needs a new/existing `ClaimBody`/`ClaimKind`/
`Anchor`/`RelationKind` variant, or is a pure read/fold over the claim graph
that needs no memory of *when* or *why* to call it. If a feature is buildable
entirely as a calling convention over existing primitives (subject naming,
`cites`, `artifacts`) with no data-model change, it's process/workflow and
belongs in the companion tool that consumes kan via CLI/MCP — not a new mode
of kan itself. Full rationale and worked examples (why `kan session
start/end` was removed, why a proposed vector index still belongs in kan):
[`ADR-0018`](adrs/18-the-kan-companion-tool-scope-boundary-kan-session-removed.md).

That companion tool now exists: **`day`** (`kan-tools/day`, on crates.io) —
the structured *process* layer to kan's structured *knowledge* layer. It
holds teloi, process atoms, and drift assessment entirely as conventions
over kan's existing verbs (`telos/<slug>` and `atom/<slug>` subjects), needs
no kan data-model change, keeps no store of its own, and shells out to the
`kan` binary rather than linking it. ADR-42 records what its existence
settles — including the two things it put back on kan: an "in tension with"
edge (`RelationKind::InTensionWith`, since shipped — ADR-46), and day
writing through kan's CLI, making kan's write-verb ergonomics a dependency
of a program rather than only of agents. Send a process/workflow feature
request there, not here.

## Process lives in `day`, not here
**This file describes kan the artifact. It does not describe how work
proceeds.** Process — designing, building, reviewing, opening a PR, cutting a
release — is declared as `day` process atoms, which are `atom/*` claims in
kan's own log and are injected into each session by day's hook. Read them
there (`kan show atom/<slug>`), revise them there (`day atom declare`), and do
not restate them here.

The reason is the same one the identity work keeps proving: two
implementations of one fact drift. This file and `atom/pull-request` both
described the one-PR-per-milestone workflow in their own words, and
`atom/release` and this file both described the release ritual. Everything
those sections held now lives in `atom/adversarial-review`,
`atom/generative-build`, `atom/pull-request` and `atom/release`, which is also
where `day doctor` can check that the vocabulary composes and `day status` can
say where the work sits.

Feature-level design work still goes through `/design` and lands in
`.design/<slug>.md` before implementation; that atom is `atom/design`.

## Provenance
Clean-room successor to `crosslink`. Build forward from SPEC.md; consult crosslink
only as lessons-learned (its sync model is what we're fixing), not a codebase to port.
