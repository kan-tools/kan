# kan — agent working notes

You are building `kan`: a local-first, provenance-preserving memory substrate for
AI agents, in Rust. This file orients you; the authoritative design is in `docs/`.

## Read first, in order
1. `docs/HANDOFF.md` — orientation, vocabulary, scope, the two open choices.
2. `docs/SPEC.md` — AUTHORITATIVE data model, identity model, anchors, computable
   relations, the fold algorithm, storage, and the v1 scope fence. If anything
   here conflicts with SPEC.md, SPEC.md wins.
3. `docs/SETUP-TODO.md` — the phased build checklist.

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

Explicitly OUT for v1: sync/atproto/lexicons, TUI, web dashboard, editor
extensions, >2 trust policies, enforcement hooks, incremental fold. The
local-only spine (this section) shipped through v0.3.0-beta.1; sync now has
a concrete staging plan (`.design/sync-layer-architecture-and-staging.md`,
`docs/DECISIONS.md` ADR-35) — see that doc before starting any sync-adjacent
work rather than treating "out for v1" as still open-ended.

## House rules
- Rust. Use `atproto-repo` + `atproto-dasl` for MST/CAR/CID (`atrium-crypto`
  for signing), so local-only and future atproto are the same on-disk
  artifact. **Not** `atrium-repo` — ADR-1 originally picked it, but ADR-11
  found a confirmed data-loss bug in its MST (filed upstream:
  atrium-rs/atrium#343) and ADR-12 records the switch. Before trusting any
  storage-layer crate here again: stress-test it the way ADR-11/12 did
  (sequential inserts, check full reachability after every single one, not
  just at the end) before building on it, not after.
- Correctness before performance. The reference fold recomputes; caching and
  incremental folds are follow-ups, optimized only against passing fixtures.
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
Declared in four AX-driven phases (`docs/DECISIONS.md` ADR-32) — `kan --help`
reflects this order directly, so treat it as the source of truth over this
line if they ever drift:
- Recording: `observe | plan | decide | block | resolve | result`
- Structuring: `same | relate | mark`
- Correcting: `retract | reject`
- Recalling: `show | status | issues | context [--budget N]`
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
`docs/DECISIONS.md` ADR-18.

That companion tool now exists: **`day`** (`kan-tools/day`, on crates.io) —
the structured *process* layer to kan's structured *knowledge* layer. It
holds teloi, process atoms, and drift assessment entirely as conventions
over kan's existing verbs (`telos/<slug>` and `atom/<slug>` subjects), needs
no kan data-model change, keeps no store of its own, and shells out to the
`kan` binary rather than linking it. ADR-42 records what its existence
settles — including the two things it puts back on kan: `RelationKind` has
no "in tension with" edge (a new variant, so kan's to own), and day will
soon write through kan's CLI, making kan's write-verb ergonomics a
dependency of a program rather than only of agents. Send a process/workflow
feature request there, not here.

## Design docs
Feature-level design work goes through `/design` (see `.claude/commands/design.md`)
and lands in `.design/<slug>.md` before implementation — this is kan's own
crosslink-free descendant of that workflow, adapted to record into kan's own log
(`kan observe`/`plan`/`decide`) once the CLI exists, rather than a shared store.

## Provenance
Clean-room successor to `crosslink`. Build forward from SPEC.md; consult crosslink
only as lessons-learned (its sync model is what we're fixing), not a codebase to port.

## Workflow: one PR per milestone
Each milestone — the original spine (`.design/kan-spine.md`'s M1–M6 roadmap)
and every release since (`.design/v0.2-milestone.md`, `v0.3-milestone.md`,
`v0.4-milestone.md`, …) — is its own branch and PR, not a direct commit to
`main` — branch off `main`, commit, push, `gh pr create`, wait for CI
(`.github/workflows/ci.yml`) to go green, then `gh pr merge --merge
--delete-branch` (regular merge, not squash, so the milestone's internal
commits stay visible in history). Keeps each PR's diff scoped to exactly one
milestone. A milestone doc frequently breaks into several requirement-scoped
PRs (see any `.design/vX.Y-milestone.md`'s own PR breakdown) — each still
gets this same branch → PR → CI → merge treatment individually, and if two
PRs both land new `docs/DECISIONS.md` ADR entries at the tail of the file
before either merges, expect (and resolve, don't avoid) a same-spot merge
conflict — reorder by ADR number, don't drop either entry.

## Workflow: release
Bump `Cargo.toml`'s `version` on `main`, then push a tag matching `v*.*.*`
(e.g. `v0.1.1-beta.1`) — `.github/workflows/release.yml` re-verifies
build/test/clippy/fmt, checks the tag matches `Cargo.toml`'s version, and
publishes to crates.io via the `crates-io` GitHub Environment (tag-restricted
to `v*.*.*` as a second guard beyond the workflow's own trigger filter).
Requires a `CARGO_REGISTRY_TOKEN` secret scoped to that environment (`gh
secret set CARGO_REGISTRY_TOKEN --env crates-io`, never through a chat
session — it's a credential Claude Code should never see). See ADR-19 for
the version-scheme/trigger rationale and ADR-20 for the environment (and the
required-reviewer gate that isn't available on `kan-tools`'s current GitHub
plan).
