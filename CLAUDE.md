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
extensions, >2 trust policies, enforcement hooks, incremental fold.

## House rules
- Rust. Use the `atrium-rs` crate family (`atrium-repo`, `atrium-crypto`,
  `atrium-identity`) for MST/CAR/CID/signing, so local-only and future atproto
  are the same on-disk artifact — see `docs/DECISIONS.md` ADR-1 for why this
  was chosen over `atproto-repo`, and ADR-8 for the confirmed API fit plus a
  known gap (no public commit-chain walking) worth revisiting if it bites again.
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
kan observe | plan | decide | resolve | same | show | issues | status |
session start/end | context [--budget N]

## Design docs
Feature-level design work goes through `/design` (see `.claude/commands/design.md`)
and lands in `.design/<slug>.md` before implementation — this is kan's own
crosslink-free descendant of that workflow, adapted to record into kan's own log
(`kan observe`/`plan`/`decide`) once the CLI exists, rather than a shared store.

## Provenance
Clean-room successor to `crosslink`. Build forward from SPEC.md; consult crosslink
only as lessons-learned (its sync model is what we're fixing), not a codebase to port.

## Workflow: one PR per milestone
Each spine milestone (see `.design/kan-spine.md`'s M1–M6 roadmap) is its own
branch and PR, not a direct commit to `main` — branch off `main`, commit, push,
`gh pr create`, wait for CI (`.github/workflows/ci.yml`) to go green, then
`gh pr merge --merge --delete-branch` (regular merge, not squash, so the
milestone's internal commits stay visible in history). Keeps each PR's diff
scoped to exactly one milestone.
