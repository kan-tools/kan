# kan — Repo Bootstrap Packet

*Drop-in seed for the `kan-tools/kan` repo. Contains: the `README.md` to paste, a `CLAUDE.md` to orient the coding agent, the `docs/` you should copy in, and the first-commit sequence. Split the sections into their files and you're building.*

---

## Files to place in the repo

```
kan/
├── README.md            ← §1 below
├── CLAUDE.md            ← §2 below (Claude Code reads this automatically)
├── LICENSE              ← MIT (or MIT OR Apache-2.0)
├── Cargo.toml           ← the reserved 0.0.0 stub, promote as you build
├── rust-toolchain.toml  ← pin the toolchain
├── justfile             ← test / lint / fmt / run
└── docs/
    ├── SPEC.md          ← copy of agent-memory-substrate-spec.md (AUTHORITATIVE)
    ├── HANDOFF.md       ← copy of kan-design-handoff.md (orientation)
    └── SETUP-TODO.md    ← copy of kan-dev-setup-todo.md (phased checklist)
```

---

## §1 — `README.md`

```markdown
# kan

**Local reasoning, global coherence — memory for AI agents.**

Where `git` versions your code, `kan` remembers your reasoning. Each agent keeps
its own signed, append-only record of what it observed, planned, decided, and
resolved — and `kan` folds those local records into one coherent view on demand,
without a central authority deciding what's true.

Nothing is overwritten. Nothing is flattened. Nothing is lost.

## Why

AI coding agents forget everything between sessions, and coordinating several of
them means reconciling contradictory state. Most tools solve this with a shared,
mutable store and locks — which is exactly where things break. `kan` takes the
opposite approach: **every actor appends only to its own log; nothing mutates
anyone else's.** Conflicts stop being write-time errors and become read-time
information. All the intelligence lives in the *fold* — a deterministic reduction
from many local logs into a coherent view, parameterized by whom you trust.

## Properties

- **Local-first** — works offline, solo, one machine, no server.
- **Provenance-preserving** — every claim is signed and carries what it was
  derived from. The record of reasoning is auditable end to end.
- **No forced consensus** — many agents, many local truths, glued into a shared
  picture while their differences are preserved (or surfaced, when they conflict).
- **Append-only** — the past is never destroyed; views are computed, not stored.

## Status

Early. Building the local-only spine first (one human, one-or-more agents, one
repo, no sync). Sync, the atproto layer, and the shared ecosystem come after the
core proves out. See `docs/SETUP-TODO.md`.

## Name

`kan` is the Kan extension: the universal construction that builds the best global
object from local data along a map. That is, more or less, the whole job.

## License

MIT
```

---

## §2 — `CLAUDE.md` (orients any Claude Code session in this repo)

```markdown
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
- Rust. Prefer the `atproto-repo` crate for MST/CAR/CID so local-only and future
  atproto are the same on-disk artifact (evaluate build-on vs roll-own; note the
  decision).
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

## Provenance
Clean-room successor to `crosslink`. Build forward from SPEC.md; consult crosslink
only as lessons-learned (its sync model is what we're fixing), not a codebase to port.
```

---

## §3 — First-commit sequence

1. `git init`, add `LICENSE`, `README.md` (§1), `CLAUDE.md` (§2).
2. Copy the three reference docs into `docs/` (rename as in the tree above).
3. Add `rust-toolchain.toml` (pin stable), a `justfile` (`test`/`lint`/`fmt`/`run`), and CI (build + test + clippy on push).
4. Commit: `chore: bootstrap kan — spec, agent notes, scaffolding`.
5. Open a Claude Code session in the repo. It reads `CLAUDE.md` → `docs/`. Ask for the **initial design pass** deliverables (crate layout, core types, `fold` signature + 4-stage pipeline, `RelationProvider` trait + git stubs, fixtures test plan, CLI surface, and resolutions for the two open choices).
6. Build Phase 3 (spine) with Phase 4 (fixtures) alongside — never after.

## §4 — Definition of done for the bootstrap
- Repo reads as intentional at a glance (README + name rationale).
- A fresh Claude Code session can orient itself from `CLAUDE.md` alone.
- `just test` / `just lint` run clean on an empty scaffold.
- The two open choices (body typing, retraction) are resolved and recorded in `docs/` or an ADR.
```
