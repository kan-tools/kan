# ADR 14: M4b: state fold, git-genesis anchors, `RelationProvider`s via shelling out to `git`

- Status: Not recorded contemporaneously
- Date: 2026-07-18
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-14

## Context

Not recorded contemporaneously.

## Decision

Not recorded contemporaneously.

## Rationale

Not recorded contemporaneously.

## Consequences

Not recorded contemporaneously.

## Evidence

Not recorded contemporaneously.

## Alternatives considered

Not recorded contemporaneously.

## Supersession

Not recorded contemporaneously.

## Historical record

**Date:** 2026-07-18
**Decision:**
- **Git access is the `git` binary, shelled out to (`src/git.rs`'s
  `GitSubstrate`), not a library** (`git2`/`gitoxide`). Kan already requires
  running inside a git checkout (`.kan/` sits beside `.git/`, ADR-3), so
  `git` is always on hand; the only plumbing needed (`rev-list
  --max-parents=0`, `merge-base --is-ancestor`) is two read-only commands.
  Vendoring a git implementation for that would be the cathedral
  `CLAUDE.md`'s smell test warns against.
- **`Anchor::Workspace(GenesisCid)` is now real**: sha256 of the repo's
  sorted root-commit SHA(s) (`GitSubstrate::genesis`), replacing M3's
  placeholder (a hash of the checkout's canonical filesystem path, which
  differed per clone and was never portable — the doc comment on
  `cli::context::workspace_anchor` said so explicitly). This changes the
  `workspace` value on every claim; old local `.kan/` dogfooding data is
  unaffected in practice since nothing reads/filters on `workspace` yet.
- **`RelationProvider` (`src/relations.rs`)**: `GitAncestry` (commit
  ancestry between claims' `ArtifactRef::Commit`/`FileAt`/`LineRangeAt`
  shas) and `GitSameFile` (shared `FileAt`/`LineRangeAt` path — `About`
  strength, no ordering). Both infallible (`Vec<ComputedEdge>`, not
  `Result`) per `docs/SPEC.md` §6.1's sketch: a provider that can't
  determine an edge just omits it rather than failing the whole fold —
  computed edges are a bonus signal, not load-bearing the way the claim log
  is.
- **State fold (`src/fold/state.rs`)**: per merge-class, `Status`-kind
  claims reduce to one live position per author (strict intra-author
  supersession, §9), then classify: all-agree ⇒ `Confirmed`; exactly one
  live position (either only one author, or cross-author disagreement fully
  resolved by domination) ⇒ `Settled`; unresolved disagreement ⇒
  `Contested { resolved, open }`. Domination = an attested `cites` edge or a
  computed `Ancestry` edge from another live position — §9's
  "computably-ordered" tier folded into the same dominance check as attested
  ordering, since both are "this position is aware of / comes after that
  one," not two separate code paths.
- `kan resolve <subject> "<text>"` appends `ClaimBody::Resolution` — a
  narrative claim (never poset-classified), distinct from `ClaimBody::Status
  { value: Resolved }` (the structural kind `fold::state` reduces). v1's CLI
  vocabulary (`docs/HANDOFF.md`, REQ-13) has no verb for authoring `Status`
  claims directly; `fold::state::classify` is exercised at the library/test
  level (AC-4, AC-10) and wired into `kan status`'s rendering, ready for
  whichever future surface (MCP tool, `kan same`-style verb) starts emitting
  `Status` claims.
**Why:** REQ-4/REQ-5/REQ-6/REQ-7 (`.design/kan-spine.md`) and `docs/SPEC.md`
§5/§6/§9 specify all of this as HARD; M4a shipped the identity fold half,
this closes the state-fold half plus the anchor/provider machinery it
depends on.
**Consequences:** `kan` now hard-requires an actual git repository with at
least one commit to run at all (`Workspace::open` calls `GitSubstrate::open`
unconditionally) — `tests/cli.rs`'s fixtures gained a `git_repo()` helper
(`git init` + an empty commit) since M3's bare-tempdir fixtures no longer
satisfy that. This was already true in spirit (`.kan/` sits beside `.git/`,
ADR-3) but is now enforced instead of merely assumed.
