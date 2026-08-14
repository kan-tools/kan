# ADR 17: Software-review-pass fixes: bugs #2–#6, anti-patterns, testing gaps, docs

- Status: All from the same forked-agent review pass that found ADR-16's bug
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-17

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

**Date:** 2026-07-20
**Status:** All from the same forked-agent review pass that found ADR-16's bug
(the fork was told to review the whole codebase against `docs/SPEC.md`/
`docs/DECISIONS.md`/`CLAUDE.md`, not just look for one thing). Bundled into
one milestone since each is small and independent; ADR-16's higher-severity
finding shipped separately, first.
**Fixes:**
- **`TidGenerator` reseeds from the reopened log's last commit `rev`**
  (`src/store/tid.rs`'s new `seeded`/`decode`, called from
  `Log::open_or_create`'s reopen branch with `commit.rev`) instead of always
  starting at 0. Kan's real usage is a fresh process per command (ADR-15), so
  "strictly monotonic within one generator's lifetime" wasn't actually strong
  enough — a backward wall-clock step between two separate invocations could
  have produced a non-monotonic `rev`.
- **`GitSubstrate::genesis()` rejects shallow clones** (`git rev-parse
  --is-shallow-repository`, new `Error::ShallowClone`) instead of silently
  hashing a truncated history — a shallow clone's root commit is wherever the
  clone was truncated, not the repo's real genesis, which would have violated
  §5's "computed identically by every actor" invariant silently.
  `tests/git_substrate.rs`'s regression test needed `git clone --depth 1
  --no-local`: git silently ignores `--depth` for local-filesystem clones,
  so a naive local-clone test would have "passed" without exercising a real
  shallow clone at all.
- **`fold::state::classify` re-checks agreement among domination survivors**:
  a 3-way disagreement resolved by ordering down to 2 agreeing survivors now
  correctly reports `Confirmed`, not `Contested`.
- **`Log::iter_all` tolerates one `BadSignature` record** (skip + `eprintln!`
  warning) instead of failing the entire log — `docs/SPEC.md` §8's "folds
  tolerate dangling cites" philosophy extended to a corrupt/forged record,
  which previously made every command fail on account of one bad claim.
  Any *other* error kind still propagates; only this specific, legible case
  is tolerated.
- **`actions::issues`'s session exclusion uses `.contains`, not `==`** against
  a single-element vec — a merge-class containing "session" (e.g. after `kan
  same`) is still bookkeeping, not an issue, regardless of what else got
  merged into it. Fixed while resolving the adjacent `compute_default`
  redundancy below, not as a separate patch.
- **`issues`/`status` no longer compute `relations::compute_default` twice
  per subject** — new shared `actions::classify_subject` computes each
  subject's edges once; both callers reuse the same `StateView`.
- **`Index::open` propagates `create_dir_all`'s error** instead of discarding
  it via `.ok()` — a real directory-creation failure now surfaces as its own
  clear cause instead of a harder-to-diagnose SQLite-open error downstream.
- **`context::render_claim` renders actual prose**, not a `{:?}` Debug dump —
  extracts each `ClaimBody` variant's real content (narrative text, a
  `Status` value, a `Relation`'s kind+target, `Retraction`'s target) instead
  of printing Rust struct/enum syntax. The doc comment calling this "the text
  an agent would actually see" was aspirational before; now it's accurate.
- **`cid::canonical_bytes` deleted** — zero callers anywhere, dead public API.
- **Documentation-only**: `fold::trust`'s doc comment now explains
  `PeerContested`'s CLI/MCP-unreachability is deliberate (v1's real scope has
  no second human to weigh trust against, not an oversight);
  `relations::GitAncestry`'s doc comment now states its O(n²) +
  subprocess-per-comparison scaling explicitly, matching `fold::identity`'s
  own honesty about its O(n) recompute cost; `GitSubstrate::is_ancestor`'s
  doc comment explains why it deviates from git's real reflexive
  `--is-ancestor` semantics; `docs/SETUP-TODO.md`'s Phase 3 checklist no
  longer overclaims `RelationProvider`s as "disableable" (down-weighting
  isn't built yet).
- **New test coverage, no code change**: `ClaimBody::Subject`/`SubjectKind`
  round-trip through the log (previously zero coverage, and no CLI verb
  constructs them — the data model defines them regardless).
**Deferred, not fixed here:** `docs/DECISIONS.md` ADR-7 and `CLAUDE.md` still
listing `session` in the CLI's "exact" vocabulary — folds into
`.design/agent-ax-and-tool-boundary.md`'s session-removal work, the next
milestone, rather than a standalone patch to text about to change again.
