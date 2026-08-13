# ADR 0033: `GitAncestry::relations` caches `is_ancestor` per directed commit pair, within one call

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-33

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

**Date:** 2026-07-19
**Decision:** `relations::GitAncestry::relations` (REQ-13, issue #27,
`.design/v0.3-milestone.md`) now caches each `GitSubstrate::is_ancestor`
result in a `HashMap<(Sha, Sha), bool>` local to the call, keyed on the
exact directed `(ancestor, descendant)` pair queried. A claim count of `n`
over `k` distinct commits now needs at most `k²` real `git` subprocess
invocations instead of up to `n²` — the gap matters once multiple claims
share a commit, which v0.2 made the common case by auto-attaching `HEAD`
to every write (ADR-22). Numbered ADR-33 (continuing after ADR-32, not
ADR-29) to preserve the intended merge order even though this PR branched
directly off `main` rather than stacking on the other four v0.3 PRs — it
touches only `src/relations.rs` and `tests/`, with zero file overlap, so
it doesn't need their code to exist first.
**Why:** `GitAncestry`'s own doc comment already named this as "the
obvious first optimization" back when the cost was still theoretical
(nothing populated real artifacts yet). REQ-8/REQ-9 of
`.design/v0.2-milestone.md` closed that gap by making every write verb
auto-attach the current `HEAD` commit, so real fold-time classification
(`actions::status`/`actions::issues`, both calling `relations::
compute_default` once per merge-class) now redundantly re-derives the same
`is_ancestor` fact whenever a class has several claims anchored to a
shared commit — routine, not a pathological case. Correctness before
performance stays the house rule (`CLAUDE.md`): this is a pure
memoization of an already-correct pairwise computation, not a new
algorithm, so it can't change which edges get produced.
**Consequences:** New `tests/git_ancestry_cache.rs`
(`is_ancestor_is_not_re_invoked_for_a_pair_already_resolved`) — a
call-count-instrumented test double: a fake `git` placed ahead of the real
one on `PATH`, logging every invocation to a file, verifying real `git
merge-base --is-ancestor` subprocess calls drop from up to 16 (over 8
claims sharing 2 commits, uncached — confirmed by reverting the cache and
re-running, which fails at 24 total git calls) to exactly 2 (cached).
Deliberately the only test in its file/binary, since it mutates the
process-wide `PATH` for the duration of the test — a mutation that would
race any other test in the same process also shelling out to `git`.
`std::env::set_var` needed an `unsafe` block under the current stable
toolchain's edition rules; safe here specifically because of that
single-test isolation (documented inline). `GitAncestry`'s own doc comment
is updated to describe the cache instead of naming it as a future
revisit.
