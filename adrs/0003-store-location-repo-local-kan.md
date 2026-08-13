# ADR 0003: Store location: repo-local `.kan/`

- Status: Not recorded contemporaneously
- Date: 2026-07-15
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-3

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

**Date:** 2026-07-15
**Decision:** The signed log and disposable SQLite index live at `.kan/`,
gitignored, sibling to `.git/` — one store per checkout.
**Why:** Mirrors git's own pattern directly (kan's README already frames it as
git's sibling: "git versions your code, kan remembers your reasoning"). A
global store keyed by `Anchor::Workspace(GenesisCid)` (shared across clones/
worktrees) was considered and deferred — not needed for a single-checkout v1
spine, and adds a lookup indirection.
