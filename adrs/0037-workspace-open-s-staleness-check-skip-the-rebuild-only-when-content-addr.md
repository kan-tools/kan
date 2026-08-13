# ADR 0037: `Workspace::open`'s staleness check: skip the rebuild only when content-addressing proves it's safe

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-37

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
**Decision:** `Workspace::open` (`.design/v0.4-milestone.md` REQ-4..5,
issue #26) skips `Log::iter_all` + `Index::rebuild` when the log's current
root CID (`Log::current_root`, a new accessor — already resident in
memory from `open_or_create`, zero extra I/O) matches what the index was
last built from (`Index::built_from_root`, backed by a new `meta` table).
`Index::rebuild`'s signature grows a `built_from_root: Option<&Cid>`
parameter, written inside the same transaction as the claims themselves —
meta and claims always commit atomically together, so a crash mid-rebuild
can never leave a half-updated claims table read back as "fresh." Any
mismatch (including a fresh or just-deleted-and-recreated index, which has
no `meta` row yet — `None != Some(root)`) falls back to exactly the prior
unconditional full rebuild. Numbered ADR-37 (continuing after ADR-36, not
ADR-35) to preserve the intended merge order even though this PR branched
directly off `main` rather than stacking on PR1 (`kan result`) — the two
touch disjoint files (`src/store/`, `src/workspace.rs` vs. `src/actions.rs`,
`src/cli/mod.rs`, `src/mcp.rs`), so neither needs the other's code to
exist first.
**Why:** `Workspace::open`'s own doc comment already named this exact
deferral ("incremental indexing is a later optimization once fixtures
exist to guard it"). Content-addressing makes the check exact rather than
heuristic: an equal root CID doesn't mean "probably unchanged," it means
the log genuinely has not changed a single bit, so skipping is provably
safe, not a staleness gamble. Deliberately *not* true incremental indexing
(appending only new claims into the existing index rows) — that's a
larger, riskier change (partial-update logic that could itself drift out
of sync) staying deferred; this ships only the skip-or-full-rebuild shape,
which can never produce a partially-updated index.
**Consequences:** `Index::rebuild`'s signature change touches every call
site, including three in `tests/index_and_fold.rs`/`tests/
write_surface.rs` that construct a `Workspace` by hand — all updated to
pass `log.current_root().as_ref()`. New `tests/workspace_staleness.rs`
proves the skip *actually happens* (not just that the code compiles)
via a black-box technique needing zero instrumentation in production
code: `Index::all_stored_claims` (what every read verb consumes) never
re-verifies against the log, so directly tampering with the index's
stored bytes and observing whether a subsequent `Workspace::open` leaves
the tampering in place (skip) or overwrites it with the log's true
content (full rebuild, triggered by an intervening write) is a direct
proof of which path ran — confirmed to actually discriminate by
temporarily reverting the skip logic and watching the test fail exactly
where expected, then restoring it.
