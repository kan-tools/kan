# ADR 15: M5: one action layer for CLI + MCP; round-robin greedy context assembly

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-15

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
**Decision:**
- **`src/actions.rs` is the one place claim-mutation/view-rendering logic
  lives.** `Workspace` moved out of `cli::context` to a top-level
  `src/workspace.rs` (nothing CLI-specific about it), and `cli::show`/
  `status`/`session` were deleted — their logic moved into `actions`,
  returning `String`/`Cid` instead of `println!`ing directly. `src/cli/
  mod.rs` is now argument parsing and printing only; `src/mcp.rs` is typed
  params in, text out. Neither surface has logic the other doesn't share —
  the literal implementation of `CLAUDE.md`'s "one surface: CLI + MCP,"
  which until now was true of the vocabulary but not the code.
- **`kan mcp` reopens `Workspace::open` fresh per tool call**, exactly like
  every separate CLI invocation does, rather than holding one `Workspace`
  across the server's lifetime. Simpler than a `Mutex`-guarded shared
  `Workspace` (no concurrent-mutation question to reason about) and
  correctness-first (never stale) at the cost of redoing the
  rebuild-index-from-log work per call — fine at today's scale per the same
  reasoning `Workspace::open`'s own doc comment already gives for doing this
  on every CLI run.
- **`rmcp`'s tool surface (ADR-10) is 11 tools**, not the 10 ADR-10 counted
  — `observe/plan/decide/resolve/same/show/issues/status/session_start/
  session_end/context` is 11 items; ADR-10's number was simply a miscount
  during Q3's resolution, not a scope change. `#[tool_router]`/
  `#[tool_handler]` need the explicit `router = self.tool_router`/`router =
  tool_router` form (confirmed via `rmcp-macros`' own doc comments, not
  assumed from the bare-attribute example) — the bare form defaults to
  `Self::tool_router()`, rebuilding a fresh router every call instead of
  reusing the one built in `KanServer::new`, and clippy's `dead_code` lint
  catches exactly this if the struct field goes unread.
- **Context assembly (`src/context.rs`) has no spec-mandated ranking
  algorithm** (`docs/SPEC.md` §11 names the feature, not a method). v1's
  choice: value a claim by kind (`Status`/`Decision`/`Blocker`/`Resolution`
  outrank narrative, which outranks `Relation`/`Retraction` bookkeeping)
  with recency as a same-kind tiebreak, selected round-robin across
  merge-classes (one claim per class per round, highest-value-that-fits)
  rather than one global greedy pass — so one chatty subject can't starve
  the budget for everything else. Deterministic by construction: class
  order comes from `fold::identity::merge_classes`'s already-sorted
  subjects, and every sort has an explicit tiebreak, so nothing depends on
  hashmap iteration order (AC-7).
- **`kan issues`'s "done" heuristic**: a live `ClaimBody::Resolution` (what
  `kan resolve` writes) OR a state-fold `Settled{Resolved|Closed}`. Not
  spec-mandated (`.design/kan-spine.md`'s CLI table says only "fold + render
  the issue-like view") — chosen because v1's CLI has no verb for authoring
  `Status` claims directly, so `Resolution` is, in practice, the only signal
  most subjects will ever carry.
**Why:** REQ-12/REQ-13/REQ-14 (`.design/kan-spine.md`), `docs/SPEC.md` §11,
AC-7/AC-8. This is the last of the spine's HARD requirements; what's left
after this (M6) is fixtures and polish, not new mechanism.
**Consequences:** `Cargo.toml` gained `schemars` (direct dependency, for
`#[derive(JsonSchema)]` on tool-parameter structs) and `rmcp`'s
`transport-io` feature (not in `rmcp`'s default set). Dev-dependencies
gained `serde_json` and `tokio`'s `process` feature, both test-only (driving
`kan mcp` as a real subprocess for AC-8, `tests/mcp_server.rs`).
