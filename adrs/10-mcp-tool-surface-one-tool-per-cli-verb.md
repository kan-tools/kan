# ADR 10: MCP tool surface: one `#[tool]` per CLI verb

- Status: Not recorded contemporaneously
- Date: 2026-07-16
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-10

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

**Date:** 2026-07-16
**Decision:** `kan mcp` exposes one `rmcp` tool per CLI verb (10 tools:
observe/plan/decide/resolve/same/show/issues/status/session_start/
session_end/context), not a single generic `append_claim(kind, ...)` tool.
**Why:** `rmcp`'s `#[tool]`/`#[tool_router]` macros make per-tool boilerplate
near-zero (confirmed by reading `rmcp`'s own test suite), which removes the
main cost that motivated the design doc's original "one generic tool" lean.
Two alternatives were weighed and rejected for v1: (a) collapsing only the
read verbs (`show`/`issues`/`status`/`context`) into one `query(kind, filter)`
tool, kept open as a plausible future consolidation if the read surface grows;
(b) a single CLI-passthrough tool (`run(args: string)` shelling out to the
`kan` binary, mirroring Claude Code's own `Bash` tool) — real precedent for
open-ended command surfaces, but kan's vocabulary is deliberately capped small
(`CLAUDE.md`'s git-like/terse house rule), which is not the regime the
narrow-tool-sprawl critique applies to, and schema-typed params protect the
"provenance is sacred" invariant on write verbs in a way free-text CLI
arguments can't. Closes Open Question Q3.
