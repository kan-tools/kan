# ADR 0032: Verb lexicon reorganized by AX phase; MCP tool surface catches up to the full CLI

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-32

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
**Decision:** Three changes closing out `.design/v0.3-milestone.md`
REQ-10..12:
1. `cli::Command`'s variants are reordered into four declared groups —
   Recording (`observe`/`plan`/`decide`/`block`/`resolve`), Structuring
   (`same`/`relate`/`mark`), Correcting (`retract`/`reject`), Recalling
   (`show`/`status`/`issues`/`context`) — with `mcp` staying outside the
   four phases (setup/tooling) at the end. Since clap prints subcommands in
   declaration order, `kan --help` now teaches the phase structure for
   free, with zero runtime cost — confirmed by inspecting the actual
   `--help` output, not just re-ordering and assuming.
2. `mcp::KanServer::get_info()`'s instructions are rewritten around the
   same four phases, replacing the previous flat kind-by-kind description.
   Still passes `tests/mcp_server.rs`'s existing sequencing-language guard
   (no "first"/"then"/"before starting") — confirmed by running that exact
   test, not just avoiding the words by inspection.
3. The MCP tool surface catches up to the full CLI: new `relate`/`reject`
   tools; `NarrativeParams` (`observe`/`plan`/`decide`) gains `status`/
   `title`/`kind`; `ResolveParams`/`BlockParams` gain `title`/`kind` (no
   `status` — REQ-9 excludes those two the same way the CLI does).
   `claim::SubjectKind` gains a direct `schemars::JsonSchema` derive (same
   rationale ADR-21 already used for `claim::StatusValue`: MCP params use
   the core type directly, since `schemars` — unlike `clap` — doesn't carry
   the "keep `claim.rs` CLI-free" concern). `relate`'s `kind` param uses a
   new MCP-local `RelateKindParam` enum (Blocks/About/ManifestsAt/
   DependsOn/Accepts, no `SameAs`) rather than `claim::RelationKind`
   directly — the MCP-side counterpart to `cli::RelationKindArg`, enforcing
   REQ-2's "`same` is the only way to write `SameAs`" at the
   deserialization boundary instead of a runtime check inside
   `actions::relate` (which still does no `kind` re-validation itself, on
   either surface).
**Why:** A flat alphabetical/kind-order tool list teaches nothing about
workflow; grouping by the four AX phases (Recording, Structuring,
Correcting, Recalling) lets the verb list itself communicate intended use
without `get_info()` having to prescribe an order (which the sequencing-
language guard test exists specifically to prevent, per `docs/DECISIONS.md`'s
kan/companion-tool boundary rule — affordance, not enforcement). The MCP
surface lagging the CLI by two PRs (`relate`/`reject`/`status`/`title`/
`kind` all landed CLI-first, MCP passing `None` as placeholders) was a
deliberate, tracked debt from ADR-29/30/31, not an oversight; this PR pays
it off in one pass rather than mirroring each earlier PR twice.
**Consequences:** `tests/mcp_server.rs` gained `ac12_mcp_tool_surface_
mirrors_the_cli`, spawning a real `kan mcp` subprocess and inspecting
`tools/list`'s JSON schemas directly (not just presence of the tool names)
for `status`/`title`/`kind` on the right tools, `status`'s *absence* on
`block`/`resolve`, and confirming `relate`'s `kind` schema has no
`SameAs`/`same_as` variant. The existing tool-name assertion list in
`ac8_lists_tools_and_calls_the_observe_tool` grew to include `block`/
`relate`/`mark`/`retract`/`reject` alongside the previously-checked subset.
