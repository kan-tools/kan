# ADR 18: The kan/companion-tool scope boundary; `kan session` removed

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-18

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

**Date:** 2026-07-21
**Context:** A dogfooding self-review (using kan to track its own M1–M6
build) surfaced real agent-experience friction, and working through the
fixes surfaced a bigger question: crosslink (kan's predecessor, `CLAUDE.md`
"Provenance") let workflow/AX concerns — session orchestration, interactive
design authoring, code-review orchestration — creep into the same tool as
the memory substrate itself. `.claude/commands/design.md`, the very `/design`
workflow used to write this decision's design doc
(`.design/agent-ax-and-tool-boundary.md`), is itself an instance of exactly
that creep, sitting inside kan's own repo.
**Decision — the boundary rule:** kan owns a feature *iff* it needs a new or
existing `ClaimBody`/`ClaimKind`/`Anchor`/`RelationKind` variant, or is a
pure read/fold over the claim graph that needs no memory of *when* or *why*
to call it. A feature belongs in a future, separate companion tool if it can
be built entirely as a calling convention over kan's existing primitives
(subject naming, `cites`, `artifacts`) without touching kan's data model —
i.e. it's process, orchestration, or multi-turn interaction, not durable
fact-recording. Narrow exception: kan may still include minimal
self-description/setup affordances for its *own* interface (install
helpers, `--help`, discoverability hints) — these describe the tool, they
don't prescribe how an agent should use it over time. The companion tool, if
and when it's built, is a separate `kan-tools` repo/install that consumes
kan via its CLI/MCP — not a new mode of kan itself (`CLAUDE.md`'s "one
surface: CLI + MCP" still holds for kan's own surface).
**Applying the rule, concretely:**
- `kan session start`/`end` **removed** from the CLI and MCP vocabulary.
  It never needed a new `ClaimBody` variant — `kan session start` just
  appended `ClaimBody::Observation` on a fixed `"session"` subject
  (`src/actions.rs`'s own prior doc comments said so) — so it fails the
  rule outright. Session-as-a-concept (grouping claims into a bounded span,
  deciding when to start/end one) is now the companion tool's job, built on
  kan's existing `observe --subject <x>` / `cites` primitives. Removing it
  also retired `actions::issues`'s special-cased exclusion of a `"session"`
  subject — with no built-in session concept, no subject is special-cased
  in `issues` anymore; every subject is judged the same way.
- `.claude/commands/design.md` **stays, flagged as tech debt** (a note in
  the file itself) rather than removed immediately — it keeps working until
  the companion tool exists to receive it; no functional change this pass.
- A proposed offline-embedding vector index (issue #15) **passes** the
  rule: it's a pure derived read projection over the claim graph, the same
  category as the fold and the SQLite index, no new `ClaimBody` needed. It
  belongs in kan, confirming the rule discriminates usefully rather than
  just rationalizing the session removal.
**Supersedes:** ADR-7's CLI-vocabulary quote and `CLAUDE.md`'s vocabulary
line both listed `session` as part of the "exact" v1 vocabulary; both are
now stale on that one point. ADR-7's own decision (no hard-delete CLI verb)
is unaffected — only the vocabulary list it quoted changed. `CLAUDE.md` is
updated directly (living documentation); ADR-7's historical text is left
as-is, per the same practice ADR-12 used when superseding ADR-1.
**Consequences:** `kan mcp install` (a new leaf under the existing `mcp`
verb, not a new top-level verb) prints two current, researched — not
guessed — Claude Code registration paths: a bare `claude mcp add kan --
<binary> mcp` command, and (via new `.claude-plugin/plugin.json` +
`.mcp.json` files at the repo root) a Claude Code plugin install. `kan
show`/`kan status` now list existing subjects when a specific lookup misses
(`actions::subject_hint`), directly derisking the silent-typo failure mode
dogfooding surfaced. Write verbs gained a `--verbose`/`-v` flag (CLI stdout
stays a bare CID by default — load-bearing for `--cites` piping,
`tests/cli.rs`); every MCP write tool always returns the richer
confirmation text, since tool-call results aren't shell-composed the way
CLI stdout is. `KanServer::get_info()`'s instructions were rewritten to be
purely factual about the data model, with no sequencing language — guarded
by a test that greps for it.
