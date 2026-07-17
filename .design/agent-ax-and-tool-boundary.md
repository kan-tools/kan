# Feature: Agent AX pass + kan/companion-tool scope boundary

## Summary
A dogfooding self-review of `kan` (using it to track its own M1–M6 build) surfaced
concrete agent-experience friction — no MCP install path, silent subject-name
typos, bare-CID output with no confirmation text — and, in working through the
fixes, a more fundamental scope question: several of the "fixes" (session
lifecycle, interactive design authoring, code-review orchestration) are workflow
concerns crosslink baked into a single tool, and kan should not repeat that. This
doc records both: a small set of AX fixes that stay inside kan's boundary, and the
boundary rule itself (a new ADR) that explains why `kan session start`/`end` is
being *removed*, not extended, and what belongs in a future companion tool instead.

## Requirements

- REQ-1: Remove `Command::Session`/`SessionAction` (`src/cli/mod.rs`),
  `actions::session_start`/`session_end`/`session_record` (`src/actions.rs`), and
  the `session_start`/`session_end` MCP tools (`src/mcp.rs`) from kan's CLI+MCP
  vocabulary. Session lifecycle is a calling convention over existing primitives
  (`observe --subject <x>`) — it was never a distinct `ClaimBody` variant (`kan
  session start` just appends `ClaimBody::Observation` on a fixed `"session"`
  subject, per `src/actions.rs`'s existing doc comments) — so it fails the
  boundary test in REQ-2 and belongs in the companion tool, not kan.
- REQ-2: Record the kan/companion-tool boundary rule as a new ADR in
  `docs/DECISIONS.md`, cross-referenced from `CLAUDE.md`'s scope section. Rule:
  **kan owns a feature iff it needs a new or existing `ClaimBody`/`ClaimKind`/
  `Anchor`/`RelationKind` variant, or is a pure read/fold over the claim graph
  that needs no memory of *when* or *why* to call it.** A feature belongs in the
  companion tool if it can be built entirely as a calling convention over kan's
  existing primitives (subject naming, `cites`, `artifacts`) without touching
  kan's data model — i.e., it's process/orchestration/multi-turn interaction,
  not durable fact-recording. Narrow exception: kan may include minimal
  self-description/setup affordances for its own interface (install helpers,
  `--help`, discoverability hints) — these describe the tool, they don't
  prescribe how an agent should use it over time.
- REQ-3: `.claude/commands/design.md` gets an explicit tech-debt note (in the
  file itself) marking it as scope creep to migrate to the companion tool once
  it exists, cross-referenced from the new ADR. No functional change to the
  file's behavior in this pass — `/design` keeps working as-is until the
  companion tool exists to receive it.
- REQ-4: `kan mcp install` — a new leaf under the existing `mcp` verb, not a new
  top-level verb — prints two registration paths, both current/documented
  Claude Code mechanisms (confirmed via research, not guessed):
  1. **Bare MCP registration**: `claude mcp add kan -- <resolved path to this
     binary> mcp`, using `std::env::current_exe()` so it's correct regardless
     of install location. No config-file mutation — kan only prints the
     command; the user/agent runs it.
  2. **Claude Code plugin**: kan's own repo gains a plugin manifest
     (`.claude-plugin/plugin.json`, required fields `name`+`description`) and
     an `.mcp.json` at the repo root declaring `kan mcp` as a bundled stdio
     server — this is the one piece of REQ-4 that isn't just CLI output, it's
     two new files shipped in the repo. `kan mcp install --print` mentions
     `/plugin install` as the alternative path once those files exist.
- REQ-5: When `kan show <subject>` or `kan status <subject>` finds no live
  claims for the given subject, the output lists the subjects that *do* exist
  (from the same fold pass already computed in `actions::show`/`actions::status`)
  instead of just printing `"<subject>: no claims"`. This is the concrete fix
  for the dogfooding finding: bare `kan status` already enumerates every
  subject and already documents that it does (both `Command::Status`'s clap doc
  comment and the MCP `status` tool's description already say "one subject, or
  every subject if omitted") — the actual gap is a silent miss on a specific
  subject lookup, not missing enumeration.
- REQ-6: Write-verb CLI output (`observe`/`plan`/`decide`/`resolve`/`same`)
  stays a bare CID on stdout by default — this is load-bearing today
  (`tests/cli.rs`'s `golden_path_across_separate_invocations` pipes a claim's
  printed CID straight into the next call's `--cites`) — with a new
  `--verbose`/`-v` flag that switches stdout to a human-readable confirmation
  line instead ("recorded <kind> on '<subject>' (<cid>)").
- REQ-7: The same write-verb MCP tools (`observe`/`plan`/`decide`/`resolve`/
  `same`) always return the richer confirmation text, not flag-gated — MCP
  tool-call results aren't shell-composed the way CLI stdout is, so there's no
  scripting contract to preserve.
- REQ-8: `KanServer::get_info()`'s instructions (`src/mcp.rs`) describe kan's
  data model and verb semantics factually (what a subject is, what each read
  verb filters to) — explicitly *not* a prescribed order of operations or
  workflow recommendation, per REQ-2's boundary rule.

## Acceptance Criteria
- [ ] AC-1: `kan session` is not a recognized subcommand (`kan session start`
      exits non-zero with clap's "unrecognized subcommand" error); `kan mcp`'s
      `tools/list` response no longer includes `session_start`/`session_end`.
- [ ] AC-2: `docs/DECISIONS.md` contains a new ADR stating the boundary rule
      verbatim enough to apply it to a future feature without re-deriving it;
      `CLAUDE.md` references it.
- [ ] AC-3: `.claude/commands/design.md` contains a visible tech-debt note.
- [ ] AC-4: `kan mcp install` prints a registration command containing the
      correct absolute path to the running binary (verified via
      `env!("CARGO_BIN_EXE_kan")` in a test, not a live `claude mcp add`
      invocation, which would mutate the test runner's real config), and
      mentions `/plugin install` as the second path.
- [ ] AC-9: `.claude-plugin/plugin.json` exists, is valid JSON, and has
      non-empty `name`/`description` fields; `.mcp.json` at the repo root
      exists, is valid JSON, and declares a `kan` entry with `command: "kan"`,
      `args: ["mcp"]`.
- [ ] AC-5: given a fixture with existing subjects `bug-42`/`issue-7`, `kan show
      bug-43` (no such subject) includes `bug-42` and `issue-7` in its output.
- [ ] AC-6: `kan observe "x"` (no flag) prints exactly the bare CID on stdout;
      `kan observe "x" --verbose` prints a multi-line confirmation that still
      contains the CID.
- [ ] AC-7: the MCP `observe` tool call's response text contains the subject
      and claim kind, not just the CID (extends `tests/mcp_server.rs`).
- [ ] AC-8: `KanServer::get_info()`'s instructions string contains no
      sequencing/ordering language (a cheap substring check for words like
      "first,"/"then,"/"before starting" in a test) — a guardrail against this
      creeping back in later, not just a one-time check.

## Architecture
- `src/cli/mod.rs`: `Command` enum loses the `Session` variant and
  `SessionAction`; gains `Mcp`'s new `install` leaf (either a
  `Command::McpInstall` sibling or a `#[command(subcommand)] McpAction` under
  `Command::Mcp` — resolved during implementation based on clap ergonomics for
  a single-leaf subcommand). Write-verb variants (`Observe`/`Plan`/`Decide`/
  `Resolve`/`Same`) each gain a `verbose: bool` field via `#[arg(long, short)]`.
- `src/actions.rs`: `session_start`/`session_end`/`session_record`/
  `SESSION_SUBJECT` deleted. `show`/`status` gain a "did you mean one of
  these" branch reusing the already-computed `FoldedView` — no extra fold
  pass. Write-verb functions (`observe`/`plan`/`decide`/`resolve`/`same`)
  return enough structured data (subject, kind, Cid) for both surfaces to
  render — likely a small `AppendResult { subject: SubjectRef, kind: ClaimKind,
  cid: Cid }` struct returned instead of a bare `Cid`, since both REQ-6's
  `--verbose` text and REQ-7's MCP text need the same three fields.
- `src/mcp.rs`: `session_start`/`session_end` tools and their param structs
  deleted; write tools' `Result<String, ErrorData>` bodies build the richer
  text from the new `AppendResult`; `get_info()`'s `with_instructions(...)`
  string rewritten per REQ-8.
- `src/workspace.rs`: unaffected by this pass.
- `docs/DECISIONS.md`: new ADR (next number after ADR-15).
- `.claude/commands/design.md`: one added note, no other change.
- New file for `kan mcp install`'s registration-string logic — likely inline
  in `src/mcp.rs` near `serve`, since it's a few lines, not its own module
  (matches the "no cathedral" house rule).
- `.claude-plugin/plugin.json` (new, repo root): minimal manifest —
  `name: "kan"`, `description`, `version` (omit, defaults to git commit SHA
  per Claude Code's own convention), `repository`.
- `.mcp.json` (new, repo root): `{"mcpServers": {"kan": {"type": "stdio",
  "command": "kan", "args": ["mcp"]}}}` — assumes `kan` is on `PATH` (true
  once installed via `cargo install`), matching the plugin path's own
  contract rather than hardcoding a dev-tree binary path.

## Open Questions

None remaining — Q1 (Claude Code plugin manifest format) resolved via
`claude-code-guide` research: `claude mcp add <name> -- <command>` for bare
registration (`--scope local|user|project`); a plugin is a directory with
`.claude-plugin/plugin.json` (required: `name`, `description`) plus an
`.mcp.json` declaring bundled MCP servers, installed via `/plugin install`.

## Out of Scope
- Session-as-a-concept's actual implementation (grouping claims into a
  bounded span, deciding when to start/end one) — that's the companion
  tool's job, not this repo, once it exists.
- Scaffolding the companion tool's repo — recorded as a plan only (this doc +
  the new ADR), no new repo this pass, per explicit decision.
- Fuzzy string-distance matching for REQ-5's "did you mean" hint — just list
  the subjects that exist, no Levenshtein ranking; a nice-to-have, not
  required to satisfy AC-5.
- Renaming any existing CLI verb (`status`, `show`, `issues`) — REQ-13 in
  `.design/kan-spine.md` pins the vocabulary, and the dogfooding finding was a
  discoverability gap, not a naming problem.
