# Feature: day — the process-layer companion tool scaffold (ADR-18 / issue #24)

## Summary

Scaffold the separate companion tool ADR-18 named and issue #24 left unbuilt: a
new `kan-tools` repo containing a Rust CLI (kan-like depth as the goal; a
deliberately minimal verb set in this first pass) packaged as a Claude Code
plugin whose primary integration is harness-level hooks into dev flow. It
carries the structured-process layer grounded in
`.design/process-layer/telos-driven-development.md`: teloi, frames,
assessments, and an atom vocabulary — with **all durable state living in kan**
via naming/citation conventions, per ADR-18's boundary rule (the tool consumes
kan via CLI/MCP; it never touches kan's data model). First PR ships the
scaffold plus two real atoms: the migrated kan-native `/design` skill and the
issue #48 adversarial-review skill.

The tool is named **day** (Brian Day, Sydney school — Day convolution is
built from Kan extensions/coends and gives profunctor composition its
monoidal structure; and `day plan` / `day review` read as the daily practice
of development). The `day` crate name is unclaimed on crates.io. Like kan,
day ships CLI + MCP as its one surface from v1.

## Requirements

- REQ-1: A new repository `kan-tools/day`, separate from
  `kan-tools/kan`, per ADR-18's "separate repo/install that consumes kan via
  its CLI/MCP" and issue #24's scope. The `day` crate name is claimed on
  crates.io early (first publish can be a minimal placeholder release) since
  its availability is part of why the name was chosen. The repo carries its
  own orientation
  docs: a README stating the telos-driven model and the kan/process-layer
  division of labor, a CLAUDE.md-equivalent with its own house rules, and the
  foundations doc (`telos-driven-development.md`) moved or mirrored from
  kan's `.design/process-layer/`.
- REQ-2: A Rust CLI binary with a minimal initial verb surface scoped to
  install/build-out only: `day init` (install harness hooks into a consuming
  repo and verify kan is reachable), `day doctor` (check kan availability,
  read the live atom set from kan's fold, and verify atom interfaces still
  compose — the composition check the foundations doc assigns to this tool),
  `day hook <event>` (the entrypoint harness hooks invoke), and `day mcp`
  (REQ-9). The fuller verb surface (telos declaration, bridge planning,
  drift assessment) is explicitly deferred to the new repo's own `/design`
  passes — this REQ is the walking skeleton, not the cathedral; verb
  renames/additions later are expected and fine.
- REQ-3: Claude Code plugin packaging mirroring kan's own ADR-18 precedent:
  `.claude-plugin/plugin.json` (non-empty `name`/`description`), skills
  shipped in the plugin's commands/skills directories, and hook registrations
  shipped as plugin hook config — installable via `/plugin install`, with
  `day init` as the non-plugin fallback path (same dual-path pattern as
  `kan mcp install`).
- REQ-4: Harness hooks are **advisory, never blocking** — they inject
  context/prompts (e.g. a session-start hook calling `day hook session-start`
  to surface current teloi, the live atom set, and drift warnings read from
  kan); they never gate or reject an agent action. This carries kan's
  affordance-not-enforcement house rule (CLAUDE.md: "Do NOT port crosslink's
  blocking hooks") into the process layer as a founding constraint, since
  crosslink's blocking hooks are the named friction this split exists to fix.
  v1 ships at least the session-start hook end-to-end.
- REQ-5: The kan-native `/design` skill migrates into the plugin: the new
  repo ships it as a plugin skill, and `kan`'s
  `.claude/commands/design.md` is replaced by a short pointer note (the
  tech-debt banner ADR-18 added finally resolves). Migration sequencing: the
  kan-side retirement lands only after the plugin version is installed and
  exercised once, in a small follow-up PR to kan.
- REQ-6: The adversarial-review skill (issue #48's shape) ships as a second
  plugin skill: north-star recitation, REQ/AC coverage against the relevant
  design doc, independent evidence verification (reviewer runs
  build/test/clippy/fmt itself), scope-narrowing check, forbidden-pattern
  check, hard four-value verdict recorded via `kan decide`. Telos-driven
  upgrade over #48's original sketch: the north-star recitation reads the
  project's live teloi from kan when any are recorded, falling back to
  CLAUDE.md/SPEC-style orientation docs when none are.
- REQ-7: All durable process-layer state lives in kan as ordinary claims
  under documented naming conventions — an initial v0 convention shipped in
  the new repo's docs: telos subjects (`telos/<slug>` shape), atom-vocabulary
  subjects (`atom/<slug>` shape, per-atom additive per the foundations doc),
  assessments as `observe`/`result` claims citing evidence CIDs. Atom
  interface declarations are a structured fenced block (JSON) embedded in the
  `atom/<slug>` subject's live claim text — kan claims stay plain text, day
  owns the parse — keeping state purely in kan rather than split across a
  checked-in schema file. The tool keeps zero store of its own; conventions
  are versioned as docs in the new repo and explicitly marked evolving
  (frame conventions deferred — see the foundations doc's open threads).
- REQ-8: kan-side bookkeeping in this repo: this design doc and its
  resolutions recorded into kan's log (`observe`/`plan`/`decide` on a
  `process-layer` subject), issue #24 closed when the scaffold lands, and
  issue #48 updated to point at the plugin skill once it ships.
- REQ-9: An MCP server in v1, mirroring kan's CLI+MCP one-surface pattern:
  `day mcp` serves stdio MCP via rmcp (same crate kan uses), initially
  exposing `doctor` (composition check + kan reachability) and the
  session-start context assembly as tools, so agents without shell access get
  the same reads the hooks get. Verb surface instability is accepted — the
  MCP tools track the CLI verbs as they evolve.

## Acceptance Criteria

- [ ] AC-1: The repo `kan-tools/day` exists, contains README,
      orientation doc, and the foundations doc; the README names ADR-18 and
      the state-lives-in-kan rule explicitly. (REQ-1)
- [ ] AC-2: `cargo build` succeeds in the new repo; `day init`, `day doctor`,
      and `day hook session-start` all exit 0 in a repo where kan is
      initialized, and `day doctor` exits non-zero with a clear message when
      kan is absent. (REQ-2)
- [ ] AC-3: `day doctor` run against a kan log containing two atom claims
      with incompatible declared interfaces (per REQ-7's fenced-JSON
      convention) reports the composition failure and names both atoms;
      against a compatible set it reports success. (REQ-2, REQ-7)
- [ ] AC-4: `.claude-plugin/plugin.json` in the new repo is valid JSON with
      non-empty `name`/`description`; `/plugin install` of the repo makes both
      skills and the hook registration available in a fresh Claude Code
      session. (REQ-3)
- [ ] AC-5: The shipped hook config contains no blocking/deny hook types —
      only context-injecting ones — verified by a test that greps the plugin
      hook config for the harness's blocking hook decision values. (REQ-4)
- [ ] AC-6: The session-start hook, run in a repo with recorded teloi,
      injects text containing the telos subjects' names; in a repo with none,
      it injects a short note and exits 0 rather than failing. (REQ-4)
- [ ] AC-7: The plugin ships a `/design` skill whose behavior matches
      kan's current `.claude/commands/design.md` (kan-native Phase 5
      recording included); the follow-up kan PR replaces
      `.claude/commands/design.md` with a pointer note. (REQ-5)
- [ ] AC-8: The plugin ships an adversarial-review skill implementing issue
      #48's checklist including the four-value verdict, and its instructions
      direct recording the verdict via `kan decide`. (REQ-6)
- [ ] AC-9: The new repo's docs contain the v0 subject-naming conventions
      (telos/atom shapes, the fenced-JSON interface format, assessment claim
      kinds, citation discipline), and `day doctor`'s atom reads use exactly
      those conventions. (REQ-7)
- [ ] AC-10: kan's log contains `observe`/`plan` claims for this design pass
      on a `process-layer` subject, plus one `decide` claim per resolved
      question below. (REQ-8)
- [ ] AC-11: `day mcp` responds to an MCP `tools/list` with at least a
      `doctor` tool and a session-context tool, and a `doctor` tool call
      returns the same composition-check result as the CLI verb (extends the
      pattern of kan's `tests/mcp_server.rs`). (REQ-9)

## Architecture

**New repo layout** (mirroring kan's shape where it fits): `src/main.rs` +
`src/cli/` for the clap surface (`init`/`doctor`/`hook`/`mcp`),
`src/mcp.rs` for the rmcp stdio server (REQ-9, modeled on kan's `src/mcp.rs`),
`src/kan_client.rs` wrapping kan invocation — subprocess calls to the `kan` binary's CLI, chosen
over linking kan as a crate so the boundary stays the public CLI/MCP surface
ADR-18 prescribes (same reason kan's own `GitAncestry` provider shells out to
git). `skills/` (or the plugin-required directory name) carrying `design.md`
and `adversarial-review.md`; `.claude-plugin/plugin.json` and hook config at
the root, modeled on kan's own `.claude-plugin/plugin.json` + `.mcp.json`
precedent from the ADR-18 pass.

**Hook flow**: plugin hook config registers session-start → runs
`day hook session-start` → the binary shells `kan status` / `kan context
--budget N` / convention-named subject reads, assembles an advisory context
block, prints to stdout for the harness to inject. Non-blocking by
construction: the hook's output is additive context; exit codes never signal
denial. (AC-5 pins this so it can't regress.)

**Composition check** (`day doctor`): reads live atom claims from kan
(convention: `atom/<slug>` subjects whose latest live claim carries the
declared input/output interface as a fenced JSON block per REQ-7), builds
the interface graph, and checks
declared compositions still type-match — a derived read over kan's fold, the
same category of computation as kan's own status/identity fold, per the
foundations doc's "kan-checked composition" decision. It writes nothing; a
failed check is advisory output (and, at the operator's choice, an `observe`
claim recording the drift finding).

**Touchpoints in this (kan's) repo** are deliberately tiny: replace
`.claude/commands/design.md` with a pointer (follow-up PR, REQ-5),
close/annotate issues #24/#48, and record the design pass into kan's log.
Kan's fold, log, anchors, and data model are untouched — the whole point of
the boundary. Nothing here violates the no-destroy invariant because nothing
here writes kan claims except through kan's own public write verbs.

**The smell test, applied**: the process layer's local path is one binary
shelling one `kan` binary in one repo, no frame reconciliation, no
cross-agent anything — all of the topos/sheaf machinery in the foundations
doc stays theory until multi-frame reality demands it. If the scaffold ends
up needing any of it to ship, the scaffold is wrong.

## Resolved Questions

- **Q1 — name: `day`** (Brian Day, Sydney school). Chosen from a brainstorm
  of profunctor/action category theorists (Bénabou, Kelly, Street, Freyd,
  Kleisli, May, Petri were the runners-up) for the Kan-extension lineage of
  Day convolution, the three-letter shape next to `kan`, the natural command
  readings (`day plan`, `day review`), and the confirmed availability of the
  `day` crate name on crates.io.
- **Q2 — atom interface format: structured fenced JSON block inside the
  `atom/<slug>` subject's live claim text.** kan claims stay plain text; day
  owns the parse; state stays purely in kan rather than split with a
  checked-in schema file. (Folded into REQ-7.)
- **Q3 — MCP in v1: yes.** `day mcp` ships in the scaffold, mirroring kan's
  CLI+MCP one-surface pattern; verb-surface churn is accepted and MCP tools
  track the CLI as it evolves. (Now REQ-9/AC-11.)

## Out of Scope

- The fuller CLI verb surface (telos declaration/assessment, bridge planning,
  work-unit execution) — deferred to the new repo's own `/design` passes;
  REQ-2's three verbs are the whole v1 surface.
- Frame representation and cross-frame reconciliation conventions — the
  foundations doc's open thread; nothing in this scaffold blocks on it.
- The poly-functor formalization of atom composition — explicitly bracketed
  in the foundations doc as a later telos for the project itself.
- Any change to kan's data model, verb surface, or fold — ADR-18's rule is
  the premise of this whole design.
- Migration of anything beyond `/design` and the #48 review skill (no
  session-concept revival, no other crosslink descendants this pass).
- Non-Claude-Code harnesses: the hook/plugin packaging targets Claude Code
  first; the CLI core stays harness-agnostic so other harnesses are a
  packaging problem later, not a redesign.
