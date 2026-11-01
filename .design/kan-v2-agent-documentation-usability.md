# Feature: Common-path agent documentation and capture usability

## Summary

Owner-authorized design/build scope (2026-11-01), grounded in the feedback and real
prof-comm documentation pilot. Make bounded, decoded evidence retrieval and
project-scoped capture usable without bespoke launchers or guessed request fields.
Keep research moving through the existing concise Day/v1 record while this path
is improved. Full Day compatibility is a separate prerequisite for replacing v1.

The owner authorized design and build of this plan. This is not implementation
acceptance, a version bump, publication authority, or permission to change live
credentials or capture routes.
Process recording follows the existing Git-first day#168 / kan#197 exception;
Day validation and claim backfill remain pending, rather than assumed complete.

## Evidence and diagnosis

- Released baseline: merge `8852067e6daf34348bf5e687c8c2ac19b3023e32`, tree
  `66ba8721034c904fba1f42e125197641e95c5c2e`. Current worktree `0961f9b` has
  that identical tree before this draft. System Kan remains v1.
- The Sonnet toy passed its 12 tests and zipapp build, captured/drained 19 hook
  events, and read authenticated evidence after exact request guidance. Its
  report is `/Users/m/code/kan-sonnet-toy-20261031/RESULTS.md`.
- The prof-comm pilot report is
  `/Users/m/code/maxinelevesque/prof-comm/.handoff/kan-v2-documentation-pilot-20261031/docs/KAN_V2_DOCUMENTATION_PILOT.md`.
  A fresh reader recovered the coexistence decision and accepted-source/CID
  from retained document readback, then corroborated the relevant v1 export.
  It did not independently verify the mathematics or exhaustive transcript equality.
- Two initial transcript exports failed after a guessed Claude directory encoding.
  Explicit later backfill retained the missed prefix; original failures remain.
  The five-second startup failure belongs to the copied pilot helper, not a
  demonstrated storage failure. Empty delivery queues do not establish capture
  completeness.
- The retained native-backup receipt says `Not a directory`. The helper passed a
  database file to `Command::Backup`, whose dispatch calls an archive-directory
  opener. The pilot's stopped directory copy passed offline verification; this
  is not a successful native-backup invocation or independent failure-domain proof.
- A bounded read-only diagnosis on a disposable copy of that backup reproduced
  `read-record` exit 1: `invalid input: unknown database profile`. SQLite's header
  says profile 2, while `RecoveryReader::open` explicitly selects profile 1.
  `Command::ReadRecord` offers no proof-profile options. Source and disposable
  database SHA-256 stayed identical. Evidence is
  `.local-state/usability-diagnostics-20261101/read-record-diagnostic.json`.
  Preserve the profile refusal; improve discoverability and guidance rather than
  silently treating admitted evidence as unsigned evidence.

## Requirements

- REQ-1: Advertised common read operations have inspectable, action-specific MCP
  schemas and executable examples, rather than an unconstrained nested query.
- REQ-2: Malformed requests identify a safe field path and expected shape without
  echoing supplied credential values, private configuration or captured content.
- REQ-3: Discovery distinguishes launch-enabled authority from configured reader
  features; unavailable workspace, search, annotation and analysis functions
  have explicit capability status. Read/write/owner authority remains separate.
- REQ-4: Normal evidence retrieval uses existing decoded content, attempt,
  discovery, session and reference-resolution facilities with precise citations,
  bounded output, continuation and explicit coverage. Raw frames/hex are an
  explicit audit path. Missing content is never an empty successful result.
- REQ-5: One explicitly selected project configuration supports its authorized
  durable worktrees, scoped runtime locations and credential references. Agents
  receive the documentation contract and selected capabilities automatically.
- REQ-6: A maintained Claude hook integration validates the actual harness-supplied
  transcript path within an explicitly authorized scope, with pre-session
  filesystem checks and bounded readiness diagnostics. Directory encoding is
  not inferred from worktree spelling; discovery never grants new filesystem scope.
- REQ-7: A supported final snapshot/drain operation reports capture gaps, queued
  bytes, acknowledged delivery and later backfill separately. Process exit,
  task completion and capture completeness remain independent facts.
- REQ-8: CLI help and failures identify archive-directory versus standalone-file
  inputs and supported profiles before an opaque SQLite/OS error where feasible.
  Unsupported profiles retain refusal and failed outputs remain retained.
- REQ-9: Documentation keeps concise Day decisions/results/handoffs and Git source
  reports as the common entry path. Captured sessions answer particular missing
  questions. The new beta introduces no competing research ledger or witness system.
- REQ-10: A fresh-session documentation exercise demonstrates ordinary decoded
  retrieval, actual capture health, source-bound continuity and backup recovery.
  Full Day migration and optional interfaces are not prerequisites for research.

## Acceptance Criteria

- [ ] AC-1: MCP discovery exposes schemas/examples for every action advertised as
  ordinarily usable. Actual agent calls exercise the common path without invented
  fields; schema examples are checked against the real shared dispatcher. (REQ-1)
- [ ] AC-2: Missing, wrong-type and unknown fields produce actionable, bounded
  diagnostics. Adversarial values and private configuration do not leak into
  those diagnostics. (REQ-2)
- [ ] AC-3: Reader-only, configured-workspace, write-enabled and owner-enabled
  instances advertise their actual capabilities. Read tools cannot mutate and
  content cannot enable privileges. Existing permission checks remain effective.
  (REQ-3)
- [ ] AC-4: The fresh reader retrieves the selected decision and supporting session
  content without hand-written byte offsets or hex decoding. Returned citations
  resolve to the same authenticated source; bounds, truncation, revocation and
  unavailable data remain explicit. (REQ-4)
- [ ] AC-5: Two explicitly authorized durable worktrees use the same selected
  project configuration. A different project or undeclared path is refused;
  no global binary or harness configuration changes occur. (REQ-5)
- [ ] AC-6: Actual exported transcript paths work for the selected worktrees.
  Symlink/out-of-scope paths and missing permissions fail with useful preflight
  guidance. Delayed readiness succeeds within the configured budget; exhausted
  readiness preserves the actual stage and diagnostics. (REQ-6)
- [ ] AC-7: Forced hook/export failure, queued delivery, acknowledgment and explicit
  backfill retain distinct states. Final snapshot/drain is bounded and retry-safe;
  a zero queue cannot clear a historical capture gap. (REQ-7)
- [ ] AC-8: Wrong artifact paths and unsupported profiles are exercised against
  known fixtures. Correct native backup and verified restore succeed using the
  documented artifact types, preserving source bytes and retained failures.
  Any profile-aware record extension requires explicit binding/profile checks;
  no automatic security-profile fallback is accepted. (REQ-8)
- [ ] AC-9: The project contract instructs agents to start from the relevant Day
  handoff/research packet, record material outcomes once and distinguish source
  evidence from asserted interpretation. A documentation task does not demand
  replay of the full project or a new acceptance bureaucracy. (REQ-9)
- [ ] AC-10: One small documentation author/fresh-reader exercise passes AC-4,
  AC-7 and AC-8 with actual source revisions and citations. Report capture limits
  and backup failure domains. Routine capture adoption is considered only on
  that evidence; Day/v1 replacement remains separately qualified. (REQ-10)

## Architecture

### MCP and decoded retrieval

`src/evidence_library/mcp.rs` currently accepts `Input { query: Value }`, parses
`Query`, and discards deserialization details. Preserve its exhaustive mutation
classification and instance-specific tool removal. Add typed common read tools
over the existing `Readers::query` dispatch and shared `Query` variants in
`src/evidence_library.rs`. Group discovery and decoded session/content access
into a small tool surface; expose validated per-action schemas/examples for the
advanced JSON API instead of advertising unbounded JSON as sufficient guidance.
Do not expose the entire mixed read/write `Query` union as a read-tool capability.

Use existing `src/evidence_library/proof/sessions.rs`, `discovery.rs`,
`src/evidence_content.rs` and `src/evidence_reader/proof.rs` for content,
citations, pins, selections and portable references. Decoded responses preserve
their exact source lineage and bounds. A reference remains subject to current
authorization and profile binding; any runtime convenience handle has explicit
scope/expiry and is not portable evidence. Do not invent a second retrieval store.

### Project configuration and capture integration

Extend the maintained opt-in integration around `scripts/capture-claude-hook.py`
and `tests/test_capture_claude_hook.py`. Keep configuration explicit and separate
from recorded facts. It names allowed project/worktree locations, credential
file references, service endpoints, transcript scope, budgets and reader options;
it contains no embedded credential values and cannot expand its own authorization.
Check public metadata and effective filesystem access before substantive work.
Use the actual hook's transcript path and session identity, never a guessed
Claude project-directory encoding or a search over unrelated transcripts.

Provide supported preflight/start/finalize/health entry points in one maintained
integration. Exact CLI spelling is a design choice, not an existing command claim.
Readiness uses bounded, stage-specific checks of the configured endpoints;
finalization retains the selected transcript prefix and reports drain receipts.
Fail-open hooks remain advisory and visibly report gaps. Session-boundary health
is concise; no per-poll Day entries or mandatory process ceremony is introduced.

### Artifact/profile diagnostics

`src/bin/kan-v2.rs` has intentionally different inputs for `Verify`, `Backup` and
`ReadRecord`; `src/evidence_store.rs` has explicit profile checks. Make those
contracts legible in help and mismatch errors. Establish diagnostics and known
profile controls before deciding whether to extend offline `read-record` to
admitted/copied archives. Any extension must select an explicit proof binding
and preserve authentication semantics, rather than reinterpret the file.

## Delivery sequence

1. Typed discovery and actionable errors, together with the decoded common read
   path and examples. These are one coherent agent-facing retrieval change.
2. Supported project-scoped capture preflight, readiness, health and finalization;
   add artifact/profile diagnostics needed by its backup and read workflows.
3. Integrated remote qualification and one focused review of the changed surface,
   followed by the bounded documentation/fresh-reader/backup-recovery exercise.
   Use targeted checks during implementation, not a new review per small change.
4. Present the qualified beta and routine-capture adoption decision. Keep the
   separate Day compatibility work from becoming a gate on ongoing research.

Use remote Rust qualification; no new local Rust/Lean build, heavy fixture or
repeat of the retained 100 GiB/10 GiB measurements is authorized by this draft.
Preserve project originals, private credentials, failed receipts and prior reviews.

## Resolved Questions

- The owner prioritizes common-path usability over full Day migration.
- Capture/retrieval supplements the concise Day/v1 record and Git artifacts.
- Reuse existing content/session/reference APIs and enforce existing authority
  separation; do not introduce another retrieval or research-provenance system.
- Setup mistakes and explicit unsupported-profile refusals are not relabeled as
  storage corruption. Acknowledgment does not establish capture completeness.
- Whole-system upgrade, live migration and replacement of v1 remain separately
  authorized actions after their actual compatibility gates.

## Open Questions

The maintained entry point is `scripts/kan-project.py --config ABSOLUTE_FILE`
with check/start/stop/hook/finalize/health/claude-settings operations. Configuration
is always explicitly selected, with authorized worktree and transcript roots;
there is no automatic global installation or guessed directory encoding.

Typed read tools cover catalog, discovery, decoded selected/attempt content,
decoded session content and portable-reference reads. The advanced shared API
remains available for audit and optional operations. Opaque signed objects are
copied verbatim, not reconstructed by an agent. Tool help exposes schemas and
examples, with read/write/owner separation unchanged.

This build improves unsupported-profile diagnostics without broadening offline
record-reader capabilities. An admitted/copied record-reader extension is deferred
until its separate proof semantics are needed; no silent profile fallback is added.

## Separate Day compatibility gate

Before replacing v1, qualify the actual Day adapter with existing identities,
author trust, claim references, teloi, atoms, bridges, witnesses, corrections and
source-bound verification/independent-review distinctions. Missing, withheld and
unavailable remain visible. An authored v2 annotation workflow must separately
pass preview/save/readback if selected as the decision-writing path. Merely
pointing current Day wrappers at the v2 executable satisfies none of this gate.

## Out of Scope

Global system-binary replacement; automatic live migration or routing cutover;
original credential changes; complete provider-wire capture; a new summary or
search backend; an automatic claim-promotion authority; full Day replacement in
this beta; semantic changes to prof-comm mathematics; new mandatory reviews of
accepted research; volume deletion; broad historical-fixture reruns; publication
or installation without the applicable later authorization.
