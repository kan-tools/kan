# ADR 36: `kan result`: closing issue #41's reachability gap, and sharpening `observe`/`result`/`resolve`'s verbiage

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-36

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
**Decision:** `ClaimBody::Result`/`ClaimKind::Result` (already present in
`src/claim.rs`, already fully handled by `src/context.rs`, never
constructed by any CLI/MCP path) gets a new `kan result <subject> <text>
[--cites] [--file] [--status] [--title] [--kind] [--verbose]` verb —
`.design/v0.4-milestone.md` REQ-1..3. Zero data-model change: this is
purely a new write path, the same "zero-cost, not a migration" shape
ADR-29's `Rejects` reshape had. `subject` is a required positional
argument (matching `resolve`/`block`, not `observe`/`plan`/`decide`'s
`--subject` defaulting to `"general"`) — a result is almost always about
the specific subject the action targeted. Implemented by reusing the
existing `narrative()` helper directly (passing `Some(subject)` so it
never falls through to the `"general"` default), which gives `result` the
same *optional* `--status`/`--title`/`--kind` pairing `observe`/`plan`/
`decide` already have (REQ-9/REQ-7, v0.3) — a natural extension beyond the
design doc's literal minimum text, decided at implementation time: "no
automatic Status pairing" (the design doc's phrasing) means no
*hardcoded* pairing the way `resolve`/`block` have, not that `--status`
shouldn't be offered opt-in like its sibling narrative verbs.

`observe`'s, `result`'s, and `resolve`'s doc comments, CLI help text, and
MCP tool descriptions are all sharpened to state each verb's trigger
condition explicitly (`observe`: "something you noticed... not something
you did"; `result`: "the outcome of an action you just took"; `resolve`:
"...an outcome that also closes the subject out") — REQ-2. `mcp::
get_info()`'s Recording-phase description gains the same three-way
distinction.
**Why:** The issue's own text posed a real, undecided question — keep
`Result` with a dedicated verb, or remove the variant as redundant with
`Observation`. Resolved: keep it, since the distinction (passive finding
vs. outcome of an action taken, vs. outcome that also closes a subject) is
real, mirroring how `Resolution` already differs from `Observation`. But
adding a fourth narrative-adjacent verb narrows the semantic gap an LLM
caller has to navigate — the sharpened, trigger-condition-based wording
exists specifically to keep that gap legible as the verb count grows,
rather than trusting an agent to infer the distinction from claim-kind
names alone.
**Consequences:** New tests in `tests/cli.rs`
(`result_writes_a_result_claim_with_no_status_pairing`,
`result_status_pairs_a_status_claim`,
`help_text_distinguishes_observe_result_resolve`) and `tests/
mcp_server.rs` (the tool-name assertion list grew to include `result`).
`#[allow(clippy::too_many_arguments)]` needed on `result()`, matching the
same pattern already present on `observe`/`plan`/`decide`/`resolve` since
v0.3 (ADR-34's independent adversarial audit already flagged this as a
minor future-cleanup candidate — a params struct would read better — not
a defect; unchanged here, consistent with the existing siblings rather
than fixed in isolation).
