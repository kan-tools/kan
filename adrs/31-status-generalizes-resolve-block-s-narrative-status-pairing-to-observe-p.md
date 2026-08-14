# ADR 31: `--status` generalizes `resolve`/`block`'s narrative+status pairing to `observe`/`plan`/`decide`

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-31

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
**Decision:** `kan observe`/`kan plan`/`kan decide` gain an optional
`--status <value>` flag (REQ-9, `.design/v0.3-milestone.md`). When given, it
writes a `ClaimBody::Status { value }` claim citing the narrative claim —
the exact pairing mechanism `resolve`/`block` already hardcode
(`Resolution`→`Resolved`, `Blocker`→`Blocked`), generalized to any
narrative kind and any `StatusValue` instead of two special cases.
`kan resolve`/`kan block` are unchanged — their fixed pairing stays
hardcoded, since that pairing is inherent to what those two kinds *mean*,
not a special case needing generalization; adding `--status` to them too
would let a caller write a contradictory pair in one call (e.g. `resolve`
citing `Status{Blocked}`), which the fixed pairing structurally prevents.
`actions::NarrativeResult` (introduced in ADR-30 for the `Subject` claim)
gains a second independent optional field, `status: Option<AppendResult>`,
alongside the existing `subject` one — `--status` and `--title`/`--kind`
compose freely in one call (a single `kan plan` can write up to three
claims: narrative, status, subject), each validated/written independently.
**Why:** Before this, only `resolve`/`block` could pair a narrative claim
with a status change in one call; `observe`/`plan`/`decide` needed a
separate `kan mark` call to do the same. Some previously-impossible-in-one-
call combinations (e.g. `Decision` + `Status{Closed}`, or `Observation` +
`Status{Resolved}` when `resolve`'s specific `Resolution` framing doesn't
fit what actually happened) had no path without adding a new verb per
combination. Generalizing the existing pairing mechanism instead of adding
verbs keeps the verb count fixed while closing the gap.
**Consequences:** `narrative()` (the shared helper `observe`/`plan`/`decide`
funnel through) now writes up to three claims in sequence — narrative,
then status (if given, citing the narrative CID), then subject (if given)
— via a new `maybe_status_claim` helper mirroring `maybe_subject_claim`'s
shape. `src/mcp.rs`'s `observe`/`plan`/`decide` tool implementations pass
an extra `None` for the new `status` param — real MCP `status` params are
REQ-12, scoped to the verb-lexicon-reorg PR. New tests in `tests/cli.rs`:
`observe_status_pairs_a_status_claim_citing_the_narrative` (AC-6) and
`plan_status_and_title_kind_together_write_three_claims` (composing REQ-9
and REQ-7 in one call).
