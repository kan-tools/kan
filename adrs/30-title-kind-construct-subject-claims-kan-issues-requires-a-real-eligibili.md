# ADR 30: `--title`/`--kind` construct `Subject` claims; `kan issues` requires a real eligibility signal, not just "never resolved"

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-30

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
**Decision:** Two related changes closing issue #32 (`.design/v0.3-milestone.md`
REQ-7..8):
1. `kan observe`/`kan plan`/`kan decide`/`kan block`/`kan resolve` all gain
   optional `--title <text> --kind issue|idea|question` flags
   (`cli::SubjectKindArg`, kept out of `claim.rs` the same way
   `StatusValueArg`/`RelationKindArg` are), required together — validated
   (`actions::validate_title_kind`) *before* any claim is written, so a
   lone `--title` or `--kind` never leaves a partial write (an orphaned
   narrative claim with no `Subject`, or vice versa). When given, an
   additional `ClaimBody::Subject { title, subject_kind }` claim is written
   alongside whatever the verb already writes. `observe`/`plan`/`decide`'s
   return type changes from bare `AppendResult` to a new
   `actions::NarrativeResult { narrative, subject: Option<AppendResult> }`;
   `resolve`/`block`'s existing `PairedAppendResult` gains a third
   `subject: Option<AppendResult>` field alongside its `narrative`/`status`
   pair. Both keep the bare-CID-by-default contract pointed at the
   *narrative* claim's CID regardless of whether the optional `Subject`
   claim was written — `--verbose` is the only way to see it.
2. `actions::issues` no longer treats "this subject has never had a
   `Status` claim" as equivalent to "open." A class is now only
   issue-*eligible* — checked before "done" is even considered — when it
   has at least one live `Status` claim (any value; presence of the claim
   kind is the signal, not which value) **or** its most recent live
   `Subject` claim declares `SubjectKind::Issue`. A class with neither
   signal is excluded entirely, not marked done.
**Why:** `ClaimBody::Subject`/`SubjectKind` existed in the type system since
early on but had no construction path and no behavioral consumer — pure
reachability debt (issue #32). Giving it real weight needed both halves at
once: writing it (part 1) would have been inert without `issues` actually
reading it (part 2), and fixing `issues` without a way to write `Subject`
claims would have left "declare this an issue before it has a status" with
no mechanism. The bug `issues` fix corrects is real and was live on this
very repo: `kan issues` listed `spine` — kan's own dogfooding log, which has
only ever carried `Observation`/`Plan`/`Decision` claims and structurally
never should carry a `Status` one — as an open issue, purely because
"never resolved" and "never opened" were conflated. Requiring `--title`/
`--kind` together (rather than defaulting a bare `--kind` to some
placeholder title, or vice versa) follows the same reasoning `ClaimBody::
Subject`'s own shape already forces: both fields are non-optional, so a
partial value has no honest claim to write.
**Consequences:** `NarrativeResult`'s introduction is additive, not a
redesign — `AppendResult` is untouched and still used everywhere a single
claim is written (`same`/`relate`/`retract`/`reject`/`mark`).
`PairedAppendResult` gaining a field is source-compatible with every
existing read of `.narrative`/`.status`. `src/mcp.rs`'s existing
`observe`/`plan`/`decide`/`resolve`/`block` tool implementations now pass
`None, None` for the two new params at their `actions::` call sites —
real MCP `title`/`kind` params are REQ-12, scoped to the verb-lexicon-reorg
PR, not this one. New tests: `tests/cli.rs` gained
`observe_title_and_kind_writes_a_subject_claim` (AC-7 success),
`observe_title_without_kind_errors`/`observe_kind_without_title_errors`
(AC-7 error half, both directions),
`issues_excludes_a_subject_with_no_status_and_no_declared_issue_kind`
(AC-8, the exact `spine`-shaped regression case), and
`issues_lists_a_subject_declared_as_issue_kind_before_any_status_claim`
(AC-9).
