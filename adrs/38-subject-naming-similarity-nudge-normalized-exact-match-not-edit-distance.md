# ADR 38: Subject-naming similarity nudge: normalized exact match, not edit-distance

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-38

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
**Decision:** `actions::warn_similar_subjects` (issue #47,
`.design/v0.4-milestone.md` REQ-6..8) checks a write verb's target subject
name(s) against every existing live subject's exact literal spelling,
using a cheap case/separator-normalized key (`-`/`_`/whitespace stripped,
case folded — `normalize_subject_name`) — not edit-distance/typo-tolerant
matching. A normalized match against a *different* literal spelling
produces a warning line naming both spellings; computed from the
pre-write state and surfaced without ever blocking the write (CLI:
stderr; MCP: appended to the confirmation text, since MCP has no side
channel separate from its own tool response). Fires on all 9
subject-taking write verbs: the 5 Recording verbs (`observe`/`plan`/
`decide`/`block`/`resolve`), `result` (REQ-1, PR1/ADR-36), and the 3
Structuring verbs (`same`/`relate`/`mark`) — both the `a` and `b`
positions for `same`/`relate`. `observe`/`plan`/`decide` only check when
the caller explicitly supplied `--subject`; defaulting to `"general"`
isn't something the caller typed, so it can't be a naming-variant typo.

**Correction to `.design/v0.4-milestone.md`'s REQ-7**: that requirement's
text names "all 8 subject-taking write verbs," listing 5 Recording + 3
Structuring — omitting `result`, even though `result` (a *positional*-
subject verb, the same shape as `resolve`/`block`) was defined by REQ-1 in
the exact same design doc. Caught and fixed at implementation time: 9
verbs, not 8, `result` included — treated as ordinary engineering
correction (`.design/v0.3-milestone.md`'s own precedent: "implementation-
time details... are ordinary engineering, not open design questions"),
not a scope change needing a fresh design pass.
**Why normalization, not edit-distance:** the one concrete failure mode
reported (#47 — `f1-c1`/`F1-C1`/`f1_c1`, a real beta-tester hitting exactly
this) is caught 100% by normalization alone, with zero new dependencies
(no crate-trust-spike question, matching v0.2/v0.3's zero-new-deps
precedent — confirmed via an empty `Cargo.toml`/`Cargo.lock` diff for this
whole PR). Edit-distance adds a real false-positive risk a nudge feature
can't afford: too loose a threshold and genuinely-different short subject
names (`f1-c1`/`f1-c2`) start warning against each other, which trains an
agent to ignore the nudge entirely. Deferred until real usage shows
normalization alone isn't catching enough, not guessed at now.
**Consequences:** New tests in `tests/cli.rs`
(`naming_nudge_warns_on_a_case_separator_variant`,
`naming_nudge_is_silent_for_a_genuinely_different_subject`,
`naming_nudge_fires_on_structuring_verbs`, `naming_nudge_fires_on_result`)
and `tests/mcp_server.rs`
(`naming_nudge_appends_a_warning_to_the_confirmation_text`). The
computation lives once in `actions::warn_similar_subjects`, called
explicitly from each CLI/MCP write call site (via small `subject_warnings`
helpers in `cli/mod.rs` and `mcp.rs`) rather than folded into `append()`
itself — `same`/`relate` need to check two candidate names against one
shared fold view, which a single-subject helper inside the shared
`append()` path can't express without complicating every other caller
that only ever has one subject.
