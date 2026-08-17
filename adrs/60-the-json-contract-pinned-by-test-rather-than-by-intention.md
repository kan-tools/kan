# ADR 60: The `--json` contract, pinned by test rather than by intention

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-60

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

**Date:** 2026-07-30
**Status:** Accepted

**Decision:** `.design/v0.8-milestone.md` REQ-5/AC-5. `tests/json_contract.rs`
pins the field set of every `--json` envelope and `SCHEMA_VERSION` itself, and
`json::SCHEMA_VERSION`'s doc comment states the contract a consumer pins to.
ADR-50 established the additive-only rule; this makes breaking it fail CI
instead of ship.

**Subset, not equality.** Each test asserts the pinned names are *present*,
never that no others are. Equality would fail on every added field, which
would convert the additive-only rule into a frozen-shape rule and make the
test something people delete rather than heed. Both directions are verified:
renaming a pinned field fails exactly one test, and adding a new field passes.
A pin that only ever fires one way is not a control.

**Per-kind fields need per-kind specimens.** `title`, `status`,
`relation`/`target`, and `supersedes` are all `skip_serializing_if` and
mutually exclusive by body kind, so no single specimen claim could exercise
them. The test builds one claim per kind, which also makes the omission
obvious if a new body variant lands without a pin.

**An unknown claim kind serializes as a claim, not as a failure.**
`kind: "Unknown"`, and deliberately **no `text`** — an unrecognized body has
no narrative this build can read, and emitting one would be fabrication. This
is SPEC §7.1/ADR-44's tolerance carried into the machine surface: a newer
actor's claims must not take out an older actor's entire view of a shared
tree, which is precisely what an aborting parse would do.

**Why this is worth a test rather than a note.** The failure it prevents has
already happened once. `day` parsed kan's prose for want of anything else;
v0.7's read-surface work changed that prose, and `day assess docs` began
reporting "no docs schema is declared" against a log that plainly declared
one — a silent breaking change delivered by a change that improved every
measure a human cares about. The research loop is about to build an external
linter on this surface, so it needs to be a contract, not a shape that happens
to hold today.

**Consequences:** `SCHEMA_VERSION` stays `1`. Everything v0.8 added (`trust`,
`excluded_by_trust`) is additive, so no consumer pinned to `1` breaks. The
version test failing is the designed prompt to ask whether a change really
required a bump — the answer is usually no, and when it is yes that belongs in
an ADR.
