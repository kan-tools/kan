# ADR 23: `Anchor`-vs-`Anchor` `SameAs` rejected as a witness, enforcement ahead of syntax

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-23

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

**Date:** 2026-07-17
**Decision:** `fold::identity::merge_classes` now excludes a `SameAs`
witness from the identity fold's graph whenever either side (`from` or
`to`) is a `SubjectRef::Anchor` — the same exclusion path an untrusted or
cross-author witness already takes, not a separate error type. No CLI
syntax exists yet to construct an `Anchor` subject, so this only fires
against library-constructed claims today; covered by a direct unit test in
`tests/identity_fold.rs` (`sameas_touching_an_anchor_is_not_honored`),
matching that file's existing pattern for other library-only scenarios
(untrusted witnesses, cross-author retraction).
**Why:** `docs/SPEC.md` §5.1 states plainly: "SameAs between two Anchors is
a TYPE ERROR, not a claim" — `Anchor` identity is strict and decided by
construction (content-addressed, computed identically by every actor), so
asserting two Anchors are "the same" is a category error, not a
disagreement a trust policy could ever resolve. Landing the enforcement now,
before any CLI path can construct an `Anchor` subject, means the follow-up
issue that adds that syntax inherits an already-tested guard rather than
having to remember to add one itself.
**Consequences:** None of `kan`'s current write verbs are affected — no
CLI/MCP surface constructs `SubjectRef::Anchor` yet (a deliberately separate
follow-up, out of v0.2's scope per `.design/v0.2-milestone.md`). The check
is defensive infrastructure, verified correct now rather than assumed
correct later.
