# ADR 50: Structured output: kan's prose stops being an accidental API

- Status: Accepted
- Date: 2026-07-22
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-50

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

**Date:** 2026-07-22
**Status:** Accepted

**Context:** `day` shells out to the `kan` binary rather than linking it
(ADR-42) — the right boundary — and then parsed kan's `show` **output** to get
claims back, because prose was the only thing on offer. v0.7's read-surface
work (REQ-17, REQ-22) changed that output, and `day` broke silently: `day
assess docs` reported "no docs schema is declared" against a log that plainly
declared one. `day`'s parser read the subject label where the kind used to be,
found no `text:` field, and returned every claim empty. `day doctor` still
passed, because it only checks reachability.

**The finding is the coupling, not the break.** Every word kan printed was a
de-facto API with no contract attached. The changes that broke it were
improvements by every measure a human cares about, which is the trap: a
project cannot improve its human-facing output and keep a machine consumer
working, unless the machine consumer is reading something else.

Both repos' tests missed it for the same reason from opposite sides. `day`'s
`tests/kan_conformance.rs` *does* catch it — it fails against the current
binary — but skips when kan is not installed, and kan's CI never runs it.

**Decision:** the read verbs (`show`, `status`, `issues`, `context`) gain
`--json`. The rendered form stays what it is, for people, and stays free to
improve; anything programmatic reads the structured form.

**What makes it a contract rather than another accident:**

- **Versioned.** Every payload carries `v` (`json::SCHEMA_VERSION`), so a
  consumer can refuse a shape it does not understand instead of silently
  misparsing it — precisely what `day` could not do, for want of a version to
  check.
- **Additive-only, `Option` omitted rather than null** — the same discipline
  `docs/SPEC.md` §7.1 applies to claims, so a consumer pinned to an older
  shape keeps working. Adding a field does not bump `v`; that is the point.
- **Named fields for things prose conflated.** `kind` and `subject` are
  separate, and each claim keeps the subject it was *filed under* rather than
  the queried name — the prose renderer attributed every claim in a merge
  class to whichever name you asked for.
- **Structure instead of stringified prose.** Relation kind and target,
  retraction targets, subject titles, status values, and supersession are
  fields, not text a consumer re-parses.
- **The predicate is shared, not duplicated.** `is_open_issue` was factored
  out of `issues` so the rendered and structured surfaces cannot drift on
  *what an issue is* — only on how it is presented. Duplicating it would have
  recreated this ADR's own bug one layer down.

**What this is not.** Not the claim wire format. `transport::git_tree` carries
signed, verifiable records; this carries a rendered *view* — the fold's
output, decategorified, unsigned. Anything that needs to verify a claim reads
the log or a published record. Keeping that line clear is why this lives in
`json.rs` and not near the transport.

**Rejected: freezing the prose.** It would have meant v0.7's read-surface
improvements were unshippable, and every future one too — paying for a
consumer's parsing choice with the legibility of the tool's primary surface.

**Follow-up, not resolved here:** kan's CI does not run `day`'s conformance
suite, so the next break is still caught by the repo that suffers it rather
than the repo that causes it. That is a cross-repo CI question and gets filed
rather than improvised.
