# ADR 0047: Withdraw the `merge=union` guidance: it destroys both sides

- Status: Accepted — supersedes the `merge=union` half of ADR-43
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-47

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

**Date:** 2026-07-21
**Status:** Accepted — supersedes the `merge=union` half of ADR-43
**Context:** An adversarial review of the shipped v0.6.0-beta.1 GitTree
transport tested ADR-43's own divergence story against a real `git merge`,
with `.gitattributes` set exactly as `GITATTRIBUTES_LINE` instructed.

**What was found:** the merge exits 0, reports "4 insertions", raises no
conflict — and both concurrent claims are gone. `merge=union` is **line**-
based. Every record in a `.claims/` file begins with the same boilerplate
lines (`---`, `{`, `"cid": …`), so git aligns the two sides' record
boundaries against each other and unions *inside* a record, welding two
claims into a single malformed record with duplicate `cid`/`sig` keys and a
concatenated body. Parsing it yields `duplicate field 'cid'`.

Without the driver, the same merge raises an ordinary conflict — nine
markers, visible, recoverable by hand. **The guidance we shipped made the
outcome strictly worse than shipping nothing**, converting a visible
conflict into silent destruction.

An aggravating cause, recorded because it matters beyond this ADR:
`Log::iter_all` walks the MST keyed by content CID, so `write_subject`
emits records in CID-lexicographic order, not append order. A new claim
therefore lands at an arbitrary offset mid-file rather than at the tail —
which independently falsifies ADR-43's premise that "a conflict at a file's
tail is itself informative."

**Decision:** ship no merge-driver guidance for `.claims/` at all.
`GITATTRIBUTES_LINE` becomes empty, `gitignore_guidance()` actively warns
against setting one, and the repo's own `.gitattributes` is removed.

**Why not fix the driver instead:** union merge could only be safe if a
record were a single line, or if record boundaries were unique enough that
git could never align across them. Both are format changes, and neither is
true today. Between "no guidance" and "guidance that loses claims," no
guidance wins immediately and unconditionally; a real concurrent-merge
story is part of the v0.7.0-beta.1 correctness release, designed against
this evidence rather than assumed.

**What ADR-43 got right, and keeps:** claims are immutable and additive, so
keeping both sides *is* the correct resolution, and kan still never rewrites
history and still runs no git commands. The error was reasoning from "both
sides should survive" directly to a line-based tool, without checking what
that tool does to this file format.

**Consequence for the invariant:** this is the third confirmed instance of
the same shape — a lossy operation treated as authoritative, resolved
last-writer-wins, in a module that writes bytes rather than one that reads
morphisms. `CLAUDE.md`'s "no operation destroys a subject" was enforced in
`fold/` and never applied to `store/`, `transport/`, or `sign/`. The
v0.7.0-beta.1 correctness release is organized around that boundary rather
than around the defect list.
