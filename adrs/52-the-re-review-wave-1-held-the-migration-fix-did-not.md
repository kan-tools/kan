# ADR 52: The re-review: Wave 1 held, the migration fix did not

- Status: Accepted
- Date: 2026-07-23
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-52

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

**Date:** 2026-07-23
**Status:** Accepted

**Context:** an independent adversarial review of the four commits that landed
after `v0.7.0-beta.1` (Wave 1 ergonomics, and the #107 migration fix), run
before cutting the point release those commits are for. Verdict: REDIRECT.

**Wave 1 held under attack**, which is worth recording as much as the defects:
the both-forms subject argument refuses the ambiguous case on all six verbs
and lands claims on the subject meant; the recovery phrase is genuinely off
argv (EOF-clean, no echo, no alternate path); `--version` matches. And the
ADR-49 fixes re-verified — D1 (append-after-recovery survives a reopen from
disk) and D4 (a `SameAs`-merged publish is subject-exact) both hold on the
binary.

**The migration fix reintroduced the exact class it was fixing.** #107 existed
because `file_name` was lossy and let two subjects collide into one file. The
fix keyed the *deletion* of the superseded file on `legacy_file_name` — the
same lossy mapping — so publishing `telos/x` deleted a different subject
`telos_x`'s file and reported that it had rewritten those claims. A write path
destroying another subject's data, keyed on a value that is not unique. The
non-negotiable invariant, violated by the fix for a bug of the same shape.

**This is the fifth instance in one development cycle** of one pattern:
*a value derived from richer data, then trusted as a unique key for an
operation that mutates or destroys.* MST key from content CID; `.claims`
filename from sanitized subject; keychain account from path; `HEAD` as a
single cell; and now the legacy filename as a deletion key. ADR-48 named the
class; ADR-49 found two more instances in its own fixes; this one makes the
rule explicit and permanent:

> **`legacy_file_name` is lossy by construction. It may be a read hint and
> nothing else — never a key for a delete, an overwrite, or an
> authorization.** Any operation that removes or authorizes must key on the
> content (the CID, the record's own signed subject), never on a name derived
> from it.

**Also from this review, worth keeping:** D-B was a *tautological guard* —
`bytes == import(bytes).export()` — on a key-deletion path, which never
compared the file it was about to delete. It passed every test because it was
trivially true. A guard that cannot be false is not a guard, and it is the
same failure as ADR-49's test that could not fail: a check written in the
shape of a check, verifying nothing. Both are now caught only because the
review runs the tool rather than reading the assertions.

**Process note:** the re-review was run because ADR-49 established that the
previous round's *fixes* were where the worst defects lived. That reasoning
held again — every defect this round was in code the prior round added, none
in the original v0.7 surface. The standing conclusion: a round of fixes to a
BLOCK/REDIRECT gets its own review before it is trusted, not a presumption of
correctness because it is "just the fixes."
