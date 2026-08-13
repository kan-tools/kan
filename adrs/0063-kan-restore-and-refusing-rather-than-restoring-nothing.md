# ADR 0063: `kan restore`, and refusing rather than restoring nothing

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-63

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

**Decision:** `.design/v0.9-milestone.md` REQ-1/REQ-2
(`.design/durability-log-recovery.md` REQ-2/REQ-3). `kan restore` rebuilds
`log/repo.car` from the tracked `.claims/` tree, ingesting every record whose
author matches this repo's identity. It is the inverse of `publish`, and it is
almost entirely v0.8's machinery pointed the other way: `GitTree::
read_all_with_rev` for the read, `Log::ingest` for the write, with the author
test deciding the destination.

**The new logic is the refusal, not the restore.** When *nothing* in the tree
was signed by this identity, restore writes nothing and exits non-zero, naming
`kan identity restore` and the recovery phrase. That case is not hypothetical
— it is what a lost signing key looks like from the inside. You point restore
at a tree full of your own past work, a freshly-minted identity reads it as
someone else's, and a silently-empty restore would *confirm* the data is gone
rather than reveal that the identity is what went missing. #93's "identity
recovery gates log recovery", enforced at the one place it bites, and the #90
failure made loud instead of silent.

**The refusal says what it found, not only what it wanted.** It lists the DIDs
that *do* appear in the tree, because the actionable question for the operator
is "is one of those me, under a key this checkout lost?" — and it points at the
overlay path (`kan show --trust <did>`) for the case where the claims are
genuinely another actor's and no restore is needed at all.

**Restore never widens `log/repo.car`.** Foreign-authored records stay the
overlay's business (ADR-59), so the local log keeps meaning *claims I
authored* — the property atproto repo semantics require and that a future
HostedRelay/AppView reads from. `tests/restore.rs` asserts it, and removing the
author filter fails exactly the two tests that encode the identity boundary
while the happy-path restore still passes. That is the point of the control:
a restore that hoovered up the whole tree would look correct from the outside.

**Consequences:** `kan restore` is a top-level verb outside the four CLI phases
(setup/tooling, like `identity` and `mcp`). The name deliberately sits beside
`kan identity restore` rather than avoiding it: one restores the identity, the
other restores the log, and #93's rule is that the first gates the second —
which the refusal message makes explicit rather than leaving to be inferred.
Restore is idempotent (`Log::ingest` returns `None` for a record already
present) and reports how many were already there, so running it twice is safe
and says so.

**A gap this surfaced, filed rather than fixed here:** two actors publishing
*the same subject* into one tree collide on one filename, since a published
file is named per subject. Found while building a fixture, not by a test that
was looking for it. It is a tree-merge question rather than a restore one, and
it is adjacent to #92's `of`-rewriting problem.
