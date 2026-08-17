# ADR 83: `TrustBase::Local` is the default: a read needs no identity

- Status: Accepted
- Date: 2026-08-04
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-83

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

**Date:** 2026-08-04
**Status:** Accepted

**Decision:** `.design/identity-surface.md` REQ-1. The base every read folds
under, absent `--trust`, becomes `Local` — every `AuthorId` appearing on a
claim in `.kan/log`. `Solo` remains reachable as `--trust me`.

**Why the default and not `Solo`.** `Solo`'s member is *me*, so every default
read had to resolve an identity in order to know whom to trust. That single
line is why a read minted one (#149), why an upgrade that re-minted took the
whole log out of every read (#90), why two role identities in one workspace
could not see each other (#121), and why a legacy `KAN_AGENT` author was
invisible (#136). Four issues and a deferred decision were one defect seen
from five directions.

**#90's failure mode disappears rather than being guarded against.** "A binary
upgrade silently mints a new identity, taking the whole log out of every read"
is a description of `Solo`. Under `Local` a re-minted identity is a nuisance:
the claims already in the log are still authored by authors in the log. The
ADR-77 guard stays because minting is still wrong; it stops being a
data-visibility event.

**It is a no-op for a single-author workspace, and that is checkable rather
than asserted.** `tests/fixtures/golden/single-author-reads.txt` was generated
against the pre-change binary and committed on its own PR *before* any
behaviour changed; it has passed unmodified through every commit since. AC-1
was the milestone's gate: had it not held, the approach was to be revisited
before anything else was written.

**Membership is the log, never the overlay.** The log is what was written
*through* this workspace; the overlay is what *arrived at* it as a committed
`.claims/` file. Foreign claims already arrive without sync, so folding
"everything present" would let a merged pull request inject a stranger's
claims into the maintainer's default view. The index records each claim's
origin, because `fold` sees both sets together and cannot tell them apart.

**Delivered at the level of authors, not claims.** `TrustBase` is a per-author
predicate, so a `.claims/` file whose author has *also* written to this log is
folded in without an explicit `--trust`. REQ-6's text was corrected to say so.
The claim-level property needs the fold to see origin per claim, and is
scheduled for v0.12 with #164 — decided, and recorded on the
`identity-surface` subject: origin is a trust signal in its own right rather
than inert packaging.

**Consequences.** `publish` folds under the same base (REQ-10), so the sharing
layer still cannot contradict the fold; a multi-role workspace's first
`publish --all` after upgrading produces a visible diff as files gain the
other roles' claims. The JSON envelope reports `base: "Local"` with every log
author at weight 1.0, so ADR-57's shape is unchanged — a new value, not a new
field.
