# ADR 29: v0.3 relation surface: `kan relate`, `Rejects` reshaped into its own claim kind, `retract`/`reject` split

- Status: Not recorded contemporaneously
- Date: 2026-07-19
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-29

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
**Decision:** Three related changes closing issue #31 (`.design/v0.3-milestone.md`
REQ-1..6):
1. New CLI/MCP verb `kan relate <a> <kind> <b>` (`actions::relate`) writes
   `ClaimBody::Relation { kind, target }` for `kind` ∈ `{blocks, about,
   manifests-at, depends-on, accepts}` — a `clap::ValueEnum` (`cli::
   RelationKindArg`, kept out of `claim.rs` the same way `StatusValueArg`
   is) that only has these 5 values, so `same-as` is rejected at argument
   parsing rather than by a runtime check. `kan same` stays its own verb,
   unfolded — `SameAs` is the only identity-conferring edge and already
   carries more ceremony (the component-size guardrail, ADR-23's
   Anchor-vs-Anchor rejection) than an ordinary relation.
2. `RelationKind` narrows from 7 to 6 variants: `Rejects` removed.
   `ClaimBody` gains a new top-level `Rejects { claim: Cid }` variant
   (`ClaimKind` gains a matching `Rejects`, sitting beside `Retraction`, not
   nested in `Relation`) — structurally mirroring `Retraction`'s
   `supersedes: Cid` shape, not `Relation`'s `{ kind, target: SubjectRef }`
   shape. Zero-cost correction: no CLI/MCP path ever constructed
   `RelationKind::Rejects`, so no existing log data references the removed
   variant.
3. New verb `kan reject <cid>` (`actions::reject`) writes `ClaimBody::
   Rejects { claim }`, only against a *different* author's claim — erroring
   (`Error::CantRejectOwnClaim`, message naming `kan retract`) on the
   caller's own. `kan retract`'s existing cross-author error
   (`Error::NotYourClaim`) is updated the same way, naming `kan reject`.
   Two verbs with a write-time author check each, not one verb silently
   dispatching between two claim kinds depending on whose claim the CID
   turns out to be — no single call should have two possible fold-time
   meanings depending on facts the caller may not track.
   `fold::identity::excluded_by_rejection(claims, trust) -> HashSet<Cid>` is
   a new sibling to `excluded_by_retraction`, but **trust-gated** (unlike
   self-retraction, which is deliberately `TrustBase`-independent): a live
   `Rejects { claim }` claim excludes `claim` from a viewer's fold only
   when that viewer's `TrustBase` trusts the rejecting author
   (`docs/SPEC.md` §8's "a local suppression honored only by folds that
   trust the rejecter"). Threaded through both `fold::fold`'s general
   claim-visibility filtering and `identity::merge_classes` (a rejected
   `SameAs` witness stops contributing to identity computation for a viewer
   who trusts the rejecter) — the same two threading points
   `excluded_by_retraction` already has. Undo needs no special-casing: a
   `Rejects` claim is itself an ordinary claim CID, so an author retracting
   their own `Rejects` (via the existing `Retraction` mechanism) already
   makes `excluded_by_rejection` skip it.
**Why:** `RelationKind::Rejects` looked like a domain-semantic edge the way
`Blocks`/`About`/etc. are, but isn't one — it doesn't relate two subjects,
it suppresses one specific claim, which is exactly what `Retraction`
already does for same-author claims. Modeling it as `Relation`'s sibling
instead of `Retraction`'s sibling would have meant a `SubjectRef` target
standing in for "the claim I mean," an indirection with no benefit once the
shape mismatch was named directly. The `retract`/`reject` split (rather
than one verb with silent dispatch) follows the same reasoning ADR-21
already used for `resolve`/`block` staying separate from a generic
status-setter: an agent's single action should have exactly one fold-time
meaning, readable from which verb it called, not inferred after the fact
from claim authorship.
**Consequences:** `src/context.rs`'s `render_claim`/`kind_value` gained
match arms for `ClaimBody::Rejects`/`ClaimKind::Rejects` (filed alongside
`Retraction` in the value-scoring tier — bookkeeping, not narrative
content). New tests: `tests/cli.rs` (`relate_writes_a_relation_claim_for_
each_non_identity_kind`, `relate_rejects_same_as_at_argument_parsing`,
`reject_refuses_the_callers_own_claim`), `tests/write_surface.rs`
(`reject_writes_a_rejects_claim_against_another_authors_claim`, the
own-claim library-level counterpart, and the updated `NotYourClaim` message
assertion) — the cross-author success/failure split needs a genuinely
different signing `Identity`, the same reason `retract`'s own cross-author
test lives at the library level, not through the CLI subprocess harness.
`tests/identity_fold.rs` gained the trust-gating pair
(`rejects_claim_excluded_when_viewer_trusts_the_rejecter`/
`rejects_claim_from_untrusted_author_is_not_honored`) plus
`rejected_sameas_witness_does_not_merge_when_rejecter_is_trusted` for the
`merge_classes` threading point specifically. MCP `relate`/`reject` tools
are deliberately deferred to the verb-lexicon-reorg PR (REQ-10..12),
alongside the rest of that PR's MCP param additions, rather than mirrored
here.
