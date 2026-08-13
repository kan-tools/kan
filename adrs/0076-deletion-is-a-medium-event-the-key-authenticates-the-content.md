# ADR 0076: Deletion is a medium event; the key authenticates the content

- Status: Accepted
- Date: 2026-07-31
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-76

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

**Date:** 2026-07-31
**Status:** Accepted

**Decision:** `.design/medium-architecture.md`. atproto repos are CRUD; kan has
one withdrawal mechanism and no notion of the other two. This records what each
means.

**Update is prevented structurally.** kan records in an atproto repo are keyed
by their **content CID**, so `putRecord` with different content under the same
key is a detectable contradiction — the key states CID X, the content hashes to
Y. Immutability stops being a rule anyone must respect and becomes a property
of the addressing.

That is the **third instance of one pattern**: `.claims/`'s filename
authentication (ADR-43 REQ-13), the rule that an identity binding must name the
repo it is found in (ADR-74), and now record keys. Stated generally so it is
not rediscovered a fourth time: **the key authenticates the content.**

**Deletion is a medium event, never a claim event.** A claim's existence is not
a property of any medium — it is a signed object, and a log, a `.claims/` tree,
and a PDS are all places it happens to be. A record vanishing means *no longer
published there*, not *withdrawn*. Inferring retraction from absence would let
deletion silently perform a fold-affecting operation kan explicitly says it is
not.

kan already behaves this way: `git_tree`'s `missing_records` reports removed
records as an **anomaly**, not a retraction. This generalizes #92 from
`.claims/` to every medium.

**The invariant is local, and that is the honest statement.** "No operation
destroys a subject" holds absolutely inside `.kan/`. At any medium kan does not
control it is a *convention*, and deletion there is genuinely destructive:
retraction preserves what was withdrawn, deletion removes it, and if that
medium was a reader's only source the claim is gone for them.

**And deletion is probably legally required**, which reframes atproto's CRUD as
answering a constraint rather than being careless about immutability. A hosted
service that cannot delete cannot operate in most jurisdictions. kan meets this
the moment it hosts anything: the archive drops an object trivially; the
replica can delete a record but other members have already synced it, so
**erasure at a service is not erasure globally** and promising otherwise would
be false; and an appview must honour deletion *and not re-derive from its own
cache*, which would quietly resurrect deleted data.

**Retraction propagation is an appview correctness requirement**, distinct from
T3's completeness. An appview serving a repo must serve that repo's
`Retraction` claims — omitting one misstates the repo's own position, which is
misrepresentation rather than incompleteness. `Rejects` is different: it is
another author's, trust-local, so an appview serves it as a claim and applies
nothing, since honouring rejections centrally would be the appview applying
someone's trust base — the folding it must not do (`docs/SPEC.md` §8).

T3's per-repo commitment already makes the first enforceable: a client
verifying against the commit root *notices* a missing retraction. For
cross-repo selections, which have no commitment, the spec rule is **if you
return a claim, you return its retractions** — cheap for an appview already
indexing them, and the difference between being opinionated about what you see
and being wrong about what you saw.
