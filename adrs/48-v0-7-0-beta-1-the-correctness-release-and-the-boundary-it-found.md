# ADR 48: v0.7.0-beta.1: the correctness release, and the boundary it found

- Status: Accepted
- Date: 2026-07-22
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-48

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
**Design doc:** `.design/v0.7-milestone.md` (24 requirements, 26 acceptance
criteria)

**Context:** three independent adversarial reviews of the shipped
v0.6.0-beta.1 (issue #48's method — hostile by default, north star recited
from the record, evidence verified rather than accepted) found roughly twenty
confirmed defects, about half of which destroy data. None came from the test
suite; all 105 tests passed throughout. Every one came from running the
binary.

**The finding, which is the point of this ADR.** All three tracks converged
on the same boundary without being told to:

> kan is correct exactly where the design attention went — the fold and the
> cryptographic core — and absent everywhere data is keyed, framed, or
> rendered.

Track 1 counted five lossy derivations in the codebase and found four treated
as authoritative and resolved last-writer-wins; the only one handled
correctly was the one *designed* as a heuristic. Track 3: "the cryptographic
core is sound; the framing layer around it is not." Track 2: "every read
surface reports its filtered view as if it were the whole log."

`CLAUDE.md`'s non-negotiable invariant — *no operation destroys a subject* —
was enforced with real care in `fold/`, the one module that reads morphisms,
and never applied to `store/`, `transport/`, or `sign/`, the modules that
write bytes. **One boundary never crossed, not twenty independent slips.**
That is why this release was organized around the boundary rather than around
the defect list, and it is the most useful thing to carry forward: the next
audit should start wherever a value is derived and then treated as unique.

**What shipped**, by area (PR numbers in parentheses):

*Local spine* — `recorded_at` in signed content, ending the collision where
identical content overwrote itself and could void a retraction (#79); an
`flock` around append plus HEAD revalidation under it, ending concurrent
claim loss (#80); `sync_all` ordering and atomic HEAD replacement (#80);
recovery from a torn CAR tail or lost HEAD, so a damaged log opens instead of
bricking (#82); identity retrievable across a repo move, and an explicit
`KAN_IDENTITY_FILE` escape from a keychain that hangs non-interactively
(#81).

*GitTree* — `text_len` framing, so the writer's own output stops failing its
own reader on trailing whitespace and prose cannot inject a record boundary
(#83); injective filenames (#83); a record format version (#83); header
fields authenticated against the claim they describe (#84); deletion
detection (#84); `publish` folding before it writes (#84); `publish --all`
and a tested merge story (#85).

*Read surfaces* — `cites`/`artifacts`/author/time finally visible, CID
lookup, `context` ranking globally and naming what it omitted, superseded
statuses marked, relations visible from both ends, and descriptions that stop
promising what the surface cannot deliver (#86).

**Format breaks, taken once and deliberately.** `recorded_at` and
`KnownBody`'s `deny_unknown_fields` changed the shape of every newly written
claim, and the GitTree record format went to v2. All were enumerated in the
design doc up front rather than discovered during implementation, because the
argument permitting them expires: the beta has exactly one user, who made
this call about their own data. **This is the last release where that
argument is available.** `docs/SPEC.md` §7.1's coexistence contract carries
everything afterwards, and this release is its first real exercise — which is
also why ADR-44's own worst case had to be closed here (see below).

**ADR-44 was half-implemented and this release found it.** `deny_unknown_fields`
landed on `ClaimContent` and not on the `KnownBody` mirror, so a *known* kind
carrying a field from a newer kan deserialized, silently dropped the field,
and was reported as "altered since it was signed" — verbatim the behaviour
ADR-44 measured and claimed to have eliminated, still live one level down.
§7.1 now states the rule at both levels.

**Two things deliberately not overclaimed:**

- Deletion detection is envelope metadata, not signed. It catches accidental
  loss and naive removal; an editor who rewrites every remaining record's
  `seq`/`of` defeats it. Authenticated deletion detection needs the publisher
  to sign over the record set — a new claim shape, and therefore its own
  design pass rather than something smuggled into a fix.
- `Contested`/`Confirmed` remain unreachable. They need the `PeerContested`
  trust surface, which is v0.8. This release only stopped *promising* them.

**`KAN_AGENT` removed rather than repaired.** Its own source called it "not a
real keypair and nothing verifies it against anything," kan's own `.mcp.json`
set it, and the shipped configuration therefore made the agent surface and
the human surface read disjoint views of one log by default. v0.9's per-agent
identity replaces it wholesale. Repairing something already scheduled for
deletion, in the release whose theme is that provisional patches cause data
loss, would have been the wrong lesson.

**Process notes worth keeping:**

- **Negative controls became mandatory.** PR 3's concurrency test *passed
  against the broken code* on its first run — the child processes serialized
  on their own startup jitter and never actually raced. Every concurrency and
  corruption test in this release is now checked by disabling the fix and
  confirming the test fails. The same omission is why
  `tests/log_cross_process_stress.rs`, sequential despite its name, never
  caught the defect it looks like it covers.
- **A test encoded a defect as a guarantee.** ADR-47's fix had to change
  `assert!(GITATTRIBUTES_LINE.contains("merge=union"))`. The suite was
  verifying the code did what the design said, and the design was wrong.
- **Third confirmed instance of the crate-trust rule paying for itself**
  (after ADR-11/12 and ADR-25): `fs4`'s API does not match what its docs
  suggest — `FileExt` sits at the crate root, not `fs_std`, and the exclusive
  method is `lock()`, not `lock_exclusive()`. Found by reading the source.
- **One defect was nearly misattributed.** The keychain hang surfaced as
  "build a new binary, run it, watch it hang," which is indistinguishable
  from a regression in the change under test. Only reversing the order across
  two scratch copies proved the change was innocent.

**Issue #62 closed as non-reproducible**, not fixed. Retracting every claim
on a subject correctly drops it from `issues`, as do the narrower triggers
tried. Changing code that was right, to close a ticket, is how a defect list
grows fictions.
