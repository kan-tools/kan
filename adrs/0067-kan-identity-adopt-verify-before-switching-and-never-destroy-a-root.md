# ADR 0067: `kan identity adopt`: verify before switching, and never destroy a root

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-67

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

**Decision:** `.design/v0.9-milestone.md` REQ-8, closing the actionable half of
#90. `kan identity adopt --key <path>` points a workspace at a signing key it
already has claims from. The documented way out of #90 was editing
`.kan/identity-id` from a stack trace, which is less a recovery path than an
invitation to make things worse.

**It verifies before it switches, and that is the whole difference from
hand-editing.** A key that authored *none* of the log's claims is refused, with
the DIDs the log does contain named. Someone reaching for this has already lost
track of which key is theirs; adopting the wrong one would leave the log
invisible under a *second* identity and give them every reason to conclude the
data is gone. Adopting into an empty log is allowed — there is nothing to
contradict.

**It reads a key that exists and never creates one.** `load_or_create`'s whole
contract is to produce a key one way or another, which is exactly wrong here:
quietly minting the identity someone is trying to recover from losing is the
failure this command exists to end. Hence `Identity::load_existing`.

**Retiring a displaced seed, found only by testing it.** A seed-rooted
workspace derives its identity from the seed *before* looking at any key file,
so writing the adopted key without retiring the seed left adopt reporting
success and changing nothing — the single worst outcome for a recovery command,
and one that reads perfectly fine in the source. Adopt now moves the seed aside
to `seed.replaced-<epoch>` and drops a keychain seed reference, **never
deleting**: it is a root secret, and nothing in a recovery path should be
confident enough to destroy one it cannot put back. A keychain-held seed is
left in the keychain and merely unreferenced, which is the most this can do
without destroying something.

**A correction recorded rather than quietly fixed.** The migration table's
"what this does not cover" note originally named adopt as the fix for the
`KAN_AGENT` orphan case. It is not, and the reason matters: those claims have
the *right* key — the DID matches exactly — and differ only in
`AuthorId.agent`, so there is nothing to adopt. `--trust` cannot reach them
either, since a trust base names `AuthorId`s and `agent` is part of one. The
real fix is read-side, matching an author by DID irrespective of `agent`; it
touches the fold and is filed as #136 rather than smuggled into a command it
does not fit. The note in `tests/fixtures/migration-expectations.tsv` carries
the correction, because a wrong pointer in a table people consult during an
incident is worse than no pointer.

**Consequences:** `kan identity adopt` joins `identity did`, `phrase`,
`restore`, `encryption-key`, and `role` under the setup/tooling verb group.
Negative control: disabling the authored-nothing check fails exactly the
refusal test and no other.
