# ADR 0066: Seed-rooted new identities, grandfathered old ones, and where the root lives

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-66

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

**Decision:** `.design/v0.9-milestone.md` REQ-4/REQ-6/REQ-7. A workspace
created from v0.9 onward is **seed-rooted**: a 32-byte root secret from which
the signing key (`kan/v1/sign`) and the encryption key (`kan/v1/encrypt`) are
both derived. A workspace that already had an identity is **grandfathered** —
same key, same DID, no seed, nothing rewritten.

**Two schemes coexist permanently, and that is the safe form rather than the
untidy one.** Migrating existing identities onto a seed must either preserve
the signing key (making the seed decorative) or replace it (moving every
existing DID and dropping every claim out of every read). The second is #90 and
#107 exactly. Grandfathering makes that outcome *impossible* rather than
unlikely, which is the only standard worth holding after two shipped
occurrences.

**The migration decision is one predicate**, and freshness is decided from
files alone — never by probing the keychain. A keychain probe on that path can
hang for a rebuilt binary (#96), and hanging while deciding whether to mint an
identity is the worst possible place to do it.

**Where the root lives: the OS keychain when available, a `0600` file when
not** — exactly how the signing key is stored today (ADR-25).

This overrode a first implementation that wrote the seed as a plaintext file
unconditionally, following ADR-55's "file-resident seed" literally. An existing
test caught it: issue #6's property is that a brand-new identity leaves *no*
plaintext secret on disk, and the seed path had quietly reopened that for every
new workspace — a strictly worse at-rest posture than the version it upgrades
from. ADR-55's own wording ("OS file permissions **plus the existing keychain
path where present**") sanctions the keychain reading, and callers who genuinely
need no-prompt already set `KAN_IDENTITY_FILE`, which bypasses all of it
unchanged. The no-prompt-everywhere property was being bought with every new
user's root secret, which is not a trade ADR-55's threat model actually asked
for.

**The derived signing key is never written anywhere.** It is a pure function of
the seed, so storing it would be a second copy of one secret. A seed-rooted
workspace therefore has *fewer* secrets at rest than a v0.8 one, not more.

**A phrase now has two readings, and kan reports both rather than guessing.** A
seed-rooted workspace's phrase encodes the seed; a grandfathered one's encodes
the signing key. Both are 24 words of BIP-39 entropy and nothing distinguishes
them. A marker byte was rejected (it collides with a legacy key whose first
byte matches — 1 in 256, not rare enough for a recovery path) and so was a
shorter phrase (it buys distinguishability by cutting the root's entropy).
Ambiguity resolvable against a workspace that knows its own author is better
than either, so `kan identity restore` reports what the phrase yields under
each reading and says which one — if either — is this repo's.

**`KAN_NO_KEYCHAIN` is new**, and is the missing middle of the
`KAN_IDENTITY_FILE` story: today the only way to avoid a keychain prompt is to
name a specific key file, which suits an agent managing its own key and not
someone who simply wants `0600` files. It exists because this milestone's tests
could not otherwise run on macOS — exercising fresh-workspace creation means
*not* setting `KAN_IDENTITY_FILE`, which means touching the keychain, which for
a rebuilt binary is #96's hang. A suite that hangs locally and passes on CI is
worse than one that fails.

**Verification.** `tests/seed_identity.rs` covers both schemes; inverting
grandfathering fails exactly the two tests asserting an existing identity
survives, and no others. The migration matrix (ADR added with the workflow)
independently re-checks all nine released versions' workspaces against this
build, which is what turns "grandfathering works" from a claim about the code
into a claim about every kan a user could be upgrading from.
