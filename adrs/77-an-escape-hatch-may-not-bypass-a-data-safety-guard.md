# ADR 77: An escape hatch may not bypass a data-safety guard

- Status: Not recorded contemporaneously
- Date: Not recorded contemporaneously
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-77

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

**Context.** `WouldMintSecondIdentity` (#90's fix) refuses to create a signing
key when the log already holds claims, because a new DID plus `TrustBase::Solo`
takes every existing claim out of every read at exit 0. It was written inside
the `KAN_IDENTITY_FILE` branch of `Identity::load_or_create`, which made it a
property of one code path.

ADR-66 then added `KAN_NO_KEYCHAIN` so this project's own tests could run on
macOS, where the keychain is not usable non-interactively (#96, #69). That
variable reaches `load_or_create_plaintext` without passing the guard. On a
workspace whose key is in the keychain — and whose plaintext copy ADR-53
correctly deleted — it minted a second identity against a 3.7 MB log (#146).
Two further paths turned out to do the same: the keychain's `NoEntry` branch,
and v0.9's seed-rooting, whose freshness test reads identity files only.

**Decision.** A guard protecting against data loss is a property of the
workspace, not of the code path that happens to reach it. It is stated once and
every path that can mint calls it. The condition — *a new identity would be
created and the log is non-empty* — never had anything to do with which
mechanism was minting, so the mechanism appears only in the remedy text.

More generally: **an escape hatch added for operability may not weaken a
correctness guarantee.** A hatch that skips a slow or interactive step must
still traverse the checks on the path it is skipping. Where it cannot, that is
a reason to reconsider the hatch, not to accept the gap.

**Consequences.** `add_role` remains the one deliberate bypass, and stays a
bypass on purpose: minting a role is an explicit act, which is the operator
signal the guard exists to wait for. The error carries what was about to mint
and the remedy for that mechanism.

The migration matrix gains an identity axis (`identity-file` / `seed`). Every
cell previously drove `KAN_IDENTITY_FILE` — the one branch that short-circuits
the other two — so no cell could reach the defect. That is the recurring
method note in its sixth instance: **the check compared against the wrong
thing.** A harness driving one shape cannot see a defect living in the other.

**What this ADR does not cover, because running it disproved the premise.**
#146 also proposed asserting on a `log ∪ overlay` overlap instead of deduping,
on the reasoning that an overlap means the author test misclassified something.
It does not. A declared role (ADR-58) genuinely *is* a different author from
the primary that wrote the log, so it correctly reads the primary's published
records as foreign — and the same `UNIQUE constraint failed` crash reproduces
through publish-then-read-as-a-role with no identity defect anywhere. The
assertion was implemented as specified and broke that supported flow on its
first run. `ingest_published` now skips what the log already holds, whoever
signed it; the assertion remains behind it as an invariant check that should
never fire.
