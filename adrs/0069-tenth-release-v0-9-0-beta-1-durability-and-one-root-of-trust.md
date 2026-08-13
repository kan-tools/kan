# ADR 0069: Tenth release: v0.9.0-beta.1, durability and one root of trust

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-69

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

**What it is:** the two tracks ADR-35 had in separate releases, taken together
because both converge on #93's "identity recovery gates log recovery" from
opposite sides — a restore is only a restore if one escrowed secret reproduces
the exact signing DID, which is what the root work establishes. Seven PRs, each
requirement-scoped and CI-green:

- **#130 (ADR-63)** — `kan restore`, and the refusal when nothing in the tree
  is this identity's.
- **#132 (ADR-64)** — the `unpublished`/`published`/`stale` durability column.
- **#133 (ADR-65)** — the derived X25519 encryption key.
- **#134** — the migration matrix.
- **#135 (ADR-66)** — seed-rooted new identities, grandfathered old ones.
- **#137 (ADR-67)** — `kan identity adopt`.
- **#138 (ADR-68)** — a blocking keychain read that says what it waits on.

**Why minor, not patch:** three new verbs (`restore`, `identity adopt`,
`identity encryption-key`), a new additive `--json` field (`durability`), and
new on-disk files (`.kan/seed`, `.kan/seed-id`). All additive: `SCHEMA_VERSION`
stays `1`, and a v0.8 workspace opens unchanged — grandfathered, never
migrated.

**What makes that last claim checkable rather than asserted.** The migration
matrix runs all nine prior releases' workspaces against this build on every PR
touching identity or storage, and every one reads `ok`. "An upgrade does not
lose your log" stopped being a property of the code review and became a
property of CI. It is the most valuable thing in this release and it was not in
the milestone doc — it came from asking how migration should prove itself.

**Why still beta:** the v1 scope fence is not closed. #30 survives v0.9,
narrowed: ADR-55's two-layer signing and enclave-held per-device sub-keys touch
`AuthorId` and `TrustBase` and remain their own milestone. #121's default-trust
question is deliberately open, and its inputs changed when consuming foreign
claims became real.

**The pattern this release confirms, now with four instances in one milestone.**
Every defect that mattered came from running or testing rather than reading,
and all four had the same shape — *the check compared against the wrong thing*:
a durability column keyed on a timestamp `publish --all` never updates; a
migration harness scoring a working guard as data loss; a plaintext seed
reopening #6, caught by a v0.6-era test firing three milestones later; and
`adopt` reporting success while changing nothing on a seed-rooted workspace.
Each read as correct in the source. A green suite plus a wrong comparison is
indistinguishable from correctness, which is the whole argument for the matrix
and for dogfooding before calling anything done.
