# ADR 0061: `--trust roles` covers the primary identity, found by dogfooding

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-61

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

**Decision:** Declaring the first role also records the workspace's existing
signing identity as a role named `primary`, so `--trust roles` covers claims
written *before* any role existed.

**How it was found, which is the point.** Not by a test written for it — the
v0.8 suite was green — but by walking the research loop's actual scenario end
to end with the built binary: primary identity writes, two roles get declared,
each role writes, then read it back. `--trust roles` as the prover returned 2
of 3 claims and reported one excluded. Every unit of that was behaving as
specified; the specification was wrong.

**The gap.** `--trust roles` expanded to "declared roles plus the *active*
identity". A workspace's original identity is neither declared (it predates
`role add`) nor active (once `KAN_IDENTITY_FILE` points at a role), so it fell
through both. The obvious command — "show me everything this workspace wrote"
— silently omitted the entire pre-roles history.

**Why it was still worth fixing given the disclosure worked.** The exclusion
*was* reported (`excluded_by_trust: 1`), so this was never the silent-loss
class ADR-57 exists to end. It was the wrong answer to the obvious question,
which is a different and lesser defect — but the argument in ADR-58 for putting
the active identity in the alias ("leaving it out would make the obvious
command quietly drop the caller's own claims") applies verbatim to the identity
that was active *before*, and applying an argument to one case and not its twin
is how surfaces end up inconsistent.

**Why at `role add` and not at read time.** Once `KAN_IDENTITY_FILE` names a
role, kan never consults the keychain — deliberately, since that is the whole
reason the override exists (ADR-25, #96). So the primary's DID is not
discoverable at read time at any acceptable cost. Declaring the first role is
the one moment it is guaranteed loaded and in hand.

**Consequences:** `.kan/roles` gains a `primary` row on first `role add`, whose
`key_path` records where that key is *looked up* — for a keychain identity, an
account path rather than a file that exists. A workspace that declared roles
under the v0.8 PRs before this one keeps working and simply lacks the row; a
`role add` after upgrading adds it, and naming the DID explicitly works
regardless. `trust_roles_covers_claims_written_before_any_role_existed` is the
regression test; `declared_roles_are_listed_with_their_dids` was updated rather
than deleted, since its old assertion ("active is never a declared role") was
exactly the wrong belief.

This is the fourth consecutive release where the scope-defining defect came
from running the tool rather than from the issue tracker or the suite (ADR-51's
review chain, v0.8's own `WouldMintSecondIdentity` finding, and this). Worth
stating as a pattern: the suite checks what was specified, and dogfooding is
what checks whether the specification was right.
