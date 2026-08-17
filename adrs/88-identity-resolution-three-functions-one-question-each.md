# ADR 88: Identity resolution: three functions, one question each

- Status: Accepted (shipped in #182)
- Date: 2026-08-06
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-88

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

**Date:** 2026-08-06
**Status:** Accepted (shipped in #182)

**Decision:** `workspace_identity` / `signing_identity` /
`create_workspace_identity`, replacing `existing_identity` and
`load_or_create`'s tri-purpose behaviour. `.design/identity-resolution.md`'s
shape, executed.

- **`workspace_identity`** — *which identity does this workspace have?* Pure:
  never creates, writes or migrates. **One precedence order**, used by reads
  and writes alike, and it **includes the keychain**, which is what closes
  #170. `KAN_IDENTITY_FILE` is deliberately not consulted here.
- **`signing_identity`** — *which identity should sign this write?* A
  selection naming something absent is **always** an error: never a mint,
  never a fallback, never a substitution.
- **`create_workspace_identity`** — the only function that writes an identity,
  which makes the ADR-77 guard a property of the workspace rather than of
  whichever code path reached it. #180 closes **by construction**: the old
  `load_or_create` had five branches that could mint and four called the
  guard; the one that did not is now simply another way for question 1 to
  answer `None`.

**`--trust me` routes through question 2**, not question 1 — "me" is the
identity that would *sign* here, so a role-scoped caller asking "what did I
write" gets the role rather than the human's claims.

**The evidence set stays, and that reverses part of the spec.**
`.design/identity-resolution.md` argued for "no evidence set to maintain".
Removing it entirely let a seed-rooted workspace with an unreachable keychain
re-mint and shadow its own identity — v0.11 round 5's B3 defect, reintroduced.
Caught on the first run by `tests/derived_cells.rs`. The set stays and is now
*correct* rather than absent, and the repair was available **only because
question 1 became pure**: `identity_evidence` can count `.kan/identity-id`,
which the old guard had to exclude because `keychain_account` *wrote* that
file while resolving. Making resolution pure made the guard stronger, as a
consequence rather than as a separate fix.

**Role-registry validation was tried and reverted**, and the measurement is
the argument: requiring a selection to name a declared role took the suite
from 41 failures to 78, because in the CI/`day`/agent workflow
`KAN_IDENTITY_FILE` *is* the identity and the workspace never gets a
`.kan/identity`, so `workspace_identity` is `None` forever and every write
after the first is refused. It broke the configuration the variable exists
for. CLAUDE.md's "affordance, not enforcement" covers the rest: naming an
existing key is asking, and undeclared authorship is surfaced by `kan identity
authors` and narrowed past by `--trust roles`.

**A keychain that errors is not a fallback to a key file.** ADR-53 *deletes* a
plaintext copy matching the keychain and keeps one only when it **differs**,
so a surviving `.kan/identity` beside a live entry is disproportionately the
mismatched case — falling back would sign as a DID that is not this
workspace's identity. A fallback also makes a workspace resolve differently
depending on transient reachability, which is #170's disagreement class moved
from across-paths to across-time.

**`adopt` now retires every root, not one.** It retired the seed and
`seed-id` but never `.kan/identity-id`, which was harmless until this ADR gave
both paths one keychain-consulting order — after which a surviving pointer
outranks the key adopt just wrote, and adopt reports "this workspace now signs
and reads as that identity" while the keychain keeps signing. That is the
adopt→restore dead end of v0.11 rounds 2 and 3, reintroduced by the precedence
choice and found by a cold review, in the command whose own comment calls that
outcome the worst available to a recovery tool (#153).

**Method, because it is the transferable part.** The change landed against a
**derived** cell table (`tests/derived_cells.rs` enumerates the product of the
dimensions and probes both resolvers — 128 configurations) rather than a
curated list, after two cold reviews each found rows missing from a
hand-written one. Its `unset` plane now shows read and write agreeing on every
row. Two cold reviews of the change itself found: a test hollowed out by the
fixture migration, AC-8 defended on one of the two paths it names, and the
`adopt` defect above — none of which the author would have found, and all of
which the suite reported as green.
