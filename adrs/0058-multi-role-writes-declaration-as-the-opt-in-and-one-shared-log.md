# ADR 0058: Multi-role writes: declaration as the opt-in, and one shared log

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-58

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

**Decision:** `.design/v0.8-milestone.md` REQ-4/REQ-6. A workspace may hold
several signing identities ("roles"), declared by `kan identity role add
<name> [--key <path>]`, which mints the role's key deliberately and records
`<did>\t<name>\t<path>` in `.kan/roles`. `kan identity role list [--json]`
reads them back. Reads select them with `--trust roles`, which expands to
every declared role **plus the active identity**.

**Declaration, not a flag on the write verbs.** The milestone left the shape
open between `--as <role>` and a registered role set; the registry won it for
a reason worth recording. A per-write flag is something a script sets once and
carries blanket, so the "deliberate" signal decays into ambient configuration
— which is precisely the property the `WouldMintSecondIdentity` guard needs
and cannot get from an env var. Declaring a role is a separate, one-time,
auditable act, and `role list` makes the result inspectable later. It also
gives `--trust roles` something real to expand, so the read side needs no
second registry.

**The guard is not weakened.** `add_role` reaches `load_or_create_plaintext`
directly — `load_or_create` minus the guard — and nothing else does. An
*undeclared* second identity against a non-empty log is refused exactly as
before, with the refusal now naming the supported path instead of only saying
no. `tests/multi_role.rs`'s negative control is the assertion, and inverting
the guard fails exactly that one test and no other, which is what makes it a
control rather than a restatement.

**Registering one key twice is refused, both ways.** A duplicate *name* and a
duplicate *DID* are separate errors: one identity under two role names would
make attribution ambiguous in every read. Re-running `role add` against an
existing key file loads it rather than regenerating, so a repeated declaration
can never destroy a signing key — asserted by comparing the DID across the
attempt.

**Q2 resolved: one shared `.kan/log`, not a log per role.** Settled by test
rather than argument. The stated worry was the commit chain: `Log` stamps the
*opening* identity's DID into every `Commit`, so a shared log's chain is
heterogeneous. It costs nothing on the read path — the fold reads claim
authors, and `Log::get_stored` verifies each record against its **own**
author, so no read consults a commit signer at all. Four alternating writes by
two roles survive intact with both authors distinct
(`one_shared_log_survives_roles_writing_alternately`), which is where a lost
`reload_if_stale` would have shown up as one role's claims overwriting the
other's.

The forward-looking cost is real and worth naming now rather than
rediscovering: atproto's repo model is single-signer, so a heterogeneous
commit chain is a thing the sync layer will have to reconcile — most likely by
giving each role its own repo at sync time while keeping one local log. That
is a sync-layer decision (ADR-35's staging plan), not a reason to split the
local log today, and splitting now would buy a hypothetical at the cost of a
demonstrated-working simplicity.

**Why `--trust roles` includes the active identity.** Excluding it would make
the obvious command — "show me everything this workspace's own identities
wrote" — quietly drop the caller's own claims, a smaller instance of exactly
the bug this milestone exists to fix. A caller wanting a hierarchy rather than
a flat union names DIDs and weights explicitly; `roles=0.5` is rejected rather
than silently meaning something, since the alias expands to a set.

**Consequences:** `.kan/roles` is machine-local and gitignored with the rest
of `.kan/` — a role is a local process arrangement, and the shareable part is
the claims roles write, which already carry their own author. A malformed line
is skipped rather than fatal: the file only ever *widens* a read, so a
hand-edit typo must not take out every command that opens a workspace. This is
the interim plaintext-key-file form for process roles that #115 and ADR-48/49
frame as acceptable-by-design; ADR-55's derived-key per-agent model is
untouched and still a later milestone.
