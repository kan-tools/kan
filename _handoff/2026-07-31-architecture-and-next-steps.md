# Handoff — 2026-07-31

**Written to a file rather than to `kan observe spine` because the keychain
needs a one-time interactive re-authorisation after the v0.9.1 upgrade (#96).
Once that is done, this content should be recorded on the `spine` subject and
this file deleted — `kan show spine` is meant to be the source of truth, and a
file that competes with it is exactly the second-source-of-truth problem kan
exists to avoid.**

## State

- `main` at the merge of #145; clean, no open PRs.
- **`v0.9.1-beta.1`** released on crates.io.
- ADRs run to **76**.
- `kan show spine` is **stale** — its last entry predates this session's
  architecture work.

## First thing to do

`kan status` in a terminal that can answer a keychain prompt. The v0.9.1 binary
is not the one the keychain authorised, so it blocks (#96). ADR-68's warning
explains this on stderr when it happens.

Backup of `.kan/` from the incident below: `/tmp/kan-backup-1785525469` (may
have been cleared by a reboot; the log itself was never damaged).

## What this session produced

**Two releases.** `v0.9.0-beta.1` (durability + one root of trust, ADRs 63–69)
and `v0.9.1-beta.1` (the bulk read, ADR-72).

**One long architecture pass**, design-only, recorded in
`.design/medium-architecture.md` with ADRs 74–76 and a correction to ADR-70.
**Read that doc before touching sync, identity, or hosting** — it supersedes
ADR-54's publicness ladder and settles six tension points found by walking the
hardest deployment end to end.

Headlines, in case the doc is not the first thing read:

- **There is no linear ladder.** There are *media*; an identity writes to one
  and replicates to others; a projection is `fold(⋃ readable claim media,
  trust)`. v0.8 had already built this without naming it.
- **Conflict resolution is not a problem kan has.** The log is a G-Set;
  union is the merge; convergence comes from the data type, not a protocol.
- **Every hosted service is blind.** Archive, replica, appview — plaintext
  access is a grant to a *named service*, never a property of the substrate.
- **Agents are derived roles.** `HKDF(seed, "kan/v1/agent/" + label)`, vouched
  by claim, enrolled as a member. Most of it shipped in v0.9's role registry.
- **The key authenticates the content** — now seen three times (`.claims/`
  filenames, identity bindings naming their repo, record keys as content CIDs).
- **Deletion is a medium event, never a claim event**, and non-destruction is
  a *local* invariant.

## The incident, and why it matters more than it looks

Recording this handoff into kan hit a real defect: **`KAN_NO_KEYCHAIN` bypasses
the `WouldMintSecondIdentity` guard** and minted a second identity against this
repo's own log. Filed as **#146**. No data was lost; `repo.car` was never
written.

Two things worth carrying forward:

1. **The escape hatch reopened the defect the milestone was hardening
   against.** `KAN_NO_KEYCHAIN` was added in ADR-66 so v0.9's own tests could
   run on macOS. It took a code path with no guard.
2. **The crash was the lucky part.** The index rebuild does not dedupe
   `log ∪ overlay`, so the duplicate CID raised `UNIQUE constraint failed`. Had
   it deduped, the workspace would have opened under a new identity and
   reported `no subjects yet` against a 3.7 MB log — #90's silent version. So
   **fix the guard before the dedupe**; deduping alone makes it worse.

## Next steps, in order

1. **#146 — the guard bypass.** Live defect, data-invisibility class. Move the
   guard out of the `KAN_IDENTITY_FILE` branch so it covers every minting path;
   then make the `log ∪ overlay` overlap an assertion rather than a dedupe,
   since overlap means the author test misclassified something. Add a
   with/without-`KAN_IDENTITY_FILE` axis to the migration matrix — it currently
   drives every cell with the variable set, which is why it never caught this.
2. **#116 — `RelationKind::{Supersedes, Refutes}`.** Requested by the math
   research build. Cleanly specified, additive under ADR-44, same shape as
   #60's `InTensionWith`.
3. **#131 + #92 together** — both are the `of` field meaning something a
   per-subject file cannot guarantee with two writers. ADR-76 generalizes #92
   from `.claims/` to every medium, so take them as one pass. Any fix changes
   the tracked `.claims/` format, so it is a migration with a matrix row.
4. **#136** — KAN_AGENT orphans; match an author by DID irrespective of
   `agent`. Touches the fold.
5. **#90 item 3** — do not persist a minted keychain account until it is
   known-good. Now applies to `seed-id` as well as `identity-id`.

**Design-only work queued** (each its own pass, not folded into the above):

- The `TrustBase` generalization from `author → weight` to `claim → weight`
  that ADR-75's scoped delegation needs. A fold change; wants negative
  controls.
- Q4 in `.design/medium-architecture.md` — the enforcement departure from
  `CLAUDE.md`'s "affordance, not enforcement". Encryption shrank it to a
  capability check on ciphertext, but it still needs recording as deliberate.

## Decisions still owed

- **#121** — is `Solo` the right default. Deferred four times; its inputs have
  changed twice (foreign-claim consumption became real; multi-role shipped). It
  may be two decisions rather than one.
- **#67** — now load-bearing rather than academic: time-bounded delegation
  (ADR-75) is only as strong as a self-attested timestamp, and a notary is what
  would fix it.
- **`kan-infra`** — does not exist. The archive needs no server (S3-shaped), so
  only the replica is blocked on it.

## Cross-repo

`day` can upgrade to v0.9.1 and collapse its whole-log read to one invocation
(`kan show --all --json`, #123). Its Frames design pass is unblocked. day#88
(harness config preferring kan/day over native Claude memory) is filed and
unstarted.
