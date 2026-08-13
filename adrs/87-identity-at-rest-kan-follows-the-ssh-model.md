# ADR 87: Identity at rest: kan follows the ssh model

- Status: Accepted (REQ-3 implements)
- Date: 2026-08-06
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-87

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
**Status:** Accepted (REQ-3 implements)

**Decision:** the key lives in a **file**; encryption at rest is an **opt-in
passphrase**; a platform keystore is one place to put that passphrase rather
than a higher tier; and an **agent is a later, well-triggered follow-up**
rather than v0.12's opening move.

**The correction that produced it.** `.design/identity-resolution.md` opened
on "agent pattern vs status quo" and treated an agent as an *alternative* to a
key file. It is not one. In ssh and gpg alike the key lives in an encrypted
file and the agent holds the *decrypted* copy in memory after one unlock,
acting as a signing oracle. The agent is not the storage layer.

Three layers kan had been making one mechanism do:

1. **At rest, encrypted** — a passphrase-encrypted file *or* a platform
   keystore. The keystore is an alternative to a passphrase, not a tier above.
2. **In use** — the agent, caching one unlock per session.
3. **Non-interactive** — an unencrypted `0600` file, *deliberately*. A GitHub
   Actions deploy key is exactly this. This layer is part of the design.

kan's error was never that `KAN_IDENTITY_FILE` exists. It is that the variable
was implemented as *redefine this workspace's identity* (question 1) rather
than *here is where the key is* (layer 3). ADR-88 separates those.

**The consequence, which inverts the spec's own sequencing:** an agent is only
worth having if the key is encrypted at rest, because its entire job is
caching an unlock. kan's key today is in the keychain or in a plaintext file;
in neither case is there an unlock to cache. So the agent question is
*downstream* of the at-rest question, and asking it first was backwards. The
trigger for building one is stated rather than vague: when `kan identity
protect` has enough adoption that typing the passphrase gets old.

**#96 and #69 are one cause, and it is code signing.** A macOS keychain item
carries an ACL of trusted applications; "Always Allow" binds the grant to the
calling binary's *code identity*, and an unsigned binary gets a new one every
rebuild. Signed, notarized applications do not have this. Established by
reading the dependency rather than assuming: kan resolves `keyring 4.1.5` with
default features `["v1"]` → `apple-native-keyring-store/keychain`, the
**legacy file keychain**, which is exactly the store that ACL belongs to. The
crate's `protected` backend targets the modern data-protection keychain, which
has no trusted-application list, but needs an entitlement and therefore a
signed binary — unverified, and permitted one timeboxed spike.

**What REQ-3 does and does not buy.** It makes the keychain opt-in, so #96
stops firing on the default path. That is a lesser claim than fixing it, and
#96 is re-scoped to say so. The larger prize is testability: every identity
test must set `KAN_NO_KEYCHAIN` or a rebuilt binary hangs, so the
keychain-reachable plane is **unreachable from the suite** — #170, #180 and
the `adopt` defect of ADR-88 all lived there, and none could have been caught
by a test. Moving the default off the keychain moves that plane into the
falsifiable one.

**Passphraseless by default**, on structural grounds rather than preference:
kan has no `kan init`, so the only place a prompt could go is inside the first
write, which would hang CI, `day` and the MCP server. `kan identity protect`
is where prompting belongs, and `read_secret_line`'s off-TTY branch means
`echo "$PASS" | kan identity protect` works, so provisioning scripts need no
terminal. An explicit `kan init` is filed as #173.
