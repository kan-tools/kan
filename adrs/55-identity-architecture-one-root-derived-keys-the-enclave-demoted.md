# ADR 55: Identity architecture: one root, derived keys, the enclave demoted

- Status: Accepted
- Date: 2026-07-28
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-55

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

**Date:** 2026-07-28
**Status:** Accepted

**Context:** the #105 identity design pass (`.design/identity-architecture.md`),
opened threat-model-first (the mandate: every past identity decision was made
against an unstated model, which is why they don't compose). It supersedes the
framing of #7/#30/#69/#90/#96/#104 as one problem. Two forks were worked
through and resolved in-session; this ADR records them and the threat model
they were decided against.

**Threat model (stated before any mechanism):** T1 local attacker / stolen
disk; T2 curious-or-malicious sync remote (new with ADR-54 — a remote that holds
the log); T3 malicious repo remote / hostile `.claims/` (forgery already caught
by signature verification, the residual risk is a *restore* trusting the wrong
identity, #90); T4 hostile or buggy local agent (writes indistinguishable from
the human's — `KAN_AGENT` was removed, not replaced); T5 compromised dependency
exfiltrating key material at signing time.

**Q1 — the enclave cannot be the root.** The three candidate resolutions were
framed as a menu, but two assumed the Secure Enclave could hold the root key,
which the hardware forbids: the enclave never imports externally-derived keys,
is Apple-hardware-only (kan runs in CI/containers/Linux and under `day`
subprocesses), and its no-prompt path needs a stable code-signing identity a
locally-rebuilt binary and a `day` subprocess lack — the actual mechanism of
#96. The real structure is an **impossibility triangle**: a single key cannot be
phrase-reproducible (REQ-3) **and** no-prompt-everywhere (REQ-4) **and**
non-extractable (T5). REQ-3+REQ-4 are load-bearing for agents and durability, so
they win and **T5 is accepted as residual at the root**.

- **The root** is a phrase-derived, file-resident seed → signing key,
  reproducible and no-prompt on every platform; at-rest protection is OS file
  permissions plus the existing keychain path where present, **not** the
  enclave.
- **The enclave returns later**, only for *signing* and only as the deferred
  **two-layer end-state**: an escrowed phrase-reproducible root that *certifies*
  enclave-held per-device signing sub-keys (non-extractable → closes T5 for
  signing), claims signed by the device key and attributed to the root. This is
  the same machinery as REQ-6 (per-agent keys) and the sync doc's multi-device
  question — multi-device is multi-signing-key-under-one-root, a fold. It
  touches the fold, `AuthorId`, and `TrustBase`, so per the "don't touch the
  fold without a measured reason" rule it is its own later milestone, named not
  built here.

**Q2 — HPKE to derived X25519 keys, per-space-epoch wrapping.** kan is
append-only, so sharing is monotonic: an immutable claim cannot be
re-encrypted, a reader who could decrypt it keeps that ability, and removal
stops *future* access only. **Revocation is future-only by construction** — the
same truth as the L3/L4 ratchet, stated as kan's stance rather than hidden. This
rules out MLS (forward-secrecy/churn machinery kan cannot honor over immutable
claims, plus a delivery service it lacks) and a static group key (no membership
story). The primitive is **HPKE (RFC 9180)** wrapping a per-space-epoch content
key to each member's derived **X25519** encryption key; membership change starts
a new epoch for future claims while past epochs stay readable by prior members,
with an optional explicit grant-history re-wrap. `age` was the runner-up (same
recipient model, off-the-shelf) but is a file format rather than a KEM
primitive. The full protocol is the HostedRelay/#7 E2EE pass (ADR-35 M1); this
pass names the primitive.

**Key separation, done right (and the footgun avoided).** The signing key stays
**P-256** (`did:key`, ADR-4, REQ-8, unchanged); the encryption key is a derived
**X25519** key — the textbook sign/encrypt split, which *avoids* the
Ed25519→X25519 conversion footgun by deriving independently rather than
converting. The encryption key is per-*identity* (all of one human's devices
derive the same one from the phrase, so any device decrypts shared spaces),
while the two-layer signing sub-keys are per-*device* — multi-device adds
attribution keys without multiplying encryption recipients.

**Migration (first-class, because #107 proved that is where these break).**
Today's phrase encodes the P-256 key directly; a seed-derived scheme changes
that. Resolution: **grandfather each existing signing key** verbatim as the
signing slot (every existing DID and signed claim stays valid), introducing the
seed only for the new encryption/sub-keys. Existing identities are
`{grandfathered signing key + new seed}`; only new identities get full "one seed
derives everything." This preserves the DID by construction — the only form that
makes the #90/#107 failure impossible, not merely discouraged. Migration must
prove existing claims stay readable on a real log with a negative control (a
fresh binary must not silently mint a new DID — the #90 guard at
`sign::load_or_create` extended to the seed path), per ADR-52's rule.

**What stays open, by design (not this pass's questions):** the HPKE
epoch/grant-history protocol and relay wire (HostedRelay/#7 pass), and the
`did:plc` migration (atproto pass, ADR-35 M5). REQ-8 keeps a `did:key` so that
road stays open.

**Status of the build:** none. This is a design pass; implementation is its own
later work, and the two-layer signing end-state is a separate milestone from the
root-and-encryption-keys work because only the former touches the fold.
