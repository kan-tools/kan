# Feature: Identity architecture — one root of trust, derived keys, threat-model-first

## Summary

kan has no identity *architecture* — only an accumulation of decisions made one
release at a time (keychain over file, plaintext fallback, `KAN_IDENTITY_FILE`,
recovery phrase), each against an implied threat model nobody wrote down, which
is why they don't compose (#105). This pass replaces that with a single
human-held root of trust from which signing, encryption, and per-agent keys are
**derived** rather than independently minted, held under an explicit retention
policy, and escrowed as one recoverable secret. It supersedes the framing of #7
(E2EE), #30 (per-agent identity), #96/#69 (keychain unusable non-interactively),
#90 (silent identity mint) and #104 (phrase via argv) as *one* problem. Per the
#105 mandate this doc **states the threat model before any mechanism**, and
treats **migration as a first-class requirement**, because #107 proved that is
exactly where these changes break. This is the opening design pass; the enclave
resolution (the central fork) is stated here and deliberately left open for
resolution, not guessed.

## Threat Model

Stated first, because every past identity decision was made against an unstated
one and looks different depending on which actors are in scope. The actors kan's
identity system must be reasoned about against:

- **T1 — Local attacker / stolen disk.** Someone reads `.kan/` on a lost or
  seized machine. Today: the keychain protects the key at rest on macOS; the
  `KAN_IDENTITY_FILE` plaintext path and the pre-v0.7.1 plaintext duplicate did
  not (both since narrowed, ADR-53). The key *is* the identity, so disk theft
  is identity theft.
- **T2 — Curious or malicious sync remote.** New with ADR-54: a remote that
  holds the log (the L1 backup, and any L2+ relay) can read whatever is not
  encrypted before it leaves the machine. This is the actor the E2EE story
  (#7) exists for, and it is why the encryption key is not optional once a
  remote exists.
- **T3 — Malicious repo remote / hostile `.claims/`.** A git remote serving a
  tampered `.claims/` tree, or a poisoned clone. kan already verifies every
  record's signature against its own author (`GitTree::read_all`,
  `src/transport/git_tree.rs`) and authenticates filenames against records — so
  forgery is caught, but a *restore* that trusts the wrong identity (#90) is
  the residual risk this pass must close.
- **T4 — Hostile or buggy local agent.** An agent (or `day`, ADR-42) running
  under the human's identity can write claims indistinguishable from the
  human's, because there is no sub-identity today (`KAN_AGENT` was removed, not
  replaced — `src/workspace.rs`). #30's per-agent keys are the answer, and they
  must not become a per-agent *approval-prompt* multiplier (#69/#96).
- **T5 — Compromised dependency.** A malicious crate in kan's tree could
  exfiltrate key material at signing time. Non-extractable enclave-held keys
  bound the blast radius (the key never enters kan's address space); an
  in-process file key does not. **Accepted as residual risk at the root**
  (Q1 resolution): a phrase-reproducible, no-prompt key must be materializable
  in-process, so T5 is unreachable together with REQ-3+REQ-4, which win. T5 is
  closed only later, and only for *signing*, by the two-layer certified-device-
  key end-state (enclave-held device sub-keys) — not at the root.

Several past decisions look different under T2/T5 (which were never named) than
under T1 alone (the only one implicitly considered). Requirements below are
tagged with the actors they address.

## Requirements

- REQ-1: one root, derived not minted — a single master seed derives the
  signing key, the encryption key, and per-agent sub-keys via
  domain-separated derivation (HKDF with distinct `info` strings, or SLIP-0010
  paths), so each is cryptographically independent yet reproducible from one
  escrowed secret. **Not** key reuse — the signing key must not also be the
  encryption key (reusing one P-256 pair for ECDSA and ECDH weakens both).
  Addresses: "one thing to back up," #7, #30. **Migration asterisk (Q1):**
  "the seed derives the signing key" holds only for *new* identities; existing
  ones grandfather their current signing key as-is to preserve the DID (see
  Migration), introducing the seed only for the new encryption/sub-keys.
  (T1, T2, T4)
- REQ-2: identity recovery gates log recovery — the signing DID must be
  reproducible *before* the log is read, never as a consequence of reading it.
  This is `.design/durability-log-recovery.md` IREQ-1 and it makes the restore
  path of that pass possible at all — a log restored under a DID you cannot
  reproduce is one `Solo` trust hides entirely (#90). (T3)
- REQ-3: one secret reproduces the DID — one escrowed secret must reproduce the
  exact signing `did:key`. Holds today (`sign::from_recovery_phrase` → `did`,
  `src/sign.rs:485`); every candidate resolution below must preserve it, or
  restore (durability IREQ-2) breaks. (T1, T3)
- REQ-4: no interactive prompt on any read/sign/restore path — every fold read,
  every claim signing, and restore must complete with no GUI/keychain prompt.
  This has caused three incidents (#96) and is a hard requirement, not a
  preference — a signing key reachable only interactively is unusable by the
  agents kan exists to serve. Constrains where key material may live and how it
  is authorized. (T4, and the operational core of #69/#96)
- REQ-5: recipient/group encryption, not only self — the encryption capability
  must support encrypt-to-a-recipient-set, not only encrypt-to-self, because
  the publicness ladder's permissioned rungs (L2/L3, ADR-54) need it —
  `.design/sync-remote-and-publicness-ladder.md` REQ-6 /
  `.design/durability-log-recovery.md` IREQ-5. Self-encryption alone builds
  only the L1 backup. (T2)
- REQ-6: per-agent identity as a derivation path, not a distributed keypair —
  #30's per-agent (and per-device, `sync-remote-and-publicness-ladder.md` Q2)
  identity is a derivation path off the master seed, not a new keypair to
  distribute and revoke — which is most of what makes #30 hard. Sub-keys must
  be attributable in `AuthorId` (`src/workspace.rs:110`) without partitioning
  the log the way `KAN_AGENT` did. (T4)
- REQ-7: secret input paths matter as much as output — the phrase must never
  reach argv (#104, closed in v0.7.1 — `src/cli/mod.rs` reads it from stdin),
  and any new "paste your seed / enroll this device" flow this pass introduces
  must specify where that secret enters and never through the command line.
  (T1, T5)
- REQ-8: still a `did:key` — whatever this becomes must still produce a
  `did:key` for signing (ADR-4, SPEC §10), or the atproto sync roadmap (ADR-35
  M5) breaks. P-256 (ADR-4's choice for platform support) is also the Secure
  Enclave curve — a happy accident that may make the enclave resolution cheaper
  than it looks. (T3, and roadmap continuity)

## Acceptance Criteria

This is a design-only pass; criteria are decisions locked and artifacts
produced, not code.

- [ ] AC-1: The threat model (T1–T5) is stated before any mechanism, and each
      requirement is tagged with the actors it addresses (checkable: every REQ
      carries a `(T…)` tag).
- [ ] AC-2: The key-separation scheme is specified concretely enough to
      implement — the derivation function, the domain-separation inputs, and
      which key is signing vs. encryption vs. sub-key (including the per-agent
      derivation paths) — with a rationale for the curve choice(s) that keeps
      REQ-8's `did:key`. (REQ-1, REQ-6, REQ-8)
- [ ] AC-3: The central enclave tension (Q1 below) is resolved to exactly one
      of the candidate resolutions, with the threat actors that decide it named
      — not left as "an enclave, somehow"; and the resolution states where the
      master seed / any device-enrolment secret enters, never via argv. (REQ-3,
      REQ-4, REQ-7)
- [ ] AC-4: The migration section specifies whether existing DIDs are preserved
      or re-minted, and if re-minted, exactly how existing claims stay readable
      under a reproducible DID (the #90/#107 failure made impossible, not merely
      discouraged). (Migration, REQ-2)
- [ ] AC-5: REQ-5's recipient/group encryption scheme is named at least to the
      level of "which primitive, keyed how," so the HostedRelay pass (ADR-54)
      can build the L2/L3 rungs against it rather than rediscovering it. (REQ-5)
- [ ] AC-6: The pass records an ADR (**ADR-55**) and this doc is folded into
      kan's log (observe/plan/decide), and #7/#30/#69/#90/#96/#104 are
      cross-referenced as resolved-in-framing by it.

## Architecture

The shape, from #105, with the mechanism sketched and the one fork left open.

**Derivation (REQ-1, REQ-8).** A master seed (the escrowed secret) feeds
domain-separated derivation:

```
recovery phrase ──► master seed ──┬──► signing key   (did:key, P-256, ADR-4)
   (escrowed)                      ├──► encryption key (E2EE / recipient-set, #7)
                                   └──► per-agent/-device sub-keys (#30, paths)
```

The sharpening the obvious reading gets wrong: "the DID's key seeds encryption"
must mean *a master seed derives both keys*, not *the signing key is also the
encryption key*. Key separation is not pedantry — reusing one P-256 pair for
ECDSA and ECDH weakens both, and the Ed25519→X25519 conversion has sharp edges
(cofactors, signature malleability). The clean form is master seed + HKDF/
SLIP-0010 with distinct `info`/paths, giving independent `sign` and `encrypt`
keys and per-agent keys as further paths (which is what makes #30 tractable
rather than a distribution problem — REQ-6). Concretely (Q2 resolution): the
signing key stays **P-256** (`did:key`, ADR-4, unchanged) and the encryption
key is a derived **X25519** key — the textbook sign/encrypt curve split, which
also *avoids* the Ed25519→X25519 conversion footgun above by deriving
independently rather than converting. The encryption key is per-*identity* (all
of one human's devices derive the same one from the phrase, so any device can
decrypt shared spaces), while the two-layer signing sub-keys are per-*device* —
so multi-device adds signing keys for attribution but does not multiply
encryption recipients.

**Recipient encryption for L2/L3 (REQ-5, Q2 resolution).** Because kan is
append-only, sharing is monotonic — a claim is immutable and content-addressed,
so a reader who could decrypt it keeps that ability, and removal stops *future*
access only. Revocation is future-only *by construction*, the same truth as the
L3/L4 ratchet, stated as kan's stance rather than hidden. This rules out MLS
(forward-secrecy/churn machinery kan can't honor over immutable claims, and a
delivery service it doesn't have) and a single static group key (no membership
story). The primitive is **HPKE (RFC 9180)** wrapping a **per-space-epoch**
content key to each member's X25519 key: claims encrypt under the epoch key;
adding a member wraps forward (with an optional explicit "grant history"
re-wrap of past epochs — itself a recorded escalation); removing a member starts
a new epoch for future claims while past epochs stay readable by whoever held
them. Steady-state cost is per-membership-change, not per-claim. The full
protocol (epoch transitions, the grant-history operation, the relay wire) is the
HostedRelay/#7 E2EE pass (ADR-35 M1); this pass names the primitive.

**Where the operative key lives (REQ-4) — resolved (Q1).** kan today loads a
P-256 keypair from the keychain, or a plaintext file under `KAN_IDENTITY_FILE`
(`sign::load_or_create`, `src/sign.rs:114`), and signs in-process
(`identity.sign`). The root key is **phrase-derived and file-resident** on
every platform — reproducible (REQ-3) and no-prompt (REQ-4) — with at-rest
protection from OS file permissions plus the existing keychain path where
present, **not** the enclave. The enclave cannot be the root: it cannot import
an externally-derived key (enclave keys are generated in-enclave, never
imported), it is Apple-hardware-only while kan runs in CI/containers/Linux and
under `day` subprocesses, and its no-prompt path depends on a stable
code-signing identity that a locally-rebuilt binary and a `day` subprocess lack
— which is the actual mechanism of #96. The impossibility triangle behind this:
a single key cannot be phrase-reproducible **and** no-prompt-everywhere **and**
non-extractable; REQ-3+REQ-4 are load-bearing for agents and durability, so
non-extractability (T5) is not achievable at the root and is accepted as
residual there.

**The enclave's future home (the two-layer end-state, deferred).** T5 is closed
later, only for *signing*, by a two-layer identity: the escrowed phrase-
reproducible root (rarely used — only to certify devices and recover) plus
per-device **signing** sub-keys that are enclave-held (non-extractable),
generated in-enclave, and *certified by the root*, with claims signed by the
device key and attributed to the root. This is the same machinery as REQ-6 and
the sync doc's multi-device Q2 — multi-device is multi-signing-key-under-one-
root, a fold. It **touches the fold, `AuthorId`, and `TrustBase`**, so per the
"don't touch the fold without a measured reason" rule it is its own later
milestone (built when per-agent/per-device identity is), not this pass. This
pass ships the file+phrase root and *names* this as the end-state.

**Attribution without partition (REQ-6).** `KAN_AGENT` hashed an env var into
`AuthorId.agent` and, because `TrustBase::Solo` trusts exactly one `AuthorId`,
silently partitioned the log (`src/workspace.rs:110` doc comment). Per-agent
sub-keys must be real derived keys whose `AuthorId`s are *trusted together* by
default (a `PeerContested`-like base over one human's own sub-identities), so
the human sees one merged view while each agent's writes stay attributable —
the opposite of what `KAN_AGENT` did.

**Coupling to the sync remote (ADR-54).** The encryption key (REQ-1/REQ-5) is
what the L1 backup encrypts under and what the L2/L3 permissioned rungs share to
a recipient set. A remote is threat actor T2. So this pass and the sync/remote
pass merge at the encryption key, and REQ-5 is the concrete thing HostedRelay's
design depends on.

## Migration

First-class, because #107 proved migration is where identity changes break, and
because #90 is a migration failure in miniature (a binary upgrade minting a new
DID and hiding the whole log). The pass's design is **incomplete without a
resolved migration story**, and the acceptance bar is that the #90/#107 failure
is made *impossible*, not merely discouraged.

The specific hazard: today's recovery phrase encodes the P-256 key **directly**
(24 words → key bytes, `sign::recovery_phrase`/`from_recovery_phrase`). A
master-seed scheme where the signing key is *derived* changes that relationship.

**Resolved (Q1): grandfather the existing signing key.** Migration preserves
each existing identity's current P-256 signing key verbatim as the "signing
key" slot — every existing DID and every signed claim stays valid — and
introduces the master seed only for the *new* derived keys (encryption,
sub-keys). So existing identities are `{grandfathered signing key + new seed
for encryption}`; only *new* identities get full "one seed derives everything."
This preserves the DID by construction, which is the only form that makes the
#90/#107 failure impossible rather than merely discouraged. The rejected
alternative — re-minting a derived DID with a signed old→new bridge attestation
folded so old claims stay attributed — is more machinery and more risk for no
gain, since grandfathering already keeps every claim readable. Migration must
still prove existing claims stay readable across the upgrade on a real log,
with a negative control (a fresh binary must **not** silently mint a new DID —
the guard from #90 already exists at `sign::load_or_create` and must be
extended to the seed path), per ADR-52's discriminating-test rule.

## Resolved Questions

**Q1 (resolved): the enclave cannot be the root; the root is phrase-derived and
file-resident; the enclave returns later as certified device sub-keys.** Two of
the three candidate resolutions assumed the enclave could hold the root key,
which the hardware forbids — the Secure Enclave never imports externally-derived
keys, is Apple-hardware-only (kan runs in CI/containers/Linux and under `day`),
and its no-prompt path needs a stable code-signing identity a rebuilt binary
lacks (#96's real mechanism). The real structure is an impossibility triangle —
a single key cannot be phrase-reproducible **and** no-prompt-everywhere **and**
non-extractable — and REQ-3+REQ-4 win because they are load-bearing for agents
and durability, so T5 (non-extractability) is accepted as residual at the root.
The enclave's only sound home is the deferred two-layer end-state (escrowed root
certifies enclave-held per-device signing keys), which unifies with REQ-6 and
multi-device but touches the fold and is its own later milestone. Migration
grandfathers each existing signing key to preserve its DID (see Migration).

**Q2 (resolved): HPKE (RFC 9180) to derived X25519 keys, per-space-epoch wrap.**
The append-only model makes sharing monotonic — you cannot un-share an immutable
claim — so revocation is future-only by construction, which rules out MLS
(forward-secrecy/churn machinery kan can't honor, plus a delivery service it
lacks) and a static group key (no membership story). The primitive is HPKE
wrapping a per-space-epoch content key to each member's X25519 encryption key
(derived from the seed, key-separated from the P-256 signing key); membership
change starts a new epoch for future claims while past epochs stay readable by
prior members, with an optional explicit grant-history re-wrap. `age` was the
runner-up (same recipient model, off-the-shelf) but is a file format rather than
a KEM primitive, so epoch/grant-history semantics would be bolted on. The full
protocol is the HostedRelay/#7 E2EE pass (ADR-35 M1); this pass names the
primitive per AC-5. See the Architecture section's recipient-encryption note.

## Open Questions

None — Q1 and Q2 resolved above. The remaining unknowns (the HPKE epoch/
grant-history protocol, the relay wire, `did:plc` migration) are explicitly the
HostedRelay/#7 and atproto passes, not open questions of this one.

## Out of Scope

- The HostedRelay wire protocol and the sync remote itself (ADR-54,
  `sync-layer-architecture-and-staging.md` M4) — this pass supplies the
  encryption key it needs; it does not design the transport.
- The atproto/PDS lexicon and `did:plc` migration (ADR-35 M5) — REQ-8 keeps a
  `did:key` so that road stays open, but it is not designed here.
- `kan-infra` (enclave provisioning at scale, HSM/KMS for a hosted service, key
  backup procedures for the company side) — a different kind of decision, its
  own future pass (`sync-layer-architecture-and-staging.md` already scopes
  `kan-infra` out).
- The v0.8 Workspace-wiring build — unblocked by and independent of this pass
  (ADR-54; #105's own scope note).
- SPIFFE/SPIRE-style revocation/rotation research for per-agent keys beyond the
  derivation-path model — noted by #30, deferred until the derivation scheme
  (REQ-6) is fixed.
