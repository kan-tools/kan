# ADR 0025: Identity key moves to the OS keychain, plaintext-file fallback preserved

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-25

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

**Date:** 2026-07-17
**Decision:** `sign::Identity::load_or_create` now tries the OS keychain
first (`keyring` crate v4.1.5, default features — these already cover
macOS Keychain, Windows Credential Manager, and Linux Secret Service via
D-Bus with no extra feature flags needed, confirmed by reading the crate's
own `[features] v1 = [...]` table rather than assuming from its README).
Keyed by the canonicalized `.kan/identity` path as the keychain "account"
(service `dev.kan.identity`), so each checkout keeps its own identity —
same per-checkout scoping the plaintext file already had (ADR-3), keychain
or not. Three cases: already in the keychain → read it; not yet in the
keychain but a plaintext file exists → migrate it in (write to the
keychain) and **deliberately leave the plaintext file in place** as a
fallback copy, not delete it — REQ-16's explicit open decision, resolved
here; neither → generate fresh and write only to the keychain, no
plaintext file created (the actual point of issue #6). If the keychain is
genuinely unavailable at any point, falls back entirely to the original
plaintext-file-only behavior with a loud `eprintln!` warning.
**Crate-trust spike (CLAUDE.md's house rule, before building on it, not
after):** read the actual `keyring`/`keyring-core`/
`zbus-secret-service-keyring-store` source (not just docs), confirming
`Entry::new`'s failure mode is a clean `Err`, not a hang, and that a
missing entry is a distinct `Error::NoEntry` rather than conflated with a
platform failure. Then stress-tested for real on this machine (macOS): 20
sequential inserts, each followed by re-verifying *every prior* entry is
still reachable (not just the latest, and not just checked once at the
end) — the same discipline ADR-11/12 used to catch `atrium-repo`'s MST
data-loss bug — all passed cleanly, no hang, no OS permission prompt.
`.github/workflows/ci.yml` runs on `ubuntu-latest` with no Secret Service
daemon by default, so this PR's own CI run is the real-environment proof
of the fallback path (AC-9) — the exact "headless CI" scenario REQ-15
names, not simulated.
**Why:** Issue #6 flagged the identity key sitting in plaintext at rest as
a real gap; the OS keychain is the standard place to fix that without
inventing kan-specific encryption. Leaving the plaintext file in place
after migration (rather than deleting it) was chosen over deletion because
a keychain write that silently didn't durably persist (a young-ish crate,
hence the spike above) would otherwise orphan the identity with no
recovery path — consistent with the project's broader "no operation
destroys a subject" caution, applied here to the identity file itself even
though it isn't a claim.
**Consequences:** `Cargo.toml` gains the `keyring = "4.1.5"` dependency,
default features only. `tests/keychain_identity.rs` covers idempotency,
migration-preserves-the-plaintext-file, and AC-9 — the AC-9 test is
written to hold correctly under *either* outcome (keychain available or
not) rather than assuming which branch a given CI/dev machine takes, since
that's genuinely environment-dependent and the point is exercising the real
platform behavior, not mocking it away.
