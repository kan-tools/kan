# ADR 19: First release: v0.1.1-beta.1, tag-push-triggered crates.io CD

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-19

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

**Date:** 2026-07-21
**Decision:** First real crates.io publish (the crate name itself was already
reserved at a `0.0.0` stub, `docs/SETUP-TODO.md` Phase 0) is `0.1.1-beta.1` —
a genuine semver pre-release, not just an informally-described "beta" at a
plain version number. `.github/workflows/release.yml` publishes on push of a
tag matching `v*.*.*`; the job re-runs the full `build`/`test`/`clippy`/`fmt`
gate itself (not trusting a separate `ci.yml` run via cross-workflow status,
which the same tag push also triggers independently) and verifies the pushed
tag's version matches `Cargo.toml`'s before calling `cargo publish`.
**Why:** A semver pre-release version means downstream users never resolve
it as a default dependency without an exact pin — the standard way to signal
"not yet stable" through the version string itself, chosen explicitly over a
plain `0.1.1` that would only be "beta" by informal description. Tag-push
(not GitHub-Release-published) keeps the trigger to one deliberate action
(`git push --tags`) fully under the releaser's control, no separate release-
notes-UI step required.
**Consequences:** Publishing requires a `CARGO_REGISTRY_TOKEN` repo secret
(a crates.io API token with publish scope) — added directly via the GitHub
UI or `gh secret set`, never through a chat session, since it's a credential
Claude Code should never see or handle. `README.md`/`LICENSE` already
existed and needed no changes; `Cargo.toml` gained `readme = "README.md"`
for the crates.io page. `cargo publish --dry-run --allow-dirty` confirmed
clean packaging both before and after the version bump.
