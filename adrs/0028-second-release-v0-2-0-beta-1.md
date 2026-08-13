# ADR 0028: Second release: v0.2.0-beta.1

- Status: Not recorded contemporaneously
- Date: 2026-07-18
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-28

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

**Date:** 2026-07-18
**Decision:** `Cargo.toml`'s version bumps `0.1.1-beta.1` → `0.2.0-beta.1` —
a minor-version bump (new backward-compatible functionality: the full v0.2
write surface, artifact auto-attachment, the `KAN_AGENT` patch, keychain
storage, the MCP resource), staying a semver pre-release rather than
promoting to a stable `0.2.0`. No changes needed to `release.yml` or the
`crates-io` environment — both already exist and worked cleanly for the
first release (ADR-19/ADR-20).
**Why beta again, not stable:** confirmed data compatibility with
`v0.1.1-beta.1` first (checked, not assumed) — `src/store/` is untouched
byte-for-byte since the first release, and `src/claim.rs`'s only diff is a
derive, not a field/variant change, so every v0.1.1-beta.1 `.kan/log/` and
`.kan/identity` reads and continues to work unmodified under v0.2. That
compatibility is real, but the project itself isn't yet: several
known-reachability gaps remain open (non-`SameAs` `RelationKind`s, issue
#31; `ClaimBody::Subject`/`SubjectKind` construction, issue #32; real
per-agent cryptographic identity replacing the `KAN_AGENT` placeholder,
issue #30) and `docs/SPEC.md`'s v1 scope fence isn't fully closed out yet.
A pre-release version keeps signaling "not yet stable" honestly rather than
implying more finality than the current state warrants.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging before tagging, same discipline as the first release.
