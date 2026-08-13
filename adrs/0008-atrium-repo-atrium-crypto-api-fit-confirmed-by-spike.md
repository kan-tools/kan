# ADR 0008: `atrium-repo`/`atrium-crypto` API fit confirmed by spike

- Status: Not recorded contemporaneously
- Date: 2026-07-16
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-8

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

**Date:** 2026-07-16
**Decision:** Proceed with the `atrium-rs` family (ADR-1) for real — no
roll-own fallback. `store/log.rs` wraps `atrium_repo::Repository` +
`blockstore::CarStore` (single on-disk CAR file at `.kan/log/`); `sign.rs`
wraps `atrium_crypto::keypair::Keypair` for did:key generation and signing.
**Why:** Read the actual crate source (not just crates.io/GitHub metadata,
which is all ADR-1 had). `Repository::create` builds a repo from scratch,
`CommitBuilder`/`RepoBuilder::finalize` take an externally-supplied signature
(no atproto-network coupling), and `CarStore` gives exactly the "local-only
and future-sync are the same on-disk artifact" property `docs/SPEC.md` §10
wants. Closes Open Question Q1 in `.design/kan-spine.md`.
**Known gap, revisit trigger:** `atrium-repo`'s `Commit` type exposes `rev()`
but not `prev()`, so commit-chain history can't be walked through the public
API — `store/log.rs` works around this by capturing each claim's `Tid` in the
stored record envelope at append time rather than deriving order from the
commit graph after the fact. If a future milestone needs real commit-graph
operations (e.g. diffing between two historical roots, walking `prev` chains,
anything `blockstore::DiffBlockStore` seems aimed at but isn't fully explored
yet) and `atrium-repo` doesn't expose it, `atproto-repo` (ADR-1's rejected
alternative — single-maintainer, but more actively hands-on with exactly this
kind of repo-internals surface) is worth a second look for that specific gap,
not necessarily a wholesale swap back.
**Superseded by ADR-11:** the API-fit spike didn't catch it because it only
checked shape, not correctness under repeated writes — `atrium-repo`'s
`mst::Tree` had a confirmed silent data-loss bug at ordinary scale. ADR-11
covers this in full; it doesn't change the API-fit reasoning above, but it
did mean the M1–M3 `store/log.rs` built on top of it was unsafe, resolved
by ADR-12's switch.
