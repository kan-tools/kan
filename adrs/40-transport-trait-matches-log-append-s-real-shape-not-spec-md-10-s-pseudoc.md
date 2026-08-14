# ADR 40: Transport trait matches Log::append's real shape, not SPEC.md §10's pseudocode

- Status: Not recorded contemporaneously
- Date: 2026-07-20
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-40

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

**Date:** 2026-07-20
**Decision:** `src/transport.rs`'s `trait Transport` (`.design/v0.5-milestone.md`,
sync staging Milestone 0) adapts `docs/SPEC.md` §10's illustrative `fn
publish(&self, &[Claim]); fn subscribe(&self, &[Did]) -> Stream<Claim>;`
sketch into four concrete choices, each checked against real code rather
than guessed: (1) `publish(&mut self, content: ClaimContent, identity:
&Identity) -> Result<Cid, Error>` matches `Log::append`'s real single-claim,
unsigned-content-in shape exactly, not SPEC's batch-of-pre-signed-`Claim`s;
(2) `subscribe` returns a real `tokio-stream`-backed `ClaimStream`
(`Pin<Box<dyn Stream<Item = Result<Claim, Error>> + Send>>`), a new minimal
dependency, rather than a plain `Vec<Claim>`; (3) the stream item is the
signed `Claim`, not `store::log::StoredClaim` — `rev` is log-internal
ordering that doesn't belong across the transport boundary; (4)
`Transport::Error` is its own enum (`#[error(...)] Log(#[from]
store::log::Error)`), decoupled from `LocalOnly`'s specific backing store so
`HostedRelay`'s future error variants have somewhere to live without
`store::log::Error` growing transport-shaped variants. `LocalOnly` wraps
`store::log::Log` 1:1: `publish` delegates directly to `Log::append`;
`subscribe` returns `tokio_stream::empty()` — the honest answer for a
single-author local log, not a stub.
**Why match `Log::append` instead of SPEC's sketch:** `docs/SPEC.md` §10's
pseudocode was always illustrative, and `Log::append` is the only thing
`LocalOnly` — the transport this milestone actually has to implement —
wraps. Inventing batching or pre-signed-`Claim` input to match the sketch
literally would give `LocalOnly` a shape it can't honestly implement without
new `Log` surface nothing in this milestone's requirements asks for.
**Consequences:** New dependency `tokio-stream = "0.1"` (thin wrapper around
the same `futures-core::Stream` trait; already adjacent to kan's tokio async
runtime, `Cargo.toml`'s existing `rt-multi-thread` feature). Zero change to
`Workspace`/CLI/MCP — `Transport` is additive, wiring deferred to
`HostedRelay`'s own `/design` pass (Milestone 3 in
`.design/sync-layer-architecture-and-staging.md`). New tests
`tests/transport.rs::local_only_publish_matches_log_append_directly` (a
CID-equivalence proof against direct `Log::append` usage) and
`::local_only_subscribe_is_honestly_empty`. The trait signature is
explicitly not meant to be final — `HostedRelay`'s design pass may need to
widen it once a second real implementation exists to design the wiring
against.
