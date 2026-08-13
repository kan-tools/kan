# ADR 0012: Switch `store/log.rs` from `atrium-repo` to `atproto-repo`

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-12

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
**Decision:** Rewrite `store/log.rs` on `atproto-repo` + `atproto-dasl`
(Nick Gerakines' family, ADR-1's originally-rejected alternative),
dropping `atrium-repo`/`atrium-api`/`atrium-identity` entirely. `atrium-crypto`
is kept for signing — ADR-11 never implicated it, and `atproto-identity`
would have pulled in PLC/web-resolution/DNS machinery kan doesn't need.
**Why:** ADR-11's confirmed data-loss bug ([atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343))
made continuing on `atrium-repo` a non-option. Before committing to the
switch, `atproto-repo`'s `Mst` was stress-tested with the *same* methodology
that found the `atrium-repo` bug — not just read, this time: 25,000+ raw
`Mst::insert`/`get` cycles and 2,500 full CAR-round-trips (write → reopen →
verify), zero data loss. `atproto-repo`'s own MST implementation is also
more thoroughly tested (40 unit tests across its MST module vs. a handful in
`atrium-repo`'s single `mst.rs`) and enforces atproto's real `collection/
rkey` record-path format at the API level rather than accepting arbitrary
strings — kan claims now live under the `dev.kan.claim` collection,
incidentally matching `docs/SPEC.md` §10.1's future lexicon namespace
directly instead of needing a later migration.
**Consequences, all deliberate and documented in `store/log.rs`'s module
doc:**
- Initially, `Log::append` did a full CAR-file rewrite every time (O(n) —
  `atproto-repo`'s `CarWriter` has no incremental-append mode). Superseded
  by ADR-13 the same day, once that cost turned out to matter enough to fix
  rather than just track.
- `atproto-repo`'s `Mst` has no eager empty-tree root (unlike `atrium-repo`,
  which computed one at creation) — `Log`'s `commit_cid` is `Option<Cid>`,
  and the first real commit is created lazily on the first `append`, not as
  a synthetic "genesis over nothing."
- Two `Cid` types are genuinely in play at once: `Mst`'s own methods split
  inconsistently between the raw `cid` crate type and `atproto_dasl::Cid`'s
  DAG-CBOR-serialization wrapper (`root`/`from_root` take/return raw;
  `insert`/`get` take/return wrapped) — not a kan design choice, just the
  crate's actual shape, confirmed by compiler error rather than assumed.
- `tests/log_stress.rs` is a permanent regression guard: sequential appends
  through the real `Log` API, checking every prior claim's reachability
  after every single append, plus a fresh-reopen check. Institutionalizes
  the exact check that caught ADR-11's bug so a similar regression (in
  `atproto-repo` or in kan's own usage of it) fails CI immediately rather
  than surfacing as silent data loss later.
