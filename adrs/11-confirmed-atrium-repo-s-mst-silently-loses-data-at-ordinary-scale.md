# ADR 11: CONFIRMED: `atrium-repo`'s MST silently loses data at ordinary scale

- Status: Filed upstream as
- Date: 2026-07-16
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-11

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
**Status:** Filed upstream as
[atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343).
Resolved by ADR-12 (switch to `atproto-repo`) the same day.
**Finding:** `mst::Tree::add` followed later by `get` could silently and
permanently lose a previously-inserted entry. Confirmed via a minimal,
deterministic repro (`salt="salt-2"` failed at exactly 18 sequential
inserts, every time; never failed at 17) plus an aggregate: ~24% of
independent random key sequences lost data within 20 sequential inserts
using realistic, CID-shaped keys.
**Ruled out as causes** (each independently verified, not assumed):
- Missing `CommitBuilder::prev()` — a real bug in `store/log.rs`'s original
  usage (fixed), but fixing it did **not** fix the data loss.
  `atrium-repo`'s own `test_extract_complex` doesn't call `.prev()` either
  and passes, confirming it isn't required.
- Blockstore backend — identical failure rate (72/300) with
  `MemoryBlockStore` and `CarStore`.
- Tree lifecycle — identical failure rate with one long-lived `Tree` vs.
  reopening `Tree::open` from the root CID per insert (the pattern
  `Repository::add_raw` uses internally).
- `Repository`/`CommitBuilder`/signing — bug reproduced at the raw
  `mst::Tree` layer alone, no higher-level API involved.
- Key shape was likely the actual trigger: `atrium-repo`'s own test (short,
  fixed-13-char `Tid`-based keys) didn't reproduce even scaled to 50×30
  runs; failures correlated with longer, hash-derived (CID-shaped) keys —
  exactly what a content-addressed application keying by `add_raw` would
  naturally use.
**Practical impact:** every claim `store/log.rs` had appended since M1
(including dogfooding claims recorded after M3) carried this risk once a
`.kan/log/` accumulated on the order of 15-20+ claims. M1–M3 were already
merged; this wasn't a pre-merge catch. See ADR-12 for the resolution.
