# ADR 90: A storage crate must prove conformance, not just reachability

- Status: Accepted
- Date: 2026-08-11
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-90

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

**Date:** 2026-08-11
**Status:** Accepted

**Decision:** Before this repo trusts a storage-layer crate, it must pass a
*structural* check against an independent implementation, not only the
reachability stress test ADR-11/12 established. `tests/mst_conformance.rs` is
that check: it asserts our MST root CID equals the one `@atproto/repo` 0.10.10
computes for the same key set, alongside the reachability protocol.

**Why the old rule was insufficient, demonstrated rather than argued.**
ADR-11/12 found a data-loss bug in `atrium-repo`'s MST and set the house rule:
sequential inserts, full reachability checked after every single one, before
building on the crate rather than after. That rule caught its bug. It cannot
catch `atproto-repo` 0.14.5's (kan#204), because **nothing is lost** —
`insert_recursive` computed each key's layer, discarded it into
`_target_height`, and never recursed, so every key landed in one flat root
node. Every key stays reachable. The tree is simply not a tree.

The consequences were not cosmetic. The root was rewritten in full on every
insert, so CAR bytes grew as ~52n²: a hard write-failure cliff at ~1,431
claims against `atproto-dasl`'s 100 MiB default, reached deterministically in
CI and locally, with kan's own log 31% of the way and day's 47%. And the root
CID matched no conformant implementation, which falsifies the premise ADR-12
chose this crate for — that local-only and future atproto are the same
on-disk artifact.

**A second defect the reachability rule also could not see:** `MstNode::left`
and `TreeEntry::tree` carried `skip_serializing_if = "Option::is_none"`, so
`l` and `t` were omitted where the schema has them present-but-nullable. In
DAG-CBOR an absent field and a null field are different bytes and therefore a
different CID, so *even a single-entry tree* diverged. Fixing the layering
alone would not have restored conformance.

**The rule generalizes past MSTs.** Reachability answers "did we lose data?".
Conformance answers "is what we wrote the thing we claim it is?". A format
whose whole value is that someone else can read it needs the second question
asked by someone else's implementation — ours agreeing with itself proves
nothing. That failure mode is not hypothetical: our first spec-derived
reference used the wrong layer convention (skipping empty layers rather than
decrementing strictly) and produced a wrong expected CID, which we published
before the cross-check caught it. The fixture therefore records
`@atproto/repo`'s output as the authority, not our reading of the spec.

**Consequence: kan owns the MST.** It lives in `src/mst/`, and
`atproto-repo` is kept only for `Commit`, `RecordPath` and `compute_cid` —
the parts that did not fail. Vendoring-plus-`[patch.crates-io]` was tried
first and rejected: a `[patch]` section is honoured only in the root manifest
of the crate being *built*, so it fixes local and CI builds while leaving
everyone who runs `cargo install kan` on the broken MST. A fix that does not
reach the installed binary is not a fix.

Owning it is also the honest reading of two crates failing at one layer. This
is where the non-negotiable invariant lives — the tree is what makes a claim
findable — so it is the last place to hold a dependency whose correctness we
cannot check. Now we check it: `tests/mst_conformance.rs` runs on every build.
