# Current roadmap

This file is the short, current map of kan's shipped baseline and active
cross-repository work. It does not replace the authority of `docs/SPEC.md` or
an accepted RFC. Historical milestone designs and reconstructed ADRs explain
how kan arrived here; they are not a substitute for this current ordering.

## Shipped baseline

As of `v0.13.0-beta.1`, the local-first spine is built: signed append-only
claims, the local CAR log, tracked GitTree publication and ingestion, disposable
SQLite and overlay projections, deterministic folds, identity roles, CLI/MCP
reads and writes, durability reporting, and restore.

The read/write boundary is now explicit in `docs/SPEC.md` §10.1 and
`tests/fixtures/read-write-surface.tsv`. `tests/surface_conformance.rs` checks
the catalog against the implementation in both directions, and compiler policy
routes filesystem mutations through typed persistence capabilities. That work
landed in [PR #233](https://github.com/kan-tools/kan/pull/233) and closed
[issue #216](https://github.com/kan-tools/kan/issues/216).

## Active public-protocol track: RFC 3

[RFC 3](../rfcs/3-authoritative-lexicon-publication.md) specifies authoritative
`tools.kan.*` Lexicon publication, immutable codec/lens bindings, and a portable
version-aware AppView. Its formal status is **Review** through
2026-08-20T00:50:11Z. The implementation issues below are the scoped roadmap;
they do not change the RFC's status or permit production publication before
the RFC process and acceptance gates are complete.

The tracking epic is [#29](https://github.com/kan-tools/kan/issues/29):

| Order | Workstream | Depends on |
|---|---|---|
| 1a | [#235 — `kan-atproto` wire boundary and claim-envelope migration](https://github.com/kan-tools/kan/issues/235) | shipped baseline |
| 1b | [#237 — `_lexicon.kan.tools` and `did:web:kan.tools` authority](https://github.com/kan-tools/kan/issues/237) | may proceed in parallel with #235 |
| 2 | [#236 — versioned Lexicons and append-only codec/lens registers](https://github.com/kan-tools/kan/issues/236) | #235 |
| 3a | [#238 — release-verified atomic publisher](https://github.com/kan-tools/kan/issues/238) | #236, #237 |
| 3b | [#239 — portable reference AppView](https://github.com/kan-tools/kan/issues/239) | #235, #236 |
| 4 | [#240 — Railway deployment and independent recovery](https://github.com/kan-tools/kan/issues/240) | #237, #238, #239 |
| 5 | [#241 — end-to-end release qualification and drift probes](https://github.com/kan-tools/kan/issues/241) | #235–#240 |

The first parallel implementation wave is therefore #235 and #237, subject to
RFC 3 completing review. Production is not complete until #241 verifies the
public route from DNS and DID resolution through authoritative PDS records and
normalized AppView responses, including recovery and provenance evidence.

## Repository-family ownership

- `kan` owns RFCs, canonical claim codecs, normative lens semantics, and the
  `kan-atproto` wire boundary.
- public `kan-tools/kan-lexicon` owns Lexicon source, generated clients,
  immutable releases, and language-neutral fixtures.
- public `kan-tools/kan-appview` owns portable reference AppView code and its
  container artifact.
- private `kan-tools/kan-infra` owns Railway configuration, credentials,
  monitoring, deployment pins, and recovery procedures.

## Separate and deferred tracks

HostedRelay, its product/access model, firehose ingest, and additional AppView
selection policy are not silently folded into RFC 3. The older
`.design/sync-layer-architecture-and-staging.md` and ADR-35 remain useful
history for HostedRelay sequencing, but their `dev.kan.*`, `did:plc`, version,
and public-ATProto assumptions are superseded for RFC 3 by the RFC and the
issue graph above. The longer-term identity program remains tracked in
[#30](https://github.com/kan-tools/kan/issues/30).

## Which document wins

1. `docs/SPEC.md` defines shipped kan semantics and invariants.
2. Accepted RFCs define public protocol and governance commitments; a Review
   RFC is a proposal until its review period completes and its status changes.
3. `.design/*.md` files specify bounded implementation work or preserve
   historical design context.
4. GitHub issues track execution and dependencies; they do not override the
   SPEC or RFC status.
