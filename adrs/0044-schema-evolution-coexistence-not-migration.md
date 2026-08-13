# ADR 0044: Schema evolution: coexistence, not migration

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-44

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
**Context:** ADR-43's `ClaimBody::Publication` variant made every older kan
unable to read this repo's log at all (`unknown variant Publication`). kan
had no stated compatibility contract, and the absence became visible the
moment a sharing layer existed — where the readers are other actors who
cannot simply be told to upgrade. The break then blocked the tooling used to
design the fix: `day design check` shells out to the installed `kan`, which
could no longer read the log it was being asked to validate against.
**Measurements (the justification, not assumptions):**
1. `content_cid` emits `d8 2a 58 25 00 01 …` — CBOR tag 42, byte string,
   multibase-identity prefix, CIDv1. kan's on-disk encoding is the
   IPLD/atproto standard and needs no correction. The unreadable
   `{"": [0, 1, 113, …]}` seen in ADR-43 was purely a `serde_json`
   projection artifact: serde's data model cannot express CBOR tags.
2. A field added as `Option<T>` with `skip_serializing_if` yields a
   **byte-identical CID** when absent. Additive evolution is possible.
3. A **new reader** reads an **old record** and verifies correctly. Backward
   compatibility is free.
4. An **old reader** given a **new record** fails two ways, and the
   difference is the whole point. A new *enum variant* is a hard decode
   error: loud and honest. A new *struct field* deserializes successfully,
   silently drops the field, and then fails CID verification — reporting a
   legitimate claim as **altered since it was signed**.
**Decision:** the contract is now `docs/SPEC.md` §7.1, authoritative.
`ClaimContent`'s existing fields are frozen forever; new fields are additive
and optional only; unknown claim kinds are **preserved as opaque
CID-verifiable claims** rather than rejected or dropped, and carry no status
or relational meaning into the fold; `ClaimContent` is `deny_unknown_fields`
so an out-of-date reader says "unknown field" instead of impugning the
record.
**Why coexistence rather than migration:** a CID is identity and the log is
append-only, so rewriting a claim produces a *different claim*. Republishing
old content under new shapes was considered and rejected — it creates two
CIDs for one fact, fragmenting exactly the identity the fold exists to
establish. A log-rewriting tool was rejected outright: history you can alter
is not what kan is.
**Consequences:** #66 (unknown-variant tolerance) is answered by the
preserve-as-opaque rule. #67 (a claim carries no time) becomes tractable —
it is the natural first *additive* field, and measurement 2 is what makes
adding it possible without invalidating history. The `Unknown` variant's
exact re-encoding is the delicate part of implementation: a preserved claim
that cannot re-encode cannot be verified, and would be worse than an honest
hard failure — flagged in `.design/schema-evolution.md`'s Architecture so it
is confronted early rather than discovered late.
**Supersedes:** nothing. Extends ADR-5 (`ClaimKind`+`Body` merge) with the
rules for changing that enum, and ADR-43, whose data-model change is what
exposed the gap.
