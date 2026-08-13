# ADR 0071: `kan show --all`: a bulk read, because the cost is process startup

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-71

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

**Date:** 2026-07-30
**Status:** Accepted

**Decision:** #123, `.design/kan-read-contract.md` REQ-5. `kan show --all
--json` returns every subject's live claims from one `Workspace::open`. Each
entry is a full `ShowJson`; the envelope adds the shared trust base and a
whole-log exclusion count.

**The measurement decided the shape, and ruled a candidate out.** `day status`
spent 1.99s of 2.76s inside 41 `kan` invocations. That cost is
`Workspace::open`: an *empty* log costs ~30ms per call, a one-claim subject
costs the same as the largest, and `kan identity did` — which reads no log at
all — costs the same again. So **no optimisation inside a read helps**. #25
("incremental identity/state fold") names this problem almost exactly and is
*not* it; reaching for it would have been effort spent on the ~15% that is not
the problem. Only collapsing process startups helps, which is why this is a
bulk verb rather than a faster fold.

Measured here on a fresh 40-subject log: **1.33s across 41 invocations, 0.06s
in one.** The 22× is process startup, not the fold — which is the same fact
#123 established, now from the other side.

**Entries are full `ShowJson` values, repetition and all.** Every entry
carries its own `trust`, identical across the response. That is deliberate: a
consumer already parsing `show --json` for one subject parses these unchanged,
which is worth more than the few hundred bytes, and the ask was explicitly to
reduce the invocation *count* rather than the payload. `tests/json_contract.rs`
pins the reuse so it cannot be quietly "tidied" into a slimmer shape that
forces day to write a second parser.

**A flag on `show`, not a new verb.** kan's CLI vocabulary is four declared
phases (ADR-32) and `show` is already the "one subject's live claims" verb;
`--all` is that verb over every subject. A new noun would have widened the
surface for something that is the same question asked wider.

**`--all` requires `--json`.** It exists for programs, and nobody reads forty
subjects' full claim histories at a terminal. Refusing is better than rendering
something no one wants and calling it a feature.

**The property under test is agreement, not speed.** One invocation must return
exactly what forty-one returned, or the fast path is a different answer wearing
the same name — and a consumer building its whole claim graph from it would
inherit the difference silently. `tests/bulk_read.rs` compares **CID for CID**
rather than by count, over a log containing a retraction, a `SameAs` merge, a
relation, and superseded statuses. Dropping one claim per class fails exactly
the agreement tests while the shape tests still pass, which is what makes them
a control.

**Consequences:** additive, so `SCHEMA_VERSION` stays `1`. `show`'s `subject`
argument becomes optional (`--all` conflicts with it at the parser), and `show`
with neither now says what to type instead of what it cannot do. This closes
day's last outstanding read-surface ask; the remaining items on that contract
were satisfied by v0.8.
