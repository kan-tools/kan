# ADR 62: Ninth release: v0.8.0-beta.1, the reader and the trust surface

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-62

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

**What it is:** the milestone that makes kan genuinely multi-actor rather than
merely capable of it (ADR-35's v0.8 slot, delivered as specced). Five PRs,
each requirement-scoped, each CI-green before merge:

- **#124 (ADR-57)** — `--trust AUTHOR[=WEIGHT]` on every read verb, CLI and
  MCP; the view names the trust base that produced it; a read discloses what
  that base excluded.
- **#125 (ADR-58)** — `kan identity role add`, multi-role writes by
  declaration, `--trust roles`; Q2 settled on one shared log.
- **#126 (ADR-59)** — `Log::ingest` and the foreign-author overlay; closes
  #97.
- **#127 (ADR-60)** — the `--json` field set and `SCHEMA_VERSION` pinned by
  test.
- **#128 (ADR-61)** — the dogfooding fix, below.

**Why minor, not patch:** new CLI surface (`--trust`, `kan identity role`),
new JSON fields, and a new on-disk directory (`.kan/overlay/`, `.kan/roles`).
All of it is **additive**: `SCHEMA_VERSION` stays `1`, existing claim fields
are untouched, and a v0.7 log opens and reads unchanged under v0.8. A
consumer pinned to schema `1` keeps working; a v0.7 binary reading a v0.8
workspace sees the log it always saw, since the overlay is a separate store
rather than a change to `log/repo.car`.

**Why still beta:** ADR-19's scheme keeps the pre-release suffix until the v1
scope fence closes, and it has not. `KAN_IDENTITY_FILE` remains the
provisional per-role identity mechanism (#30/ADR-55's derived-key model is
designed and unbuilt), and #121's default-trust question is deliberately open.

**The finding worth carrying forward.** The scope-defining defect of this
release came from *running the tool*, with all 39 test binaries green: walking
the real director/prover loop end to end showed `--trust roles` returning two
of three claims, because a workspace's original identity is neither declared
nor active once `KAN_IDENTITY_FILE` names a role. Every unit behaved as
specified; the specification was wrong. That is now four consecutive releases
where the defect that mattered most came from use rather than from the tracker
or the suite (ADR-51's review chain, v0.8's own `WouldMintSecondIdentity`
scoping finding, and this). The suite checks what was specified; dogfooding is
what checks whether the specification was right, and the two are not
substitutes.

**An unplanned partial on #90.** The disclosure shipped for #121's sake also
removes the silence from #90's signature failure: a workspace whose claims all
belong to a superseded identity printed `no subjects yet` at exit 0, and now
prints it with a note naming the excluded count. #90 stays open — it also asks
for `kan identity adopt`, a `kan doctor`, and a high-water-mark check — but
the property that made it dangerous is gone.

**Consequences:** the release the research loop upgrades to; #114 and #115 are
closed by it. `day` can now select a trust base per read and read the frame
back out of the response, which is what its Frames design pass was waiting on.
v0.9 is scoped to durability (restore + the status column, `.design/
durability-log-recovery.md` REQ-2/REQ-3/REQ-5) **and** Milestone 3's per-agent
identity together — a deliberately larger milestone than any so far, chosen
over shipping them separately.
