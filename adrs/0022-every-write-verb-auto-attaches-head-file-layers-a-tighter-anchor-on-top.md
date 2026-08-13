# ADR 0022: Every write verb auto-attaches `HEAD`; `--file` layers a tighter anchor on top

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-22

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
**Decision:** `actions::append` (the one shared write path every verb funnels
through) now always attaches `ArtifactRef::Commit(<current HEAD sha>)` —
`GitSubstrate::head_commit` (`git rev-parse HEAD`), no flag needed. Every
public write function (`observe`/`plan`/`decide`/`same`/`resolve`/`block`/
`mark`/`retract`) additionally takes an opt-in `file: Option<String>`
(`--file <path>[:<start>-<end>]` on the CLI, `file` on every MCP write tool)
that attaches a more specific `ArtifactRef::FileAt`/`LineRangeAt` *on top of*
the automatic commit artifact, reusing the same `HEAD` sha rather than
computing or requiring a separate one — a `FileAt` anchor is "this file, as
of that commit," not an independently-anchored artifact. The trailing
`:start-end` is only parsed as a line range if it actually parses as two
integers; anything else (including no colon, or a colon that's just part of
the path) falls back to treating the whole string as the path. `kan
resolve`/`kan block`'s pair-write applies `--file` to the narrative claim
only — the paired `Status` claim always gets just the automatic commit
anchor, since "here's the file this is about" describes the narrative, not
the bare status flip.
**Why:** `docs/SPEC.md` §6.2 already recommends anchoring to the tightest
git object available; before this, no write path actually did it, so every
claim's `artifacts` field was empty in practice and `relations::GitAncestry`/
`GitSameFile` were unreachable dead weight downstream. Making it automatic
(not a flag agents have to remember) turns the recommendation into a real
default. `--file` stays opt-in and additive rather than replacing the commit
anchor, since a file-level claim is still also true of the commit it was
made in — losing that would be a strictly less precise artifact record, not
a more precise one. Falling back to "whole string is the path" on an
unparseable range (rather than erroring) was chosen because a colon can
legitimately appear in a real path; erring on the side of "best-effort
attach something" fits `docs/SPEC.md`'s framing of computed/attached
provenance as an accepted-if-imperfect signal, not something that should
block a write over a malformed suffix.
**Consequences:** `actions::append`'s signature grew a `file` parameter,
propagating to every public write function and both the CLI (`NarrativeArgs`
and each write `Command` variant gain `--file`) and MCP (`file` on every
write tool's params struct) surfaces — a mechanical but real signature
change across the whole write surface. Tested at the library level
(`tests/artifact_attachment.rs`, inspecting `ClaimContent::artifacts`
directly) rather than through `kan show`, which doesn't render artifacts
today; extending `show` to surface them was considered but is unrelated
display surface this ADR's scope (REQ-8/REQ-9) didn't ask for.
