# kan

**Local reasoning, global coherence — memory for AI agents.**

Where `git` versions your code, `kan` remembers your reasoning. Each agent keeps
its own signed, append-only record of what it observed, planned, decided, and
resolved — and `kan` folds those local records into one coherent view on demand,
without a central authority deciding what's true.

Nothing is overwritten. Nothing is flattened. Nothing is lost.

## Why

AI coding agents forget everything between sessions, and coordinating several of
them means reconciling contradictory state. Most tools solve this with a shared,
mutable store and locks — which is exactly where things break. `kan` takes the
opposite approach: **every actor appends only to its own log; nothing mutates
anyone else's.** Conflicts stop being write-time errors and become read-time
information. All the intelligence lives in the *fold* — a deterministic reduction
from many local logs into a coherent view, parameterized by whom you trust.

## Properties

- **Local-first** — works offline, solo, one machine, no server.
- **Provenance-preserving** — every claim is signed and carries what it was
  derived from. The record of reasoning is auditable end to end.
- **No forced consensus** — many agents, many local truths, glued into a shared
  picture while their differences are preserved (or surfaced, when they conflict).
- **Append-only** — the past is never destroyed; views are computed, not stored.

## Status

Pre-1.0 (`v0.4.0-beta.1` on crates.io). The local-only spine — one human,
one-or-more agents, one repo, no sync — is built and hardening. Sync (a
private-team `HostedRelay` transport, then the public atproto layer) has a
concrete staged plan targeting `v1.0.0` — see
`.design/sync-layer-architecture-and-staging.md` and `docs/DECISIONS.md`
ADR-35 — but hasn't started yet.

## Name

`kan` is the Kan extension: the universal construction that builds the best global
object from local data along a map. That is, more or less, the whole job.

## License

MIT
