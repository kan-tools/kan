# ADR 0021: v0.2 write-surface layout: pair-writes, a real `retract`, and a CLI-only status-value enum

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-21

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
**Decision:** `kan resolve`/`kan block` each now write two claims — a
narrative claim (`Resolution`/`Blocker`) plus a `Status` claim citing it
(`Resolved`/`Blocked`) — via a shared `actions::PairedAppendResult`, rather
than requiring a second explicit call to write the structural half. `kan
mark <subject> <value>` writes a bare `Status` claim with no narrative
pairing, for `Open`/`InProgress`/`Closed`, which have no natural narrative
counterpart. `kan retract <cid>` looks up the target claim's subject and
author before writing, rejecting a cross-author retraction attempt at write
time (`actions::Error::NotYourClaim`) instead of silently writing an inert
claim that `fold::identity::excluded_by_retraction` (ADR-16) would ignore
anyway — that fold-level check remains the actual source of truth; this is
a friendlier, immediate echo of it. The CLI's status-value argument is a
`clap::ValueEnum` (`cli::StatusValueArg`) kept out of `claim.rs` entirely,
converted to `claim::StatusValue` at the CLI/actions call boundary in
`cli::run`; the MCP surface instead derives `schemars::JsonSchema` directly
on `claim::StatusValue`, since `schemars` (unlike `clap`) doesn't carry the
same "keep the data model CLI-free" concern.
**Why:** An agent resolving or blocking something is asserting a status
change, not narrating a side detail — making that one action into one write
(two claims, correct `cites` provenance) removes an "did I remember the
second call" failure mode entirely. `retract`'s write-time author check
gives an agent a clear, immediate CLI error instead of a claim that silently
does nothing on the next fold, which would otherwise look like a bug rather
than an intentional trust boundary. Two different enum representations for
one value (`StatusValueArg` vs. `claim::StatusValue`) is deliberate, not
duplication: `clap`'s derive macro is CLI-only surface area, and letting it
leak into `claim.rs` (a type both the CLI and MCP layers depend on) would
tie the core data model to one CLI framework's derive conventions.
**Consequences:** `actions::same`/`actions::resolve` gained a `cites: Vec<String>`
parameter (previously omitted for no documented reason — the only
undocumented gap of its kind in the write surface); `kan same --cites` and
`kan resolve --cites` now round-trip the same way `observe`/`plan`/`decide`
already did. `kan block` deliberately does *not* gain `--cites` in this
pass — no requirement motivated it, and adding it speculatively would be
scope beyond what v0.2 asked for. Testing a genuine cross-author `retract`
rejection needs a second real signing `Identity` (a fabricated `AuthorId`
with no matching keypair fails signature verification before `retract`'s
own check even runs), so that half of AC-3 is covered at the library level
in `tests/write_surface.rs`, not through the CLI subprocess harness
`tests/cli.rs` uses for everything else — the CLI's one-identity-per-repo
model has no way to construct a second author yet (that's REQ-11..13, a
later slice of this same milestone).
