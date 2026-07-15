# kan — decisions (ADR log)

Short-form record of choices made during design passes. `docs/SPEC.md` stays as
pasted from the original design session and is not edited to match; where a
decision here narrows or overrides something SPEC.md left open, this file wins
for *implementation*, and SPEC.md still wins for the underlying data
model/algorithm it's authoritative over. Full context for each entry lives in
the `.design/*.md` doc that produced it.

## ADR-1 — Repo/MST/CID/signing crate family: `atrium-rs`, not `atproto-repo`
**Date:** 2026-07-15
**Decision:** Use the `atrium-rs` family (`atrium-repo`, `atrium-crypto`,
`atrium-identity`, …) rather than Nick Gerakines' `atproto-repo` family, which
`docs/HANDOFF.md` had originally pointed at.
**Why:** `atrium-rs` is org-maintained, 420★/49 forks/204 releases, actively
developed, and backs `bsky-sdk` — the community-standard choice. `atproto-repo`
is single-maintainer, 32★, and tagged `0.15.0-alpha.2` on main. Bus-factor and
community vetting outweigh `atproto-repo`'s numerically higher crates.io
version for something this foundational.
**Caveat:** `atrium-repo` itself is the youngest crate in either family
(v0.1.8) — its fit for from-scratch local MST/CAR construction (vs. reading an
existing hosted repo) is unverified. See `.design/kan-spine.md` Open Question Q1.

## ADR-2 — Single binary, one crate
**Date:** 2026-07-15
**Decision:** `kan` ships as one crate (lib + CLI + `kan mcp` subcommand),
not a Cargo workspace of `kan-core`/`kan-cli`/`kan-mcp`.
**Why:** Matches the local-only "dramatically simpler" smell test in
`CLAUDE.md` — no workspace/versioning ceremony until there's a concrete reason
(e.g. a second consumer of `kan-core`) to split.

## ADR-3 — Store location: repo-local `.kan/`
**Date:** 2026-07-15
**Decision:** The signed log and disposable SQLite index live at `.kan/`,
gitignored, sibling to `.git/` — one store per checkout.
**Why:** Mirrors git's own pattern directly (kan's README already frames it as
git's sibling: "git versions your code, kan remembers your reasoning"). A
global store keyed by `Anchor::Workspace(GenesisCid)` (shared across clones/
worktrees) was considered and deferred — not needed for a single-checkout v1
spine, and adds a lookup indirection.

## ADR-4 — Local-only identity: self-generated `did:key`
**Date:** 2026-07-15
**Decision:** `AuthorId.did` is a `did:key:...` derived from a keypair
generated on first use, stored at `.kan/identity`.
**Why:** `did:key` is self-certifying (no PDS/network needed) and is the exact
identity atproto expects later — upgradeable to `did:plc` without re-signing
history, so local-only and future-sync share one identity model from day one.
An opaque local UUID placeholder was considered and rejected: it would require
re-deriving (and possibly re-signing) identity when sync lands.

## ADR-5 — Body typing: structural/narrative split, `ClaimKind`+`Body` merged
**Date:** 2026-07-15
**Decision:** Accepts `docs/SPEC.md` §12.1's recommended default — closed
typed variants for `Subject`/`Status`/`Relation`/`Retraction`; opaque text for
`Observation`/`Plan`/`Decision`/`Result`/`Blocker`. Additionally, `ClaimKind`
and `Body` (two fields in SPEC.md §1's sketch) are merged into a single
`ClaimBody` enum, with kind exposed as a derived method.
**Why:** The fold only needs structured access to the four structural kinds;
narrative kinds are cited-but-not-parsed prose, so typing them would balloon
the fold's surface for no payoff. Merging kind+body into one enum makes an
invalid kind/body pairing unrepresentable in the type system — same
information as SPEC.md's sketch, safer representation.

## ADR-6 — Retraction: Option B as specified, retract-the-retraction as undo
**Date:** 2026-07-15
**Decision:** Accepts `docs/SPEC.md` §12.2's recommended default (Option B,
retraction-as-claim/palimpsest) as-is. Undo is retracting the `Retraction`
claim itself — no separate `Restore`/`Unretract` kind.
**Why:** Because superseded claims are excluded from state reduction and
`cites` is strictly backward-only (acyclic CID-DAG), retracting a retraction
naturally un-suppresses the original claim with no special-casing required.

## ADR-7 — Hard-delete: storage-layer only in v1, no CLI verb
**Date:** 2026-07-15
**Decision:** True erasure (no tombstone) stays possible at the storage layer
but v1 exposes no CLI verb for it (e.g. no `kan forget`).
**Why:** Keeps the CLI vocabulary exactly what `docs/HANDOFF.md` lists
(`observe|plan|decide|resolve|same|show|issues|status|session|context`).
Erasure is rare/dangerous enough to defer to a manual/scripted operation until
there's a concrete need.
