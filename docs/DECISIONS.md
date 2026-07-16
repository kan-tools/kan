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
**Caveat (resolved):** `atrium-repo` itself is the youngest crate in either
family (v0.1.8) — its fit for from-scratch local MST/CAR construction (vs.
reading an existing hosted repo) was unverified at the time of this ADR. See
ADR-8, which confirms the fit by reading the actual source.

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

## ADR-8 — `atrium-repo`/`atrium-crypto` API fit confirmed by spike
**Date:** 2026-07-16
**Decision:** Proceed with the `atrium-rs` family (ADR-1) for real — no
roll-own fallback. `store/log.rs` wraps `atrium_repo::Repository` +
`blockstore::CarStore` (single on-disk CAR file at `.kan/log/`); `sign.rs`
wraps `atrium_crypto::keypair::Keypair` for did:key generation and signing.
**Why:** Read the actual crate source (not just crates.io/GitHub metadata,
which is all ADR-1 had). `Repository::create` builds a repo from scratch,
`CommitBuilder`/`RepoBuilder::finalize` take an externally-supplied signature
(no atproto-network coupling), and `CarStore` gives exactly the "local-only
and future-sync are the same on-disk artifact" property `docs/SPEC.md` §10
wants. Closes Open Question Q1 in `.design/kan-spine.md`.

## ADR-9 — Token-budget estimation: `tiktoken-rs` behind a `TokenEstimator` trait
**Date:** 2026-07-16
**Decision:** `kan context --budget N` estimates tokens via `tiktoken-rs`
(cl100k/o200k BPE), wrapped behind a `TokenEstimator` trait rather than called
directly at use sites.
**Why:** Real BPE tokenization is a meaningfully better estimate than a
chars/4 heuristic, and `tiktoken-rs` is a real, MIT-licensed, usable crate —
confirmed by adding it and building, not just reading its description. It
isn't exact for every model kan might feed (it's OpenAI's encodings), so the
trait boundary keeps the concrete tokenizer swappable later without touching
call sites. Closes Open Question Q2.

## ADR-10 — MCP tool surface: one `#[tool]` per CLI verb
**Date:** 2026-07-16
**Decision:** `kan mcp` exposes one `rmcp` tool per CLI verb (10 tools:
observe/plan/decide/resolve/same/show/issues/status/session_start/
session_end/context), not a single generic `append_claim(kind, ...)` tool.
**Why:** `rmcp`'s `#[tool]`/`#[tool_router]` macros make per-tool boilerplate
near-zero (confirmed by reading `rmcp`'s own test suite), which removes the
main cost that motivated the design doc's original "one generic tool" lean.
Two alternatives were weighed and rejected for v1: (a) collapsing only the
read verbs (`show`/`issues`/`status`/`context`) into one `query(kind, filter)`
tool, kept open as a plausible future consolidation if the read surface grows;
(b) a single CLI-passthrough tool (`run(args: string)` shelling out to the
`kan` binary, mirroring Claude Code's own `Bash` tool) — real precedent for
open-ended command surfaces, but kan's vocabulary is deliberately capped small
(`CLAUDE.md`'s git-like/terse house rule), which is not the regime the
narrow-tool-sprawl critique applies to, and schema-typed params protect the
"provenance is sacred" invariant on write verbs in a way free-text CLI
arguments can't. Closes Open Question Q3.
