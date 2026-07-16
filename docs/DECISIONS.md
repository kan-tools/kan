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
**Known gap, revisit trigger:** `atrium-repo`'s `Commit` type exposes `rev()`
but not `prev()`, so commit-chain history can't be walked through the public
API — `store/log.rs` works around this by capturing each claim's `Tid` in the
stored record envelope at append time rather than deriving order from the
commit graph after the fact. If a future milestone needs real commit-graph
operations (e.g. diffing between two historical roots, walking `prev` chains,
anything `blockstore::DiffBlockStore` seems aimed at but isn't fully explored
yet) and `atrium-repo` doesn't expose it, `atproto-repo` (ADR-1's rejected
alternative — single-maintainer, but more actively hands-on with exactly this
kind of repo-internals surface) is worth a second look for that specific gap,
not necessarily a wholesale swap back.

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

## ADR-12 — Switch `store/log.rs` from `atrium-repo` to `atproto-repo`
**Date:** 2026-07-17
**Decision:** Rewrite `store/log.rs` on `atproto-repo` + `atproto-dasl`
(Nick Gerakines' family, ADR-1's originally-rejected alternative),
dropping `atrium-repo`/`atrium-api`/`atrium-identity` entirely. `atrium-crypto`
is kept for signing — ADR-11 never implicated it, and `atproto-identity`
would have pulled in PLC/web-resolution/DNS machinery kan doesn't need.
**Why:** ADR-11's confirmed data-loss bug ([atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343))
made continuing on `atrium-repo` a non-option. Before committing to the
switch, `atproto-repo`'s `Mst` was stress-tested with the *same* methodology
that found the `atrium-repo` bug — not just read, this time: 25,000+ raw
`Mst::insert`/`get` cycles and 2,500 full CAR-round-trips (write → reopen →
verify), zero data loss. `atproto-repo`'s own MST implementation is also
more thoroughly tested (40 unit tests across its MST module vs. a handful in
`atrium-repo`'s single `mst.rs`) and enforces atproto's real `collection/
rkey` record-path format at the API level rather than accepting arbitrary
strings — kan claims now live under the `dev.kan.claim` collection,
incidentally matching `docs/SPEC.md` §10.1's future lexicon namespace
directly instead of needing a later migration.
**Consequences, all deliberate and documented in `store/log.rs`'s module
doc:**
- Initially, `Log::append` did a full CAR-file rewrite every time (O(n) —
  `atproto-repo`'s `CarWriter` has no incremental-append mode). Superseded
  by ADR-13 the same day, once that cost turned out to matter enough to fix
  rather than just track.
- `atproto-repo`'s `Mst` has no eager empty-tree root (unlike `atrium-repo`,
  which computed one at creation) — `Log`'s `commit_cid` is `Option<Cid>`,
  and the first real commit is created lazily on the first `append`, not as
  a synthetic "genesis over nothing."
- Two `Cid` types are genuinely in play at once: `Mst`'s own methods split
  inconsistently between the raw `cid` crate type and `atproto_dasl::Cid`'s
  DAG-CBOR-serialization wrapper (`root`/`from_root` take/return raw;
  `insert`/`get` take/return wrapped) — not a kan design choice, just the
  crate's actual shape, confirmed by compiler error rather than assumed.
- `tests/log_stress.rs` is a permanent regression guard: sequential appends
  through the real `Log` API, checking every prior claim's reachability
  after every single append, plus a fresh-reopen check. Institutionalizes
  the exact check that caught ADR-11's bug so a similar regression (in
  `atproto-repo` or in kan's own usage of it) fails CI immediately rather
  than surfacing as silent data loss later.

## ADR-13 — Make `Log::append` genuinely incremental, not a full rewrite
**Date:** 2026-07-17
**Decision:** Rewrite `Log::append`'s persistence step to write only the
*new* blocks (the new record, whatever `Mst` internal nodes changed along
the insertion path, and the new commit) to the end of the CAR file, instead
of re-serializing everything `mst.storage()` has ever seen. Brings back a
`HEAD` sidecar file (ADR-8's original `atrium-repo` pattern, dropped when
ADR-12 made it briefly unnecessary) since the CAR header's `roots` are still
fixed at file-creation time — `Log` never reads them back; `HEAD` is
authoritative for the current root.
**Why:** ADR-12 shipped O(n)-per-append as a documented, correctness-first
tradeoff (tracked in issue kan-tools/kan#8) rather than something to fix
immediately. Asked directly whether a hybrid was possible: yes.
`atproto-repo`'s `CarWriter` always writes a fresh header at construction
(no public "resume" mode), but `CarBlock::to_bytes()` — the exact
length-prefix + CID + data wire format `atproto_dasl::car`'s module doc
documents — is public. That's enough to append new blocks directly, since
MST is a persistent (not in-place-mutated) structure: an `insert` only
creates new nodes along the path from root to the new leaf, so "new blocks
since last persist" is a small, bounded set, not the whole tree.
**Verification, before trusting hand-rolled low-level byte-writing again:**
- Direct timing: append latency stayed flat (~4-6ms) as the CAR file grew
  from 817 bytes to 229KB across 60 appends — confirms the write cost
  doesn't scale with log size anymore. (`tests/log_stress.rs` itself still
  takes ~6s, but that's ECDSA signature verification in `get()` — ~3ms/call,
  ~1830 calls from the test's own O(n²) reachability checking — not the
  storage layer; confirmed by timing `get()` in isolation.)
- `tests/log_cross_process_stress.rs` (new): a *fresh `Log` instance per
  append* — not one long-lived object appending repeatedly, but the actual
  kan usage pattern of one process per CLI invocation. This is the real risk
  surface for the file-is-new/header-once logic; 50 separate-instance
  appends with full reachability + `iter_all` checks every 10, run 5x with
  no failures during development (1000+ total appends across separate
  instances) before landing at a smaller CI-sized version.
