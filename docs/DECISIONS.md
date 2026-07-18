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
**Superseded by ADR-11:** the API-fit spike didn't catch it because it only
checked shape, not correctness under repeated writes — `atrium-repo`'s
`mst::Tree` had a confirmed silent data-loss bug at ordinary scale. ADR-11
covers this in full; it doesn't change the API-fit reasoning above, but it
did mean the M1–M3 `store/log.rs` built on top of it was unsafe, resolved
by ADR-12's switch.

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

## ADR-11 — CONFIRMED: `atrium-repo`'s MST silently loses data at ordinary scale
**Date:** 2026-07-16
**Status:** Filed upstream as
[atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343).
Resolved by ADR-12 (switch to `atproto-repo`) the same day.
**Finding:** `mst::Tree::add` followed later by `get` could silently and
permanently lose a previously-inserted entry. Confirmed via a minimal,
deterministic repro (`salt="salt-2"` failed at exactly 18 sequential
inserts, every time; never failed at 17) plus an aggregate: ~24% of
independent random key sequences lost data within 20 sequential inserts
using realistic, CID-shaped keys.
**Ruled out as causes** (each independently verified, not assumed):
- Missing `CommitBuilder::prev()` — a real bug in `store/log.rs`'s original
  usage (fixed), but fixing it did **not** fix the data loss.
  `atrium-repo`'s own `test_extract_complex` doesn't call `.prev()` either
  and passes, confirming it isn't required.
- Blockstore backend — identical failure rate (72/300) with
  `MemoryBlockStore` and `CarStore`.
- Tree lifecycle — identical failure rate with one long-lived `Tree` vs.
  reopening `Tree::open` from the root CID per insert (the pattern
  `Repository::add_raw` uses internally).
- `Repository`/`CommitBuilder`/signing — bug reproduced at the raw
  `mst::Tree` layer alone, no higher-level API involved.
- Key shape was likely the actual trigger: `atrium-repo`'s own test (short,
  fixed-13-char `Tid`-based keys) didn't reproduce even scaled to 50×30
  runs; failures correlated with longer, hash-derived (CID-shaped) keys —
  exactly what a content-addressed application keying by `add_raw` would
  naturally use.
**Practical impact:** every claim `store/log.rs` had appended since M1
(including dogfooding claims recorded after M3) carried this risk once a
`.kan/log/` accumulated on the order of 15-20+ claims. M1–M3 were already
merged; this wasn't a pre-merge catch. See ADR-12 for the resolution.

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

## ADR-14 — M4b: state fold, git-genesis anchors, `RelationProvider`s via shelling out to `git`
**Date:** 2026-07-18
**Decision:**
- **Git access is the `git` binary, shelled out to (`src/git.rs`'s
  `GitSubstrate`), not a library** (`git2`/`gitoxide`). Kan already requires
  running inside a git checkout (`.kan/` sits beside `.git/`, ADR-3), so
  `git` is always on hand; the only plumbing needed (`rev-list
  --max-parents=0`, `merge-base --is-ancestor`) is two read-only commands.
  Vendoring a git implementation for that would be the cathedral
  `CLAUDE.md`'s smell test warns against.
- **`Anchor::Workspace(GenesisCid)` is now real**: sha256 of the repo's
  sorted root-commit SHA(s) (`GitSubstrate::genesis`), replacing M3's
  placeholder (a hash of the checkout's canonical filesystem path, which
  differed per clone and was never portable — the doc comment on
  `cli::context::workspace_anchor` said so explicitly). This changes the
  `workspace` value on every claim; old local `.kan/` dogfooding data is
  unaffected in practice since nothing reads/filters on `workspace` yet.
- **`RelationProvider` (`src/relations.rs`)**: `GitAncestry` (commit
  ancestry between claims' `ArtifactRef::Commit`/`FileAt`/`LineRangeAt`
  shas) and `GitSameFile` (shared `FileAt`/`LineRangeAt` path — `About`
  strength, no ordering). Both infallible (`Vec<ComputedEdge>`, not
  `Result`) per `docs/SPEC.md` §6.1's sketch: a provider that can't
  determine an edge just omits it rather than failing the whole fold —
  computed edges are a bonus signal, not load-bearing the way the claim log
  is.
- **State fold (`src/fold/state.rs`)**: per merge-class, `Status`-kind
  claims reduce to one live position per author (strict intra-author
  supersession, §9), then classify: all-agree ⇒ `Confirmed`; exactly one
  live position (either only one author, or cross-author disagreement fully
  resolved by domination) ⇒ `Settled`; unresolved disagreement ⇒
  `Contested { resolved, open }`. Domination = an attested `cites` edge or a
  computed `Ancestry` edge from another live position — §9's
  "computably-ordered" tier folded into the same dominance check as attested
  ordering, since both are "this position is aware of / comes after that
  one," not two separate code paths.
- `kan resolve <subject> "<text>"` appends `ClaimBody::Resolution` — a
  narrative claim (never poset-classified), distinct from `ClaimBody::Status
  { value: Resolved }` (the structural kind `fold::state` reduces). v1's CLI
  vocabulary (`docs/HANDOFF.md`, REQ-13) has no verb for authoring `Status`
  claims directly; `fold::state::classify` is exercised at the library/test
  level (AC-4, AC-10) and wired into `kan status`'s rendering, ready for
  whichever future surface (MCP tool, `kan same`-style verb) starts emitting
  `Status` claims.
**Why:** REQ-4/REQ-5/REQ-6/REQ-7 (`.design/kan-spine.md`) and `docs/SPEC.md`
§5/§6/§9 specify all of this as HARD; M4a shipped the identity fold half,
this closes the state-fold half plus the anchor/provider machinery it
depends on.
**Consequences:** `kan` now hard-requires an actual git repository with at
least one commit to run at all (`Workspace::open` calls `GitSubstrate::open`
unconditionally) — `tests/cli.rs`'s fixtures gained a `git_repo()` helper
(`git init` + an empty commit) since M3's bare-tempdir fixtures no longer
satisfy that. This was already true in spirit (`.kan/` sits beside `.git/`,
ADR-3) but is now enforced instead of merely assumed.

## ADR-15 — M5: one action layer for CLI + MCP; round-robin greedy context assembly
**Date:** 2026-07-19
**Decision:**
- **`src/actions.rs` is the one place claim-mutation/view-rendering logic
  lives.** `Workspace` moved out of `cli::context` to a top-level
  `src/workspace.rs` (nothing CLI-specific about it), and `cli::show`/
  `status`/`session` were deleted — their logic moved into `actions`,
  returning `String`/`Cid` instead of `println!`ing directly. `src/cli/
  mod.rs` is now argument parsing and printing only; `src/mcp.rs` is typed
  params in, text out. Neither surface has logic the other doesn't share —
  the literal implementation of `CLAUDE.md`'s "one surface: CLI + MCP,"
  which until now was true of the vocabulary but not the code.
- **`kan mcp` reopens `Workspace::open` fresh per tool call**, exactly like
  every separate CLI invocation does, rather than holding one `Workspace`
  across the server's lifetime. Simpler than a `Mutex`-guarded shared
  `Workspace` (no concurrent-mutation question to reason about) and
  correctness-first (never stale) at the cost of redoing the
  rebuild-index-from-log work per call — fine at today's scale per the same
  reasoning `Workspace::open`'s own doc comment already gives for doing this
  on every CLI run.
- **`rmcp`'s tool surface (ADR-10) is 11 tools**, not the 10 ADR-10 counted
  — `observe/plan/decide/resolve/same/show/issues/status/session_start/
  session_end/context` is 11 items; ADR-10's number was simply a miscount
  during Q3's resolution, not a scope change. `#[tool_router]`/
  `#[tool_handler]` need the explicit `router = self.tool_router`/`router =
  tool_router` form (confirmed via `rmcp-macros`' own doc comments, not
  assumed from the bare-attribute example) — the bare form defaults to
  `Self::tool_router()`, rebuilding a fresh router every call instead of
  reusing the one built in `KanServer::new`, and clippy's `dead_code` lint
  catches exactly this if the struct field goes unread.
- **Context assembly (`src/context.rs`) has no spec-mandated ranking
  algorithm** (`docs/SPEC.md` §11 names the feature, not a method). v1's
  choice: value a claim by kind (`Status`/`Decision`/`Blocker`/`Resolution`
  outrank narrative, which outranks `Relation`/`Retraction` bookkeeping)
  with recency as a same-kind tiebreak, selected round-robin across
  merge-classes (one claim per class per round, highest-value-that-fits)
  rather than one global greedy pass — so one chatty subject can't starve
  the budget for everything else. Deterministic by construction: class
  order comes from `fold::identity::merge_classes`'s already-sorted
  subjects, and every sort has an explicit tiebreak, so nothing depends on
  hashmap iteration order (AC-7).
- **`kan issues`'s "done" heuristic**: a live `ClaimBody::Resolution` (what
  `kan resolve` writes) OR a state-fold `Settled{Resolved|Closed}`. Not
  spec-mandated (`.design/kan-spine.md`'s CLI table says only "fold + render
  the issue-like view") — chosen because v1's CLI has no verb for authoring
  `Status` claims directly, so `Resolution` is, in practice, the only signal
  most subjects will ever carry.
**Why:** REQ-12/REQ-13/REQ-14 (`.design/kan-spine.md`), `docs/SPEC.md` §11,
AC-7/AC-8. This is the last of the spine's HARD requirements; what's left
after this (M6) is fixtures and polish, not new mechanism.
**Consequences:** `Cargo.toml` gained `schemars` (direct dependency, for
`#[derive(JsonSchema)]` on tool-parameter structs) and `rmcp`'s
`transport-io` feature (not in `rmcp`'s default set). Dev-dependencies
gained `serde_json` and `tokio`'s `process` feature, both test-only (driving
`kan mcp` as a real subprocess for AC-8, `tests/mcp_server.rs`).

## ADR-16 — CONFIRMED and FIXED: cross-author `Retraction` wasn't gated by same-author (or any trust)
**Date:** 2026-07-20
**Status:** Found by a dedicated software-review pass (a forked agent instructed
to audit the whole codebase against `docs/SPEC.md`/`docs/DECISIONS.md`/
`CLAUDE.md`, not a user report), fixed same day.
**Finding:** `fold::identity::excluded_by_retraction` (`src/fold/identity.rs`)
took no `TrustBase` and never checked that a `Retraction`'s author matched the
author of the claim it targeted. Any author's `Retraction` claim — trusted or
not, even a total stranger's — silently excluded *any other author's* claim
from *every* viewer's fold, including a `SoloTrust` viewer who never trusted
the retracting author at all. `docs/SPEC.md` §8 is explicit that this is
supposed to be structurally impossible ("Cross-author 'retraction' is NOT
possible — you can't write to another's log"), not merely trust-gated —
`excluded_by_retraction` is called once, trust-independently, at the top of
`fold::fold`, before either `merge_classes` or the trust filter ever runs, so
there was no later trust check that could have caught this either. Directly
undermines "provenance is sacred" (`CLAUDE.md`).
**Fix:** `excluded_by_retraction` now tracks each seen claim's author and only
lets a `Retraction { supersedes }` take effect — both the initial exclusion
and the "retracting a retraction" undo path (ADR-6) — when the retracting
claim's author exactly matches the target claim's author. An other-author
`Retraction` is simply inert: not an error, not excluded, just never entered
into `excluded`/`active_retraction_target` at all. The function still takes
no `TrustBase` — that absence is now the documented point, not an oversight:
self-retraction is a data-level invariant, unconditionally same-author-only,
completely separate from `Relation::Rejects`'s trust-gated cross-author
suppression.
**Verification:** new regression test
(`tests/identity_fold.rs::cross_author_retraction_is_not_honored_even_when_fully_trusted`)
uses `PeerContested` trusting *both* the owner and the stranger equally,
specifically so the test can't be satisfied by ordinary trust gating alone —
confirmed to fail against the pre-fix code (reverted via `git stash`, re-ran,
watched it fail with the exact predicted symptom) and pass against the fix,
per the same "verify, don't assume" discipline ADR-11/12 established.

## ADR-17 — Software-review-pass fixes: bugs #2–#6, anti-patterns, testing gaps, docs
**Date:** 2026-07-20
**Status:** All from the same forked-agent review pass that found ADR-16's bug
(the fork was told to review the whole codebase against `docs/SPEC.md`/
`docs/DECISIONS.md`/`CLAUDE.md`, not just look for one thing). Bundled into
one milestone since each is small and independent; ADR-16's higher-severity
finding shipped separately, first.
**Fixes:**
- **`TidGenerator` reseeds from the reopened log's last commit `rev`**
  (`src/store/tid.rs`'s new `seeded`/`decode`, called from
  `Log::open_or_create`'s reopen branch with `commit.rev`) instead of always
  starting at 0. Kan's real usage is a fresh process per command (ADR-15), so
  "strictly monotonic within one generator's lifetime" wasn't actually strong
  enough — a backward wall-clock step between two separate invocations could
  have produced a non-monotonic `rev`.
- **`GitSubstrate::genesis()` rejects shallow clones** (`git rev-parse
  --is-shallow-repository`, new `Error::ShallowClone`) instead of silently
  hashing a truncated history — a shallow clone's root commit is wherever the
  clone was truncated, not the repo's real genesis, which would have violated
  §5's "computed identically by every actor" invariant silently.
  `tests/git_substrate.rs`'s regression test needed `git clone --depth 1
  --no-local`: git silently ignores `--depth` for local-filesystem clones,
  so a naive local-clone test would have "passed" without exercising a real
  shallow clone at all.
- **`fold::state::classify` re-checks agreement among domination survivors**:
  a 3-way disagreement resolved by ordering down to 2 agreeing survivors now
  correctly reports `Confirmed`, not `Contested`.
- **`Log::iter_all` tolerates one `BadSignature` record** (skip + `eprintln!`
  warning) instead of failing the entire log — `docs/SPEC.md` §8's "folds
  tolerate dangling cites" philosophy extended to a corrupt/forged record,
  which previously made every command fail on account of one bad claim.
  Any *other* error kind still propagates; only this specific, legible case
  is tolerated.
- **`actions::issues`'s session exclusion uses `.contains`, not `==`** against
  a single-element vec — a merge-class containing "session" (e.g. after `kan
  same`) is still bookkeeping, not an issue, regardless of what else got
  merged into it. Fixed while resolving the adjacent `compute_default`
  redundancy below, not as a separate patch.
- **`issues`/`status` no longer compute `relations::compute_default` twice
  per subject** — new shared `actions::classify_subject` computes each
  subject's edges once; both callers reuse the same `StateView`.
- **`Index::open` propagates `create_dir_all`'s error** instead of discarding
  it via `.ok()` — a real directory-creation failure now surfaces as its own
  clear cause instead of a harder-to-diagnose SQLite-open error downstream.
- **`context::render_claim` renders actual prose**, not a `{:?}` Debug dump —
  extracts each `ClaimBody` variant's real content (narrative text, a
  `Status` value, a `Relation`'s kind+target, `Retraction`'s target) instead
  of printing Rust struct/enum syntax. The doc comment calling this "the text
  an agent would actually see" was aspirational before; now it's accurate.
- **`cid::canonical_bytes` deleted** — zero callers anywhere, dead public API.
- **Documentation-only**: `fold::trust`'s doc comment now explains
  `PeerContested`'s CLI/MCP-unreachability is deliberate (v1's real scope has
  no second human to weigh trust against, not an oversight);
  `relations::GitAncestry`'s doc comment now states its O(n²) +
  subprocess-per-comparison scaling explicitly, matching `fold::identity`'s
  own honesty about its O(n) recompute cost; `GitSubstrate::is_ancestor`'s
  doc comment explains why it deviates from git's real reflexive
  `--is-ancestor` semantics; `docs/SETUP-TODO.md`'s Phase 3 checklist no
  longer overclaims `RelationProvider`s as "disableable" (down-weighting
  isn't built yet).
- **New test coverage, no code change**: `ClaimBody::Subject`/`SubjectKind`
  round-trip through the log (previously zero coverage, and no CLI verb
  constructs them — the data model defines them regardless).
**Deferred, not fixed here:** `docs/DECISIONS.md` ADR-7 and `CLAUDE.md` still
listing `session` in the CLI's "exact" vocabulary — folds into
`.design/agent-ax-and-tool-boundary.md`'s session-removal work, the next
milestone, rather than a standalone patch to text about to change again.

## ADR-18 — The kan/companion-tool scope boundary; `kan session` removed
**Date:** 2026-07-21
**Context:** A dogfooding self-review (using kan to track its own M1–M6
build) surfaced real agent-experience friction, and working through the
fixes surfaced a bigger question: crosslink (kan's predecessor, `CLAUDE.md`
"Provenance") let workflow/AX concerns — session orchestration, interactive
design authoring, code-review orchestration — creep into the same tool as
the memory substrate itself. `.claude/commands/design.md`, the very `/design`
workflow used to write this decision's design doc
(`.design/agent-ax-and-tool-boundary.md`), is itself an instance of exactly
that creep, sitting inside kan's own repo.
**Decision — the boundary rule:** kan owns a feature *iff* it needs a new or
existing `ClaimBody`/`ClaimKind`/`Anchor`/`RelationKind` variant, or is a
pure read/fold over the claim graph that needs no memory of *when* or *why*
to call it. A feature belongs in a future, separate companion tool if it can
be built entirely as a calling convention over kan's existing primitives
(subject naming, `cites`, `artifacts`) without touching kan's data model —
i.e. it's process, orchestration, or multi-turn interaction, not durable
fact-recording. Narrow exception: kan may still include minimal
self-description/setup affordances for its *own* interface (install
helpers, `--help`, discoverability hints) — these describe the tool, they
don't prescribe how an agent should use it over time. The companion tool, if
and when it's built, is a separate `kan-tools` repo/install that consumes
kan via its CLI/MCP — not a new mode of kan itself (`CLAUDE.md`'s "one
surface: CLI + MCP" still holds for kan's own surface).
**Applying the rule, concretely:**
- `kan session start`/`end` **removed** from the CLI and MCP vocabulary.
  It never needed a new `ClaimBody` variant — `kan session start` just
  appended `ClaimBody::Observation` on a fixed `"session"` subject
  (`src/actions.rs`'s own prior doc comments said so) — so it fails the
  rule outright. Session-as-a-concept (grouping claims into a bounded span,
  deciding when to start/end one) is now the companion tool's job, built on
  kan's existing `observe --subject <x>` / `cites` primitives. Removing it
  also retired `actions::issues`'s special-cased exclusion of a `"session"`
  subject — with no built-in session concept, no subject is special-cased
  in `issues` anymore; every subject is judged the same way.
- `.claude/commands/design.md` **stays, flagged as tech debt** (a note in
  the file itself) rather than removed immediately — it keeps working until
  the companion tool exists to receive it; no functional change this pass.
- A proposed offline-embedding vector index (issue #15) **passes** the
  rule: it's a pure derived read projection over the claim graph, the same
  category as the fold and the SQLite index, no new `ClaimBody` needed. It
  belongs in kan, confirming the rule discriminates usefully rather than
  just rationalizing the session removal.
**Supersedes:** ADR-7's CLI-vocabulary quote and `CLAUDE.md`'s vocabulary
line both listed `session` as part of the "exact" v1 vocabulary; both are
now stale on that one point. ADR-7's own decision (no hard-delete CLI verb)
is unaffected — only the vocabulary list it quoted changed. `CLAUDE.md` is
updated directly (living documentation); ADR-7's historical text is left
as-is, per the same practice ADR-12 used when superseding ADR-1.
**Consequences:** `kan mcp install` (a new leaf under the existing `mcp`
verb, not a new top-level verb) prints two current, researched — not
guessed — Claude Code registration paths: a bare `claude mcp add kan --
<binary> mcp` command, and (via new `.claude-plugin/plugin.json` +
`.mcp.json` files at the repo root) a Claude Code plugin install. `kan
show`/`kan status` now list existing subjects when a specific lookup misses
(`actions::subject_hint`), directly derisking the silent-typo failure mode
dogfooding surfaced. Write verbs gained a `--verbose`/`-v` flag (CLI stdout
stays a bare CID by default — load-bearing for `--cites` piping,
`tests/cli.rs`); every MCP write tool always returns the richer
confirmation text, since tool-call results aren't shell-composed the way
CLI stdout is. `KanServer::get_info()`'s instructions were rewritten to be
purely factual about the data model, with no sequencing language — guarded
by a test that greps for it.

## ADR-19 — First release: v0.1.1-beta.1, tag-push-triggered crates.io CD
**Date:** 2026-07-21
**Decision:** First real crates.io publish (the crate name itself was already
reserved at a `0.0.0` stub, `docs/SETUP-TODO.md` Phase 0) is `0.1.1-beta.1` —
a genuine semver pre-release, not just an informally-described "beta" at a
plain version number. `.github/workflows/release.yml` publishes on push of a
tag matching `v*.*.*`; the job re-runs the full `build`/`test`/`clippy`/`fmt`
gate itself (not trusting a separate `ci.yml` run via cross-workflow status,
which the same tag push also triggers independently) and verifies the pushed
tag's version matches `Cargo.toml`'s before calling `cargo publish`.
**Why:** A semver pre-release version means downstream users never resolve
it as a default dependency without an exact pin — the standard way to signal
"not yet stable" through the version string itself, chosen explicitly over a
plain `0.1.1` that would only be "beta" by informal description. Tag-push
(not GitHub-Release-published) keeps the trigger to one deliberate action
(`git push --tags`) fully under the releaser's control, no separate release-
notes-UI step required.
**Consequences:** Publishing requires a `CARGO_REGISTRY_TOKEN` repo secret
(a crates.io API token with publish scope) — added directly via the GitHub
UI or `gh secret set`, never through a chat session, since it's a credential
Claude Code should never see or handle. `README.md`/`LICENSE` already
existed and needed no changes; `Cargo.toml` gained `readme = "README.md"`
for the crates.io page. `cargo publish --dry-run --allow-dirty` confirmed
clean packaging both before and after the version bump.

## ADR-20 — `crates-io` GitHub Environment scopes the publish secret and tag policy
**Date:** 2026-07-21
**Decision:** `.github/workflows/release.yml`'s `publish` job now declares
`environment: crates-io`. Created via the GitHub API (`PUT
/repos/kan-tools/kan/environments/crates-io`), with a deployment-tag policy
restricting it to tags matching `v*.*.*` — a second, independently-enforced
guard beyond the workflow's own `on.push.tags` filter. `CARGO_REGISTRY_TOKEN`
should be added as an environment-scoped secret (`gh secret set
CARGO_REGISTRY_TOKEN --env crates-io`, or the environment's own GitHub UI
page), not a repo-wide one — scopes the token to exactly the job that
declares this environment, not every workflow in the repo.
**Why attempted and only partly succeeded:** the original intent was also a
required-reviewer approval gate (a manual "approve" click before `cargo
publish` runs, even after the tag is pushed) — GitHub's own docs say
environment protection rules are free for public repositories. Attempting it
returned a 422: `"Please ensure the billing plan supports the required
reviewers protection rule"` — confirmed via the actual API call, not assumed
from docs. `kan-tools` is an *organization*, and required reviewers on
environments needs GitHub Team/Enterprise Cloud for org-owned repos
specifically, even when the repo itself is public; the "free for public
repos" carve-out applies to personal-account-owned repos. `can_admins_bypass`
defaults to `true` regardless, so this was never going to be an unconditional
gate even if available.
**Consequences:** the tag push remains the one deliberate manual gate before
a real publish (unchanged from ADR-19) — no additional approval step exists
yet. Revisit if `kan-tools` ever moves to a paid GitHub plan; until then, this
is a known, confirmed platform limitation, not an oversight.

## ADR-21 — v0.2 write-surface layout: pair-writes, a real `retract`, and a CLI-only status-value enum
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
