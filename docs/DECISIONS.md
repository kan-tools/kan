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

## ADR-22 — Every write verb auto-attaches `HEAD`; `--file` layers a tighter anchor on top
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

## ADR-23 — `Anchor`-vs-`Anchor` `SameAs` rejected as a witness, enforcement ahead of syntax
**Date:** 2026-07-17
**Decision:** `fold::identity::merge_classes` now excludes a `SameAs`
witness from the identity fold's graph whenever either side (`from` or
`to`) is a `SubjectRef::Anchor` — the same exclusion path an untrusted or
cross-author witness already takes, not a separate error type. No CLI
syntax exists yet to construct an `Anchor` subject, so this only fires
against library-constructed claims today; covered by a direct unit test in
`tests/identity_fold.rs` (`sameas_touching_an_anchor_is_not_honored`),
matching that file's existing pattern for other library-only scenarios
(untrusted witnesses, cross-author retraction).
**Why:** `docs/SPEC.md` §5.1 states plainly: "SameAs between two Anchors is
a TYPE ERROR, not a claim" — `Anchor` identity is strict and decided by
construction (content-addressed, computed identically by every actor), so
asserting two Anchors are "the same" is a category error, not a
disagreement a trust policy could ever resolve. Landing the enforcement now,
before any CLI path can construct an `Anchor` subject, means the follow-up
issue that adds that syntax inherits an already-tested guard rather than
having to remember to add one itself.
**Consequences:** None of `kan`'s current write verbs are affected — no
CLI/MCP surface constructs `SubjectRef::Anchor` yet (a deliberately separate
follow-up, out of v0.2's scope per `.design/v0.2-milestone.md`). The check
is defensive infrastructure, verified correct now rather than assumed
correct later.

## ADR-24 — `KAN_AGENT`: an honest, temporary patch for agent-identity reachability
**Date:** 2026-07-17
**Decision:** `Workspace::my_author()` now reads the `KAN_AGENT` environment
variable; if set, `AuthorId.agent` becomes `Some(sha256(KAN_AGENT))` instead
of always `None`. This is explicitly a placeholder — `derive_agent_key`'s
doc comment says so directly — not a real per-agent keypair: `sign::verify`
is unchanged and still checks only the human's DID-embedded signature, never
anything derived from `KAN_AGENT`. This repo's own `.mcp.json` sets
`"env": {"KAN_AGENT": "claude-code"}` on the bundled server entry, so MCP
usage gets a sensible default agent tag with zero configuration (standard
MCP server `env` config, no kan-specific protocol). `Workspace::solo_trust`
now reads as narrower than it looks: it trusts exactly *this process's*
`AuthorId` (did + current `KAN_AGENT`, if any), so a `KAN_AGENT`-tagged
write is only visible back to a read made in that same `KAN_AGENT` context
— unchanged default behavior when `KAN_AGENT` is unset (still just the
human identity), but new behavior once it's in play.
**Why:** Before this, `AuthorId.agent` was never `Some(...)` anywhere
outside hand-constructed library tests — real signed claims never carried a
distinct agent identity, so `TrustBase::PeerContested` (fully built and
tested, `fold::trust`'s own doc comment) had nothing genuine to
distinguish. A real per-agent-keypair design (separate signing keys,
signature verification against an agent-embedded pubkey) is real,
non-trivial design work of its own — plausibly its own problem domain
outside kan entirely, worth checking existing workload-identity-style
standards against before inventing one from scratch. Shipping a hash-based
placeholder now, honestly labeled as such, closes the *reachability* gap
(agents can be told apart at all) without pretending to close the
*security* gap (nothing stops an agent from claiming any name) — the
dishonest alternative would be silently treating `derive_agent_key`'s
output as if it were a real key, which `claim::AgentKey`'s own doc comment
("compressed public key bytes of the signing agent") would then be lying
about for real claims, not just aspirationally for as-yet-unused ones.
**Consequences:** Filed as its own explicitly-not-v0.2 follow-up issue: the
real per-agent cryptographic identity design (see `.design/v0.2-milestone.md`
Out of Scope). AC-8 is proven end-to-end in `tests/kan_agent.rs`: two real
`kan observe` subprocess invocations under different `KAN_AGENT` values
produce two distinct, real signed `AuthorId`s (not hand-typed structs), and
a `PeerContested` `TrustBase` built from those real values can tell them
apart, while a `Solo` trust of just the untagged identity stays exactly as
narrow as before this patch.

## ADR-25 — Identity key moves to the OS keychain, plaintext-file fallback preserved
**Date:** 2026-07-17
**Decision:** `sign::Identity::load_or_create` now tries the OS keychain
first (`keyring` crate v4.1.5, default features — these already cover
macOS Keychain, Windows Credential Manager, and Linux Secret Service via
D-Bus with no extra feature flags needed, confirmed by reading the crate's
own `[features] v1 = [...]` table rather than assuming from its README).
Keyed by the canonicalized `.kan/identity` path as the keychain "account"
(service `dev.kan.identity`), so each checkout keeps its own identity —
same per-checkout scoping the plaintext file already had (ADR-3), keychain
or not. Three cases: already in the keychain → read it; not yet in the
keychain but a plaintext file exists → migrate it in (write to the
keychain) and **deliberately leave the plaintext file in place** as a
fallback copy, not delete it — REQ-16's explicit open decision, resolved
here; neither → generate fresh and write only to the keychain, no
plaintext file created (the actual point of issue #6). If the keychain is
genuinely unavailable at any point, falls back entirely to the original
plaintext-file-only behavior with a loud `eprintln!` warning.
**Crate-trust spike (CLAUDE.md's house rule, before building on it, not
after):** read the actual `keyring`/`keyring-core`/
`zbus-secret-service-keyring-store` source (not just docs), confirming
`Entry::new`'s failure mode is a clean `Err`, not a hang, and that a
missing entry is a distinct `Error::NoEntry` rather than conflated with a
platform failure. Then stress-tested for real on this machine (macOS): 20
sequential inserts, each followed by re-verifying *every prior* entry is
still reachable (not just the latest, and not just checked once at the
end) — the same discipline ADR-11/12 used to catch `atrium-repo`'s MST
data-loss bug — all passed cleanly, no hang, no OS permission prompt.
`.github/workflows/ci.yml` runs on `ubuntu-latest` with no Secret Service
daemon by default, so this PR's own CI run is the real-environment proof
of the fallback path (AC-9) — the exact "headless CI" scenario REQ-15
names, not simulated.
**Why:** Issue #6 flagged the identity key sitting in plaintext at rest as
a real gap; the OS keychain is the standard place to fix that without
inventing kan-specific encryption. Leaving the plaintext file in place
after migration (rather than deleting it) was chosen over deletion because
a keychain write that silently didn't durably persist (a young-ish crate,
hence the spike above) would otherwise orphan the identity with no
recovery path — consistent with the project's broader "no operation
destroys a subject" caution, applied here to the identity file itself even
though it isn't a claim.
**Consequences:** `Cargo.toml` gains the `keyring = "4.1.5"` dependency,
default features only. `tests/keychain_identity.rs` covers idempotency,
migration-preserves-the-plaintext-file, and AC-9 — the AC-9 test is
written to hold correctly under *either* outcome (keychain available or
not) rather than assuming which branch a given CI/dev machine takes, since
that's genuinely environment-dependent and the point is exercising the real
platform behavior, not mocking it away.

## ADR-26 — MCP resource: `kan://claims/{subject}`, one template, no enumeration
**Date:** 2026-07-17
**Decision:** `kan mcp` now advertises one `ResourceTemplate`
(`kan://claims/{subject}`, returned from `list_resource_templates`) and
implements `read_resource` to parse the subject out of a
`kan://claims/<subject>` URI and return `actions::show`'s text as a
`TextResourceContents`. `resources/list` (`list_resources`) stays at
`ServerHandler`'s default empty implementation — no fixed enumeration of
every known subject as a discrete `Resource`, since subjects are
open-ended; a client constructs a URI from a subject name it already knows
from a tool call (`show`/`issues`/`status`). No prompts, matching issue
#28's own framing ("exploratory... start with the smallest real slice").
**`rmcp` API shape, confirmed by reading the actual crate source** (not
guessed at, matching the plugin-manifest research's "verify, don't assume"
discipline from the AX-pass session): `ServerHandler` already has
default-implemented `list_resources`/`list_resource_templates`/
`read_resource` methods (`rmcp-2.2.0/src/handler/server.rs`) — no
attribute-macro equivalent of `#[tool]`/`#[tool_router]` exists for
resources in this version, so they're overridden directly as plain async
fns in the same `impl ServerHandler for KanServer` block that already
holds `get_info`. Confirmed `#[tool_handler]` only ever injects
`call_tool`/`list_tools` (`rmcp-macros-2.2.0/src/tool_handler.rs`), so it
doesn't collide with or need to know about the resource methods.
`ListResourceTemplatesResult`/`ListResourcesResult` both come from a
`paginated_result!` macro exposing a `with_all_items(vec![...])`
constructor (not a builder or `::new`, found by reading the macro
expansion, not assumed from the type name).
**Why:** REQ-17's minimal scope ("one resource," "start with the smallest
real slice") argues directly against also building resource enumeration or
prompts in this pass — both are real, separate scope, not needed to prove
the "an MCP client can read a subject's claims via URI" slice this AC
actually asks for.
**Consequences:** `KanServer::get_info` now also calls `.enable_resources()`
on the capabilities builder, and its instructions gained one factual
sentence naming the resource URI (still guarded by the existing sequencing-
language test in `tests/mcp_server.rs`, unaffected since the new sentence
adds no such language). `tests/mcp_server.rs` gained
`ac10_resource_template_lists_and_reads_a_subjects_claims`, a full
JSON-RPC-over-stdio round trip against the real `kan mcp` subprocess:
`initialize` advertises the resources capability, `resources/templates/list`
returns the template, `resources/read` on `kan://claims/<subject>` returns
the same claim text an equivalent `show` tool call would.

## ADR-27 — Witness provenance surfaced through the fold; `kan show` gains a `GitSameFile` consumer
**Date:** 2026-07-17
**Decision:** `fold::SubjectView` gains a `witnesses: Vec<identity::SameAsWitness>`
field, populated straight from `identity::MergeClass::witnesses` in
`fold::fold`'s `MergeClass` → `SubjectView` conversion (previously
discarded there, REQ-18). `kan show`'s "merged with" line now also prints
each witness's author, direction, and claim CID (REQ-19/AC-11), not just
the flat merged subject list. Separately, `kan show` now also computes
`relations::compute_default` (REQ-20/AC-12) and, when any of the subject's
claims share a `GitSameFile` edge with a claim belonging to a *different*
merge-class, prints a "related subjects (same file)" line naming that
other class. Since a same-file relation is inherently cross-subject,
`compute_default` runs over every live claim in the fold (not just the one
subject's own claims, unlike `classify_subject`'s narrower usage for
`status`/`issues`) — O(n²) over the whole live claim set on every `kan
show`, the same accepted-cost trade `relations::GitAncestry` already
documents (correctness before performance, `CLAUDE.md`).
**Why:** `docs/SPEC.md` §4.3 is explicit: "the fold must carry its
factorization + witness set... NEVER silently promote a long weak chain to
strict identity" — silently dropping `MergeClass.witnesses` at the exact
point it was already computed correctly was a real violation of that
requirement, not just an unreached feature, since every `kan show` on a
merged subject was already hitting the discard. `GitSameFile` edges were
computed and threaded through `relations::compute_all` since M4b but had
zero consumer anywhere — this closes that gap with the smallest real
surfacing (a read-only line), not a new ranking or scoring mechanism.
**Consequences:** `tests/cli.rs` gained `show_on_a_merged_subject_names_a_witness`
(AC-11) and `show_lists_a_subject_sharing_a_file_anchor_as_related`
(AC-12, using the `--file` flag PR2/ADR-22 added to construct two
same-file-anchored claims under different subjects). No change to
`fold::fold`'s public signature or `TrustBase`/identity semantics — this is
additive data threaded through an existing conversion, not a new
computation.

## ADR-28 — Second release: v0.2.0-beta.1
**Date:** 2026-07-18
**Decision:** `Cargo.toml`'s version bumps `0.1.1-beta.1` → `0.2.0-beta.1` —
a minor-version bump (new backward-compatible functionality: the full v0.2
write surface, artifact auto-attachment, the `KAN_AGENT` patch, keychain
storage, the MCP resource), staying a semver pre-release rather than
promoting to a stable `0.2.0`. No changes needed to `release.yml` or the
`crates-io` environment — both already exist and worked cleanly for the
first release (ADR-19/ADR-20).
**Why beta again, not stable:** confirmed data compatibility with
`v0.1.1-beta.1` first (checked, not assumed) — `src/store/` is untouched
byte-for-byte since the first release, and `src/claim.rs`'s only diff is a
derive, not a field/variant change, so every v0.1.1-beta.1 `.kan/log/` and
`.kan/identity` reads and continues to work unmodified under v0.2. That
compatibility is real, but the project itself isn't yet: several
known-reachability gaps remain open (non-`SameAs` `RelationKind`s, issue
#31; `ClaimBody::Subject`/`SubjectKind` construction, issue #32; real
per-agent cryptographic identity replacing the `KAN_AGENT` placeholder,
issue #30) and `docs/SPEC.md`'s v1 scope fence isn't fully closed out yet.
A pre-release version keeps signaling "not yet stable" honestly rather than
implying more finality than the current state warrants.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging before tagging, same discipline as the first release.

## ADR-29 — v0.3 relation surface: `kan relate`, `Rejects` reshaped into its own claim kind, `retract`/`reject` split
**Date:** 2026-07-19
**Decision:** Three related changes closing issue #31 (`.design/v0.3-milestone.md`
REQ-1..6):
1. New CLI/MCP verb `kan relate <a> <kind> <b>` (`actions::relate`) writes
   `ClaimBody::Relation { kind, target }` for `kind` ∈ `{blocks, about,
   manifests-at, depends-on, accepts}` — a `clap::ValueEnum` (`cli::
   RelationKindArg`, kept out of `claim.rs` the same way `StatusValueArg`
   is) that only has these 5 values, so `same-as` is rejected at argument
   parsing rather than by a runtime check. `kan same` stays its own verb,
   unfolded — `SameAs` is the only identity-conferring edge and already
   carries more ceremony (the component-size guardrail, ADR-23's
   Anchor-vs-Anchor rejection) than an ordinary relation.
2. `RelationKind` narrows from 7 to 6 variants: `Rejects` removed.
   `ClaimBody` gains a new top-level `Rejects { claim: Cid }` variant
   (`ClaimKind` gains a matching `Rejects`, sitting beside `Retraction`, not
   nested in `Relation`) — structurally mirroring `Retraction`'s
   `supersedes: Cid` shape, not `Relation`'s `{ kind, target: SubjectRef }`
   shape. Zero-cost correction: no CLI/MCP path ever constructed
   `RelationKind::Rejects`, so no existing log data references the removed
   variant.
3. New verb `kan reject <cid>` (`actions::reject`) writes `ClaimBody::
   Rejects { claim }`, only against a *different* author's claim — erroring
   (`Error::CantRejectOwnClaim`, message naming `kan retract`) on the
   caller's own. `kan retract`'s existing cross-author error
   (`Error::NotYourClaim`) is updated the same way, naming `kan reject`.
   Two verbs with a write-time author check each, not one verb silently
   dispatching between two claim kinds depending on whose claim the CID
   turns out to be — no single call should have two possible fold-time
   meanings depending on facts the caller may not track.
   `fold::identity::excluded_by_rejection(claims, trust) -> HashSet<Cid>` is
   a new sibling to `excluded_by_retraction`, but **trust-gated** (unlike
   self-retraction, which is deliberately `TrustBase`-independent): a live
   `Rejects { claim }` claim excludes `claim` from a viewer's fold only
   when that viewer's `TrustBase` trusts the rejecting author
   (`docs/SPEC.md` §8's "a local suppression honored only by folds that
   trust the rejecter"). Threaded through both `fold::fold`'s general
   claim-visibility filtering and `identity::merge_classes` (a rejected
   `SameAs` witness stops contributing to identity computation for a viewer
   who trusts the rejecter) — the same two threading points
   `excluded_by_retraction` already has. Undo needs no special-casing: a
   `Rejects` claim is itself an ordinary claim CID, so an author retracting
   their own `Rejects` (via the existing `Retraction` mechanism) already
   makes `excluded_by_rejection` skip it.
**Why:** `RelationKind::Rejects` looked like a domain-semantic edge the way
`Blocks`/`About`/etc. are, but isn't one — it doesn't relate two subjects,
it suppresses one specific claim, which is exactly what `Retraction`
already does for same-author claims. Modeling it as `Relation`'s sibling
instead of `Retraction`'s sibling would have meant a `SubjectRef` target
standing in for "the claim I mean," an indirection with no benefit once the
shape mismatch was named directly. The `retract`/`reject` split (rather
than one verb with silent dispatch) follows the same reasoning ADR-21
already used for `resolve`/`block` staying separate from a generic
status-setter: an agent's single action should have exactly one fold-time
meaning, readable from which verb it called, not inferred after the fact
from claim authorship.
**Consequences:** `src/context.rs`'s `render_claim`/`kind_value` gained
match arms for `ClaimBody::Rejects`/`ClaimKind::Rejects` (filed alongside
`Retraction` in the value-scoring tier — bookkeeping, not narrative
content). New tests: `tests/cli.rs` (`relate_writes_a_relation_claim_for_
each_non_identity_kind`, `relate_rejects_same_as_at_argument_parsing`,
`reject_refuses_the_callers_own_claim`), `tests/write_surface.rs`
(`reject_writes_a_rejects_claim_against_another_authors_claim`, the
own-claim library-level counterpart, and the updated `NotYourClaim` message
assertion) — the cross-author success/failure split needs a genuinely
different signing `Identity`, the same reason `retract`'s own cross-author
test lives at the library level, not through the CLI subprocess harness.
`tests/identity_fold.rs` gained the trust-gating pair
(`rejects_claim_excluded_when_viewer_trusts_the_rejecter`/
`rejects_claim_from_untrusted_author_is_not_honored`) plus
`rejected_sameas_witness_does_not_merge_when_rejecter_is_trusted` for the
`merge_classes` threading point specifically. MCP `relate`/`reject` tools
are deliberately deferred to the verb-lexicon-reorg PR (REQ-10..12),
alongside the rest of that PR's MCP param additions, rather than mirrored
here.

## ADR-30 — `--title`/`--kind` construct `Subject` claims; `kan issues` requires a real eligibility signal, not just "never resolved"
**Date:** 2026-07-19
**Decision:** Two related changes closing issue #32 (`.design/v0.3-milestone.md`
REQ-7..8):
1. `kan observe`/`kan plan`/`kan decide`/`kan block`/`kan resolve` all gain
   optional `--title <text> --kind issue|idea|question` flags
   (`cli::SubjectKindArg`, kept out of `claim.rs` the same way
   `StatusValueArg`/`RelationKindArg` are), required together — validated
   (`actions::validate_title_kind`) *before* any claim is written, so a
   lone `--title` or `--kind` never leaves a partial write (an orphaned
   narrative claim with no `Subject`, or vice versa). When given, an
   additional `ClaimBody::Subject { title, subject_kind }` claim is written
   alongside whatever the verb already writes. `observe`/`plan`/`decide`'s
   return type changes from bare `AppendResult` to a new
   `actions::NarrativeResult { narrative, subject: Option<AppendResult> }`;
   `resolve`/`block`'s existing `PairedAppendResult` gains a third
   `subject: Option<AppendResult>` field alongside its `narrative`/`status`
   pair. Both keep the bare-CID-by-default contract pointed at the
   *narrative* claim's CID regardless of whether the optional `Subject`
   claim was written — `--verbose` is the only way to see it.
2. `actions::issues` no longer treats "this subject has never had a
   `Status` claim" as equivalent to "open." A class is now only
   issue-*eligible* — checked before "done" is even considered — when it
   has at least one live `Status` claim (any value; presence of the claim
   kind is the signal, not which value) **or** its most recent live
   `Subject` claim declares `SubjectKind::Issue`. A class with neither
   signal is excluded entirely, not marked done.
**Why:** `ClaimBody::Subject`/`SubjectKind` existed in the type system since
early on but had no construction path and no behavioral consumer — pure
reachability debt (issue #32). Giving it real weight needed both halves at
once: writing it (part 1) would have been inert without `issues` actually
reading it (part 2), and fixing `issues` without a way to write `Subject`
claims would have left "declare this an issue before it has a status" with
no mechanism. The bug `issues` fix corrects is real and was live on this
very repo: `kan issues` listed `spine` — kan's own dogfooding log, which has
only ever carried `Observation`/`Plan`/`Decision` claims and structurally
never should carry a `Status` one — as an open issue, purely because
"never resolved" and "never opened" were conflated. Requiring `--title`/
`--kind` together (rather than defaulting a bare `--kind` to some
placeholder title, or vice versa) follows the same reasoning `ClaimBody::
Subject`'s own shape already forces: both fields are non-optional, so a
partial value has no honest claim to write.
**Consequences:** `NarrativeResult`'s introduction is additive, not a
redesign — `AppendResult` is untouched and still used everywhere a single
claim is written (`same`/`relate`/`retract`/`reject`/`mark`).
`PairedAppendResult` gaining a field is source-compatible with every
existing read of `.narrative`/`.status`. `src/mcp.rs`'s existing
`observe`/`plan`/`decide`/`resolve`/`block` tool implementations now pass
`None, None` for the two new params at their `actions::` call sites —
real MCP `title`/`kind` params are REQ-12, scoped to the verb-lexicon-reorg
PR, not this one. New tests: `tests/cli.rs` gained
`observe_title_and_kind_writes_a_subject_claim` (AC-7 success),
`observe_title_without_kind_errors`/`observe_kind_without_title_errors`
(AC-7 error half, both directions),
`issues_excludes_a_subject_with_no_status_and_no_declared_issue_kind`
(AC-8, the exact `spine`-shaped regression case), and
`issues_lists_a_subject_declared_as_issue_kind_before_any_status_claim`
(AC-9).

## ADR-31 — `--status` generalizes `resolve`/`block`'s narrative+status pairing to `observe`/`plan`/`decide`
**Date:** 2026-07-19
**Decision:** `kan observe`/`kan plan`/`kan decide` gain an optional
`--status <value>` flag (REQ-9, `.design/v0.3-milestone.md`). When given, it
writes a `ClaimBody::Status { value }` claim citing the narrative claim —
the exact pairing mechanism `resolve`/`block` already hardcode
(`Resolution`→`Resolved`, `Blocker`→`Blocked`), generalized to any
narrative kind and any `StatusValue` instead of two special cases.
`kan resolve`/`kan block` are unchanged — their fixed pairing stays
hardcoded, since that pairing is inherent to what those two kinds *mean*,
not a special case needing generalization; adding `--status` to them too
would let a caller write a contradictory pair in one call (e.g. `resolve`
citing `Status{Blocked}`), which the fixed pairing structurally prevents.
`actions::NarrativeResult` (introduced in ADR-30 for the `Subject` claim)
gains a second independent optional field, `status: Option<AppendResult>`,
alongside the existing `subject` one — `--status` and `--title`/`--kind`
compose freely in one call (a single `kan plan` can write up to three
claims: narrative, status, subject), each validated/written independently.
**Why:** Before this, only `resolve`/`block` could pair a narrative claim
with a status change in one call; `observe`/`plan`/`decide` needed a
separate `kan mark` call to do the same. Some previously-impossible-in-one-
call combinations (e.g. `Decision` + `Status{Closed}`, or `Observation` +
`Status{Resolved}` when `resolve`'s specific `Resolution` framing doesn't
fit what actually happened) had no path without adding a new verb per
combination. Generalizing the existing pairing mechanism instead of adding
verbs keeps the verb count fixed while closing the gap.
**Consequences:** `narrative()` (the shared helper `observe`/`plan`/`decide`
funnel through) now writes up to three claims in sequence — narrative,
then status (if given, citing the narrative CID), then subject (if given)
— via a new `maybe_status_claim` helper mirroring `maybe_subject_claim`'s
shape. `src/mcp.rs`'s `observe`/`plan`/`decide` tool implementations pass
an extra `None` for the new `status` param — real MCP `status` params are
REQ-12, scoped to the verb-lexicon-reorg PR. New tests in `tests/cli.rs`:
`observe_status_pairs_a_status_claim_citing_the_narrative` (AC-6) and
`plan_status_and_title_kind_together_write_three_claims` (composing REQ-9
and REQ-7 in one call).

## ADR-32 — Verb lexicon reorganized by AX phase; MCP tool surface catches up to the full CLI
**Date:** 2026-07-19
**Decision:** Three changes closing out `.design/v0.3-milestone.md`
REQ-10..12:
1. `cli::Command`'s variants are reordered into four declared groups —
   Recording (`observe`/`plan`/`decide`/`block`/`resolve`), Structuring
   (`same`/`relate`/`mark`), Correcting (`retract`/`reject`), Recalling
   (`show`/`status`/`issues`/`context`) — with `mcp` staying outside the
   four phases (setup/tooling) at the end. Since clap prints subcommands in
   declaration order, `kan --help` now teaches the phase structure for
   free, with zero runtime cost — confirmed by inspecting the actual
   `--help` output, not just re-ordering and assuming.
2. `mcp::KanServer::get_info()`'s instructions are rewritten around the
   same four phases, replacing the previous flat kind-by-kind description.
   Still passes `tests/mcp_server.rs`'s existing sequencing-language guard
   (no "first"/"then"/"before starting") — confirmed by running that exact
   test, not just avoiding the words by inspection.
3. The MCP tool surface catches up to the full CLI: new `relate`/`reject`
   tools; `NarrativeParams` (`observe`/`plan`/`decide`) gains `status`/
   `title`/`kind`; `ResolveParams`/`BlockParams` gain `title`/`kind` (no
   `status` — REQ-9 excludes those two the same way the CLI does).
   `claim::SubjectKind` gains a direct `schemars::JsonSchema` derive (same
   rationale ADR-21 already used for `claim::StatusValue`: MCP params use
   the core type directly, since `schemars` — unlike `clap` — doesn't carry
   the "keep `claim.rs` CLI-free" concern). `relate`'s `kind` param uses a
   new MCP-local `RelateKindParam` enum (Blocks/About/ManifestsAt/
   DependsOn/Accepts, no `SameAs`) rather than `claim::RelationKind`
   directly — the MCP-side counterpart to `cli::RelationKindArg`, enforcing
   REQ-2's "`same` is the only way to write `SameAs`" at the
   deserialization boundary instead of a runtime check inside
   `actions::relate` (which still does no `kind` re-validation itself, on
   either surface).
**Why:** A flat alphabetical/kind-order tool list teaches nothing about
workflow; grouping by the four AX phases (Recording, Structuring,
Correcting, Recalling) lets the verb list itself communicate intended use
without `get_info()` having to prescribe an order (which the sequencing-
language guard test exists specifically to prevent, per `docs/DECISIONS.md`'s
kan/companion-tool boundary rule — affordance, not enforcement). The MCP
surface lagging the CLI by two PRs (`relate`/`reject`/`status`/`title`/
`kind` all landed CLI-first, MCP passing `None` as placeholders) was a
deliberate, tracked debt from ADR-29/30/31, not an oversight; this PR pays
it off in one pass rather than mirroring each earlier PR twice.
**Consequences:** `tests/mcp_server.rs` gained `ac12_mcp_tool_surface_
mirrors_the_cli`, spawning a real `kan mcp` subprocess and inspecting
`tools/list`'s JSON schemas directly (not just presence of the tool names)
for `status`/`title`/`kind` on the right tools, `status`'s *absence* on
`block`/`resolve`, and confirming `relate`'s `kind` schema has no
`SameAs`/`same_as` variant. The existing tool-name assertion list in
`ac8_lists_tools_and_calls_the_observe_tool` grew to include `block`/
`relate`/`mark`/`retract`/`reject` alongside the previously-checked subset.

## ADR-33 — `GitAncestry::relations` caches `is_ancestor` per directed commit pair, within one call
**Date:** 2026-07-19
**Decision:** `relations::GitAncestry::relations` (REQ-13, issue #27,
`.design/v0.3-milestone.md`) now caches each `GitSubstrate::is_ancestor`
result in a `HashMap<(Sha, Sha), bool>` local to the call, keyed on the
exact directed `(ancestor, descendant)` pair queried. A claim count of `n`
over `k` distinct commits now needs at most `k²` real `git` subprocess
invocations instead of up to `n²` — the gap matters once multiple claims
share a commit, which v0.2 made the common case by auto-attaching `HEAD`
to every write (ADR-22). Numbered ADR-33 (continuing after ADR-32, not
ADR-29) to preserve the intended merge order even though this PR branched
directly off `main` rather than stacking on the other four v0.3 PRs — it
touches only `src/relations.rs` and `tests/`, with zero file overlap, so
it doesn't need their code to exist first.
**Why:** `GitAncestry`'s own doc comment already named this as "the
obvious first optimization" back when the cost was still theoretical
(nothing populated real artifacts yet). REQ-8/REQ-9 of
`.design/v0.2-milestone.md` closed that gap by making every write verb
auto-attach the current `HEAD` commit, so real fold-time classification
(`actions::status`/`actions::issues`, both calling `relations::
compute_default` once per merge-class) now redundantly re-derives the same
`is_ancestor` fact whenever a class has several claims anchored to a
shared commit — routine, not a pathological case. Correctness before
performance stays the house rule (`CLAUDE.md`): this is a pure
memoization of an already-correct pairwise computation, not a new
algorithm, so it can't change which edges get produced.
**Consequences:** New `tests/git_ancestry_cache.rs`
(`is_ancestor_is_not_re_invoked_for_a_pair_already_resolved`) — a
call-count-instrumented test double: a fake `git` placed ahead of the real
one on `PATH`, logging every invocation to a file, verifying real `git
merge-base --is-ancestor` subprocess calls drop from up to 16 (over 8
claims sharing 2 commits, uncached — confirmed by reverting the cache and
re-running, which fails at 24 total git calls) to exactly 2 (cached).
Deliberately the only test in its file/binary, since it mutates the
process-wide `PATH` for the duration of the test — a mutation that would
race any other test in the same process also shelling out to `git`.
`std::env::set_var` needed an `unsafe` block under the current stable
toolchain's edition rules; safe here specifically because of that
single-test isolation (documented inline). `GitAncestry`'s own doc comment
is updated to describe the cache instead of naming it as a future
revisit.

## ADR-34 — Third release: v0.3.0-beta.1
**Date:** 2026-07-20
**Decision:** `Cargo.toml`'s version bumps `0.2.0-beta.1` → `0.3.0-beta.1` —
a minor bump (new backward-compatible functionality: the relation surface
and `Rejects` reshape, `Subject`/`SubjectKind` construction plus the
`issues` correctness fix, `--status` generalization, the four-phase verb
reorg, and `GitAncestry` caching — PRs #42–#46), staying a semver
pre-release rather than promoting to stable `0.3.0`, same reasoning as
ADR-28. Follows the same branch → PR → merge → tag workflow as the prior
two releases (ADR-19, ADR-28's PR #40).
**Why beta again, not stable:** confirmed (not assumed) data compatibility
with `v0.2.0-beta.1`: `RelationKind` losing its unused `Rejects` variant and
`ClaimBody`/`ClaimKind` gaining a new `Rejects` variant are both safe for
existing logs — `serde`'s default derive (no `#[serde(tag = ...)]` or
custom impl on any of these three enums) uses externally-tagged-by-name
representation, not ordinal-index, so removing/adding a variant doesn't
shift any other variant's encoding; and ADR-29 already confirmed (via `git
log -S 'RelationKind::Rejects'`, re-confirmed by this release's own
independent audit) that no shipped CLI/MCP path ever constructed the
now-removed variant, so no real log references it. The project itself
still isn't stable, though: issue #30 (real per-agent cryptographic
identity, deliberately kept out of v0.3's scope per
`.design/v0.3-milestone.md`'s Out of Scope section) remains open, and
`docs/SPEC.md`'s v1 scope fence still isn't fully closed. A pre-release
version keeps signaling that honestly.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging (61 files, 551.7KiB) before tagging. This release also follows an
independent adversarial post-implementation audit of the full v0.3 diff
(method adapted from `forecast-bio/crosslink`'s `architect` skill, dispatched
as a fresh subagent per issue #48) — verdict APPROVE, all 13 REQs/13 ACs
independently re-verified against code rather than trusting the ADRs' own
claims, full build/test/clippy/fmt gate re-run clean. That audit is a
one-off technique this release, not yet a repeatable skill in this repo
(tracked as future companion-tool work, issue #48).

## ADR-35 — Sync layer staging plan, and a version roadmap through 1.0
**Date:** 2026-07-20
**Decision:** `.design/sync-layer-architecture-and-staging.md` replaces
issue #29's placeholder epic with a concrete milestone sequence, now mapped
onto actual versions:
- **v0.4.0-beta.1**: unrelated small cleanup kept as its own release, not
  folded into the sync epic — #41 (`ClaimBody::Result` reachability), #26
  (`Workspace::open` full-rescan perf), and a subject-naming fuzzy-match
  nudge (validated by real beta-tester feedback, issue #47).
- **v0.5.0-beta.1**: Milestone 0 — formalize `docs/SPEC.md` §10's
  `Transport` trait, `LocalOnly` as its explicit first implementation.
  Pure additive refactor.
- *(no version)*: Milestone 1 — issue #7's E2EE `/design` pass. Design-only
  output (a `.design/*.md` doc), feeds Milestone 3's implementation
  directly rather than shipping its own release.
- **v0.6.0-beta.1**: Milestone 2 — issue #30, real per-agent cryptographic
  identity. Deliberately shipped *before* `HostedRelay`, as an independent
  parallel track — see the design doc's own sequencing rationale (the
  cross-human trust story is already cryptographically real via `did:key`/
  ADR-4; per-agent sub-identity matters more once multiple agents share a
  network-exposed relay).
- **v0.7.0-beta.1**: Milestone 3 — `HostedRelay` design + build, informed
  by Milestone 1's E2EE resolution. `Transport` gets wired into
  `Workspace` for the first time here (deliberately deferred from
  Milestone 0).
- **v1.0.0**: a stability declaration, not new scope — local-only spine +
  `HostedRelay` + real identity + E2EE, with nothing left provisional (no
  more `KAN_AGENT`-style honest-but-temporary patches, no more mid-flight
  `ClaimBody`/`RelationKind` reshapes expected). Declared once that line
  is genuinely stable, not tied to a calendar date.
- **v1.x/v2**: Milestone 4 — `AtProto`/PDS/firehose transport. Deliberately
  *not* a 1.0 blocker.
**Why AtProto stays post-1.0:** `docs/SPEC.md` §10 frames the three
transports asymmetrically — `HostedRelay` is "private teams... **the
monetizable one**," `AtProto` is "public ecosystem; lexicons =
**evangelism**." `docs/HANDOFF.md` already calls the local-only spine "the
actual product." Reading those together: 1.0 is reasonably declared once
the core product (local-only + private-team sync, both hardened, real
identity, real encryption) is stable — the public-ecosystem/federation
story is expansion on a stable base, not a precondition for calling the
base stable. Requiring the entire original vision (including `AtProto`'s
external wire-protocol surface, confirmed during the sync design pass to
be entirely unbuilt — `atproto-repo`/`atproto-dasl` provide MST/CAR/CBOR
repository structure only, no PDS/XRPC/firehose client exists anywhere in
kan's dependency tree) before 1.0 would tie the stability declaration to
the single largest, least-derisked remaining piece of work, for no
product reason tied to what "stable" actually needs to mean here.
**Consequences:** `.design/sync-layer-architecture-and-staging.md`'s
staging table updated with this version mapping, so the design doc and
this ADR stay in sync as the single source of truth rather than the
roadmap living only in chat. Issue #29 gets a comment recording the
resolved plan, replacing its own "not a commitment, just what was
originally sketched" framing. v0.4 development starts next, via its own
`/design` pass.

## ADR-36 — `kan result`: closing issue #41's reachability gap, and sharpening `observe`/`result`/`resolve`'s verbiage
**Date:** 2026-07-20
**Decision:** `ClaimBody::Result`/`ClaimKind::Result` (already present in
`src/claim.rs`, already fully handled by `src/context.rs`, never
constructed by any CLI/MCP path) gets a new `kan result <subject> <text>
[--cites] [--file] [--status] [--title] [--kind] [--verbose]` verb —
`.design/v0.4-milestone.md` REQ-1..3. Zero data-model change: this is
purely a new write path, the same "zero-cost, not a migration" shape
ADR-29's `Rejects` reshape had. `subject` is a required positional
argument (matching `resolve`/`block`, not `observe`/`plan`/`decide`'s
`--subject` defaulting to `"general"`) — a result is almost always about
the specific subject the action targeted. Implemented by reusing the
existing `narrative()` helper directly (passing `Some(subject)` so it
never falls through to the `"general"` default), which gives `result` the
same *optional* `--status`/`--title`/`--kind` pairing `observe`/`plan`/
`decide` already have (REQ-9/REQ-7, v0.3) — a natural extension beyond the
design doc's literal minimum text, decided at implementation time: "no
automatic Status pairing" (the design doc's phrasing) means no
*hardcoded* pairing the way `resolve`/`block` have, not that `--status`
shouldn't be offered opt-in like its sibling narrative verbs.

`observe`'s, `result`'s, and `resolve`'s doc comments, CLI help text, and
MCP tool descriptions are all sharpened to state each verb's trigger
condition explicitly (`observe`: "something you noticed... not something
you did"; `result`: "the outcome of an action you just took"; `resolve`:
"...an outcome that also closes the subject out") — REQ-2. `mcp::
get_info()`'s Recording-phase description gains the same three-way
distinction.
**Why:** The issue's own text posed a real, undecided question — keep
`Result` with a dedicated verb, or remove the variant as redundant with
`Observation`. Resolved: keep it, since the distinction (passive finding
vs. outcome of an action taken, vs. outcome that also closes a subject) is
real, mirroring how `Resolution` already differs from `Observation`. But
adding a fourth narrative-adjacent verb narrows the semantic gap an LLM
caller has to navigate — the sharpened, trigger-condition-based wording
exists specifically to keep that gap legible as the verb count grows,
rather than trusting an agent to infer the distinction from claim-kind
names alone.
**Consequences:** New tests in `tests/cli.rs`
(`result_writes_a_result_claim_with_no_status_pairing`,
`result_status_pairs_a_status_claim`,
`help_text_distinguishes_observe_result_resolve`) and `tests/
mcp_server.rs` (the tool-name assertion list grew to include `result`).
`#[allow(clippy::too_many_arguments)]` needed on `result()`, matching the
same pattern already present on `observe`/`plan`/`decide`/`resolve` since
v0.3 (ADR-34's independent adversarial audit already flagged this as a
minor future-cleanup candidate — a params struct would read better — not
a defect; unchanged here, consistent with the existing siblings rather
than fixed in isolation).
