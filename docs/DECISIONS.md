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
- **v0.7.0-beta.1**: *(superseded — see ADR-48)* the **correctness
  release**. Not on this roadmap when it was written, because the defects
  it fixes were not known: three adversarial reviews of v0.6.0-beta.1 found
  ~20, about half destroying data. Everything below shifts one place.
- **v0.8.0-beta.1**: Milestone 2 — thread `Transport` through `Workspace`
  so a published tree is actually *read*, plus the `PeerContested` trust
  surface that makes another actor's claims visible at all. This is what
  makes kan genuinely multi-actor rather than merely capable of it.
- **v0.9.0-beta.1**: Milestone 3 — issue #30, real per-agent cryptographic
  identity. Deliberately shipped *before* `HostedRelay`, as an independent
  parallel track (the cross-human trust story is already cryptographically
  real via `did:key`/ADR-4; per-agent sub-identity matters more once
  multiple agents share a network-exposed relay). `KAN_AGENT` is not a
  prerequisite here — ADR-48 removed it rather than repairing something
  already scheduled for replacement.
- **v0.10.0-beta.1**: Milestone 4 — `HostedRelay` design + build, informed
  by Milestone 1's E2EE resolution.
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

## ADR-37 — `Workspace::open`'s staleness check: skip the rebuild only when content-addressing proves it's safe
**Date:** 2026-07-20
**Decision:** `Workspace::open` (`.design/v0.4-milestone.md` REQ-4..5,
issue #26) skips `Log::iter_all` + `Index::rebuild` when the log's current
root CID (`Log::current_root`, a new accessor — already resident in
memory from `open_or_create`, zero extra I/O) matches what the index was
last built from (`Index::built_from_root`, backed by a new `meta` table).
`Index::rebuild`'s signature grows a `built_from_root: Option<&Cid>`
parameter, written inside the same transaction as the claims themselves —
meta and claims always commit atomically together, so a crash mid-rebuild
can never leave a half-updated claims table read back as "fresh." Any
mismatch (including a fresh or just-deleted-and-recreated index, which has
no `meta` row yet — `None != Some(root)`) falls back to exactly the prior
unconditional full rebuild. Numbered ADR-37 (continuing after ADR-36, not
ADR-35) to preserve the intended merge order even though this PR branched
directly off `main` rather than stacking on PR1 (`kan result`) — the two
touch disjoint files (`src/store/`, `src/workspace.rs` vs. `src/actions.rs`,
`src/cli/mod.rs`, `src/mcp.rs`), so neither needs the other's code to
exist first.
**Why:** `Workspace::open`'s own doc comment already named this exact
deferral ("incremental indexing is a later optimization once fixtures
exist to guard it"). Content-addressing makes the check exact rather than
heuristic: an equal root CID doesn't mean "probably unchanged," it means
the log genuinely has not changed a single bit, so skipping is provably
safe, not a staleness gamble. Deliberately *not* true incremental indexing
(appending only new claims into the existing index rows) — that's a
larger, riskier change (partial-update logic that could itself drift out
of sync) staying deferred; this ships only the skip-or-full-rebuild shape,
which can never produce a partially-updated index.
**Consequences:** `Index::rebuild`'s signature change touches every call
site, including three in `tests/index_and_fold.rs`/`tests/
write_surface.rs` that construct a `Workspace` by hand — all updated to
pass `log.current_root().as_ref()`. New `tests/workspace_staleness.rs`
proves the skip *actually happens* (not just that the code compiles)
via a black-box technique needing zero instrumentation in production
code: `Index::all_stored_claims` (what every read verb consumes) never
re-verifies against the log, so directly tampering with the index's
stored bytes and observing whether a subsequent `Workspace::open` leaves
the tampering in place (skip) or overwrites it with the log's true
content (full rebuild, triggered by an intervening write) is a direct
proof of which path ran — confirmed to actually discriminate by
temporarily reverting the skip logic and watching the test fail exactly
where expected, then restoring it.

## ADR-38 — Subject-naming similarity nudge: normalized exact match, not edit-distance
**Date:** 2026-07-20
**Decision:** `actions::warn_similar_subjects` (issue #47,
`.design/v0.4-milestone.md` REQ-6..8) checks a write verb's target subject
name(s) against every existing live subject's exact literal spelling,
using a cheap case/separator-normalized key (`-`/`_`/whitespace stripped,
case folded — `normalize_subject_name`) — not edit-distance/typo-tolerant
matching. A normalized match against a *different* literal spelling
produces a warning line naming both spellings; computed from the
pre-write state and surfaced without ever blocking the write (CLI:
stderr; MCP: appended to the confirmation text, since MCP has no side
channel separate from its own tool response). Fires on all 9
subject-taking write verbs: the 5 Recording verbs (`observe`/`plan`/
`decide`/`block`/`resolve`), `result` (REQ-1, PR1/ADR-36), and the 3
Structuring verbs (`same`/`relate`/`mark`) — both the `a` and `b`
positions for `same`/`relate`. `observe`/`plan`/`decide` only check when
the caller explicitly supplied `--subject`; defaulting to `"general"`
isn't something the caller typed, so it can't be a naming-variant typo.

**Correction to `.design/v0.4-milestone.md`'s REQ-7**: that requirement's
text names "all 8 subject-taking write verbs," listing 5 Recording + 3
Structuring — omitting `result`, even though `result` (a *positional*-
subject verb, the same shape as `resolve`/`block`) was defined by REQ-1 in
the exact same design doc. Caught and fixed at implementation time: 9
verbs, not 8, `result` included — treated as ordinary engineering
correction (`.design/v0.3-milestone.md`'s own precedent: "implementation-
time details... are ordinary engineering, not open design questions"),
not a scope change needing a fresh design pass.
**Why normalization, not edit-distance:** the one concrete failure mode
reported (#47 — `f1-c1`/`F1-C1`/`f1_c1`, a real beta-tester hitting exactly
this) is caught 100% by normalization alone, with zero new dependencies
(no crate-trust-spike question, matching v0.2/v0.3's zero-new-deps
precedent — confirmed via an empty `Cargo.toml`/`Cargo.lock` diff for this
whole PR). Edit-distance adds a real false-positive risk a nudge feature
can't afford: too loose a threshold and genuinely-different short subject
names (`f1-c1`/`f1-c2`) start warning against each other, which trains an
agent to ignore the nudge entirely. Deferred until real usage shows
normalization alone isn't catching enough, not guessed at now.
**Consequences:** New tests in `tests/cli.rs`
(`naming_nudge_warns_on_a_case_separator_variant`,
`naming_nudge_is_silent_for_a_genuinely_different_subject`,
`naming_nudge_fires_on_structuring_verbs`, `naming_nudge_fires_on_result`)
and `tests/mcp_server.rs`
(`naming_nudge_appends_a_warning_to_the_confirmation_text`). The
computation lives once in `actions::warn_similar_subjects`, called
explicitly from each CLI/MCP write call site (via small `subject_warnings`
helpers in `cli/mod.rs` and `mcp.rs`) rather than folded into `append()`
itself — `same`/`relate` need to check two candidate names against one
shared fold view, which a single-subject helper inside the shared
`append()` path can't express without complicating every other caller
that only ever has one subject.

## ADR-39 — Fourth release: v0.4.0-beta.1
**Date:** 2026-07-20
**Decision:** `Cargo.toml`'s version bumps `0.3.0-beta.1` → `0.4.0-beta.1`
— a minor bump (new backward-compatible functionality: `kan result`,
`Workspace::open`'s index staleness check, the subject-naming nudge —
PRs #51–#53), staying a semver pre-release rather than promoting to
stable `0.4.0`, same reasoning as ADR-28/ADR-34. Follows the same branch →
PR → merge → tag workflow as the prior three releases.
**Why beta again, not stable:** confirmed (not assumed) data compatibility
with `v0.3.0-beta.1`: `src/claim.rs` has zero diff across this whole
milestone (`kan result` uses `ClaimBody::Result`, already present since
before v0.1's first release) — no claim-log/CAR format change at all.
`store::index::Index`'s SQLite schema gained a `meta` table, but the index
is explicitly a disposable projection, never a second source of truth
(`docs/SPEC.md` §10) — `CREATE TABLE IF NOT EXISTS` means an existing
`v0.3` `index.sqlite` file opens cleanly under `v0.4` code with no
migration, and even in the worst case (a mismatch on the very first
post-upgrade `Workspace::open`) the fallback is just one ordinary full
rebuild, exactly what every `Workspace::open` unconditionally did before
this release. The project itself still isn't stable: issue #30 (real
per-agent identity) remains open, and now issue #29's staged sync epic
(`.design/sync-layer-architecture-and-staging.md`, ADR-35) is the
explicit, versioned path to whatever "stable" ends up meaning for kan —
v1.0.0 is anchored to that plan (through Milestone 3 / v0.7.0-beta.1) now,
not left as a vague someday.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging (64 files, 615.0KiB) before tagging. Issues #41/#26/#47 closed
with comments pointing at the merging PRs, matching the v0.2/v0.3 pattern
— #47 in particular gets a direct reply to the original beta-tester
feedback, including an explicit note that the structured-data point
raised there is a real, unresolved, bigger question deliberately not
addressed by this release.

## ADR-40 — Transport trait matches Log::append's real shape, not SPEC.md §10's pseudocode
**Date:** 2026-07-20
**Decision:** `src/transport.rs`'s `trait Transport` (`.design/v0.5-milestone.md`,
sync staging Milestone 0) adapts `docs/SPEC.md` §10's illustrative `fn
publish(&self, &[Claim]); fn subscribe(&self, &[Did]) -> Stream<Claim>;`
sketch into four concrete choices, each checked against real code rather
than guessed: (1) `publish(&mut self, content: ClaimContent, identity:
&Identity) -> Result<Cid, Error>` matches `Log::append`'s real single-claim,
unsigned-content-in shape exactly, not SPEC's batch-of-pre-signed-`Claim`s;
(2) `subscribe` returns a real `tokio-stream`-backed `ClaimStream`
(`Pin<Box<dyn Stream<Item = Result<Claim, Error>> + Send>>`), a new minimal
dependency, rather than a plain `Vec<Claim>`; (3) the stream item is the
signed `Claim`, not `store::log::StoredClaim` — `rev` is log-internal
ordering that doesn't belong across the transport boundary; (4)
`Transport::Error` is its own enum (`#[error(...)] Log(#[from]
store::log::Error)`), decoupled from `LocalOnly`'s specific backing store so
`HostedRelay`'s future error variants have somewhere to live without
`store::log::Error` growing transport-shaped variants. `LocalOnly` wraps
`store::log::Log` 1:1: `publish` delegates directly to `Log::append`;
`subscribe` returns `tokio_stream::empty()` — the honest answer for a
single-author local log, not a stub.
**Why match `Log::append` instead of SPEC's sketch:** `docs/SPEC.md` §10's
pseudocode was always illustrative, and `Log::append` is the only thing
`LocalOnly` — the transport this milestone actually has to implement —
wraps. Inventing batching or pre-signed-`Claim` input to match the sketch
literally would give `LocalOnly` a shape it can't honestly implement without
new `Log` surface nothing in this milestone's requirements asks for.
**Consequences:** New dependency `tokio-stream = "0.1"` (thin wrapper around
the same `futures-core::Stream` trait; already adjacent to kan's tokio async
runtime, `Cargo.toml`'s existing `rt-multi-thread` feature). Zero change to
`Workspace`/CLI/MCP — `Transport` is additive, wiring deferred to
`HostedRelay`'s own `/design` pass (Milestone 3 in
`.design/sync-layer-architecture-and-staging.md`). New tests
`tests/transport.rs::local_only_publish_matches_log_append_directly` (a
CID-equivalence proof against direct `Log::append` usage) and
`::local_only_subscribe_is_honestly_empty`. The trait signature is
explicitly not meant to be final — `HostedRelay`'s design pass may need to
widen it once a second real implementation exists to design the wiring
against.

## ADR-41 — Fifth release: v0.5.0-beta.1
**Date:** 2026-07-20
**Decision:** `Cargo.toml`'s version bumps `0.4.0-beta.1` → `0.5.0-beta.1` —
a minor bump (new backward-compatible functionality: `src/transport.rs`'s
`Transport` trait + `LocalOnly`, PR #56, ADR-40), staying a semver
pre-release rather than promoting to stable `0.5.0`, same reasoning as
ADR-28/34/39. Follows the same branch → PR → merge → tag workflow as the
prior four releases.
**Why beta again, not stable:** this milestone touches nothing about the
on-disk claim log or index format — `Transport`/`LocalOnly` is a new,
additive seam in front of the already-shipped `Log::append`/`iter_all`, not
a change to `src/claim.rs`, the CAR/MST format, or `store::index::Index`'s
schema, so a `v0.4.0-beta.1` `.kan/` directory opens cleanly under `v0.5`
code with zero migration. The project itself still isn't stable: issue #30
(real per-agent identity, staged as Milestone 2 in
`.design/sync-layer-architecture-and-staging.md`) remains open, and this
release only closes Milestone 0 of ADR-35's sync roadmap — Milestones 1
(E2EE design, issue #7), 2 (identity, v0.6.0-beta.1), and 3 (`HostedRelay`,
v0.7.0-beta.1) remain before v1.0.0 is anchored.
**Consequences:** `cargo publish --dry-run --allow-dirty` confirmed clean
packaging before tagging.

## ADR-42 — The companion tool exists: `kan-tools/day`
**Date:** 2026-07-21
**Context:** ADR-18 drew the kan/companion-tool boundary rule and named a
"future, separate companion tool" to receive everything that fails it —
session orchestration, interactive design authoring, code-review
orchestration. It deliberately did not build one (issue #24 tracked the
scaffolding, issue #48 the adversarial-review skill). Both are now closed:
the tool exists, is published, and this ADR records what that settles so
`CLAUDE.md`'s scope section and ADR-18's "if and when it's built" hedge
stop being the only account of it.
**Decision:** the companion tool is **`day`** (`kan-tools/day`, published to
crates.io, v0.1.2-beta.1 at time of writing). Named for Brian Day (Sydney
school): Day convolution is built from Kan extensions/coends and is what
gives profunctor composition its monoidal structure, so the lineage sits
directly next to Kan's — three letters beside `kan`, and `day plan`/`day
review` read as the daily practice of development. It is a Rust CLI
(`init`/`doctor`/`hook`/`mcp`) packaged as a Claude Code plugin, whose
primary dev-flow integration is harness-level hooks.
**What it proves about ADR-18's rule:** the boundary held under a real
implementation, which is the only test that counts. day needed **no new
`ClaimBody`/`ClaimKind`/`Anchor`/`RelationKind` variant**. Its entire
schema is a set of subject-naming conventions over kan's existing verbs:
teloi on `telos/<slug>` subjects, process atoms on `atom/<slug>` subjects
carrying a fenced `day-atom` JSON interface block, assessments as
`observe`/`result` claims citing evidence CIDs. day keeps no store of its
own, and talks to kan by **shelling out to the `kan` binary** rather than
linking it as a library — so the boundary is enforced as the same public
CLI contract any other consumer gets, not as a convention day could quietly
erode. ADR-18's narrow-exception carve-out (kan may describe its own
interface) is unaffected.
**Migrations completed:** `.claude/commands/design.md` — flagged as tech
debt by ADR-18 — is now also shipped by day as its "generative closed-loop
design" atom. Issue #48's adversarial-review skill was built there rather
than here, as that issue anticipated. kan's copy of `design.md` stays for
now, since day's repo is private and therefore not `/plugin install`-able
by anyone else yet; its banner now points at day instead of at a
hypothetical future tool, and a real bug in it was fixed in passing (it
instructed agents to pass file paths to `--cites`, which takes claim CIDs
and errors on a path — found live while recording this very work into kan).
Full retirement in favour of a pointer is deliberately deferred until the
plugin path actually works for a third party.
**What this puts back on kan:** two things surfaced from the other side of
the boundary. (1) `RelationKind` has no edge for "in tension with", so
tension between teloi — the central relation in day's model, and what makes
teloi more than a values list — is unqueryable prose. That needs a new
`RelationKind` variant, which by ADR-18's own rule is **kan's** to own, not
day's to work around; it blocks day's v0.5 frames work. (2) day's v0.2 will
write through kan's public CLI (`kan decide`/`observe`/`result`), making
kan's write-verb ergonomics and error messages a dependency of a *program*,
not only of agents.
**Consequences:** `CLAUDE.md`'s "Scope boundary: kan vs. a future companion
tool" section is updated to name day and drop the future tense — living
documentation, same practice ADR-18 used when it superseded ADR-7's
vocabulary line. ADR-18's own historical text is left as-is.

## ADR-43 — `GitTree`: the committed tree as a sharing layer, not a rendering
**Date:** 2026-07-21
**Context:** A request to make teloi and other defining claims visible
*inside* the code they are about — readable in `git diff`, reviewable in a
PR, readable without kan installed. The obvious framing was "render a claim
to Markdown". That framing is wrong, and its wrongness is the whole ADR.
**Decision:** publishing a claim into the committed git tree is **moving it
to another sharing layer** — the same category of act as publishing to a
`HostedRelay` or an atproto PDS, with git as the substrate instead of a
server. So it is a `Transport` implementation (`src/transport/git_tree.rs`),
not a render step. `docs/SPEC.md` §10's "local-only and atproto-ready are
the SAME on-disk artifact" extends to git cleanly: the claim in the tree is
byte-identical in identity to the one in the log — same content, same CID,
same signature.
**Why the rendering framing fails:** a rendered file is a *second, unsigned
source of truth* sitting beside the signed one, with no answer to a tampered
file. A transport carries signed claims, so a file can be **verified rather
than trusted**: its content is re-hashed and compared to the CID it states,
and the signature is checked against the author's DID. Narrative text lives
in the Markdown body rather than the frontmatter precisely so that editing
the prose a human actually reads changes the CID and fails verification.
**One data-model change:** `ClaimBody::Publication { layer: Layer }`.
Publication is a decision *about* a subject, so it is a claim — attributable,
retractable, and itself publishable, so a clone can see who chose to share a
subject and why. Local configuration would have been unattributable, unsynced
state in a system where everything else is signed.
**Wire format, amended during implementation:** the design proposed plain
JSON of `ClaimContent` in the frontmatter. That does not work. `Cid`
serializes for DAG-CBOR, so through `serde_json` it becomes
`{"": [0, 1, 113, ...]}` — unreadable, and it does not deserialize back.
Annotating `Cid` fields to serialize as strings was the obvious fix and is
**unacceptable**: it would change how `ClaimContent` encodes to DAG-CBOR and
therefore change every CID kan has ever computed. So the frontmatter carries
the content as hex DAG-CBOR — encoded exactly as the log encodes it — with
derived, ignored-on-read legibility fields (author, subject, kind, cites)
beside it. Found by publishing a real subject: 9 of 12 records failed, and
only the 3 with no citations worked, because every unit-test fixture happened
to have no `cites` edge.
**Divergence is not drift:** claims are immutable and additive, so a git
merge keeping both sides is the *correct* resolution, and a conflict means
two actors wrote concurrently. `.gitattributes` ships `merge=union` so the
common case resolves automatically; the fold's existing contest stage handles
the semantics. **⚠ The `merge=union` half of this is withdrawn — see ADR-47.
It is line-based and destroys both sides' claims. The reasoning about claims
holds; the conclusion about files did not.** kan never rewrites history to
resolve a conflict, and **runs
no git commands at all** — it writes files and reads them; staging and
committing stay the user's.
**Extends ADR-3, does not contradict it:** `.kan/` remains gitignored in
full. `.claims/` is a separate tracked directory, because it is a sharing
layer rather than a store. The two never overlap.
**Sequencing:** slots into `.design/sync-layer-architecture-and-staging.md`
as M1.5, ahead of `HostedRelay` (M3). It is the second `Transport`
implementation M0 deliberately waited for before designing the `Workspace`
wiring, it exercises the multi-actor path with zero infrastructure, and
issue #7 (E2EE) does not gate it — a git remote already trusted with the
entire source tree is a different threat model from an untrusted relay.

## ADR-44 — Schema evolution: coexistence, not migration
**Date:** 2026-07-21
**Context:** ADR-43's `ClaimBody::Publication` variant made every older kan
unable to read this repo's log at all (`unknown variant Publication`). kan
had no stated compatibility contract, and the absence became visible the
moment a sharing layer existed — where the readers are other actors who
cannot simply be told to upgrade. The break then blocked the tooling used to
design the fix: `day design check` shells out to the installed `kan`, which
could no longer read the log it was being asked to validate against.
**Measurements (the justification, not assumptions):**
1. `content_cid` emits `d8 2a 58 25 00 01 …` — CBOR tag 42, byte string,
   multibase-identity prefix, CIDv1. kan's on-disk encoding is the
   IPLD/atproto standard and needs no correction. The unreadable
   `{"": [0, 1, 113, …]}` seen in ADR-43 was purely a `serde_json`
   projection artifact: serde's data model cannot express CBOR tags.
2. A field added as `Option<T>` with `skip_serializing_if` yields a
   **byte-identical CID** when absent. Additive evolution is possible.
3. A **new reader** reads an **old record** and verifies correctly. Backward
   compatibility is free.
4. An **old reader** given a **new record** fails two ways, and the
   difference is the whole point. A new *enum variant* is a hard decode
   error: loud and honest. A new *struct field* deserializes successfully,
   silently drops the field, and then fails CID verification — reporting a
   legitimate claim as **altered since it was signed**.
**Decision:** the contract is now `docs/SPEC.md` §7.1, authoritative.
`ClaimContent`'s existing fields are frozen forever; new fields are additive
and optional only; unknown claim kinds are **preserved as opaque
CID-verifiable claims** rather than rejected or dropped, and carry no status
or relational meaning into the fold; `ClaimContent` is `deny_unknown_fields`
so an out-of-date reader says "unknown field" instead of impugning the
record.
**Why coexistence rather than migration:** a CID is identity and the log is
append-only, so rewriting a claim produces a *different claim*. Republishing
old content under new shapes was considered and rejected — it creates two
CIDs for one fact, fragmenting exactly the identity the fold exists to
establish. A log-rewriting tool was rejected outright: history you can alter
is not what kan is.
**Consequences:** #66 (unknown-variant tolerance) is answered by the
preserve-as-opaque rule. #67 (a claim carries no time) becomes tractable —
it is the natural first *additive* field, and measurement 2 is what makes
adding it possible without invalidating history. The `Unknown` variant's
exact re-encoding is the delicate part of implementation: a preserved claim
that cannot re-encode cannot be verified, and would be worse than an honest
hard failure — flagged in `.design/schema-evolution.md`'s Architecture so it
is confronted early rather than discovered late.
**Supersedes:** nothing. Extends ADR-5 (`ClaimKind`+`Body` merge) with the
rules for changing that enum, and ADR-43, whose data-model change is what
exposed the gap.

## ADR-45 — Sixth release: v0.6.0-beta.1 (GitTree's publish half + the schema contract)
**Date:** 2026-07-21
**Decision:** `Cargo.toml` bumps `0.5.0-beta.1` → `0.6.0-beta.1` — a minor
bump for new backward-compatible functionality (`GitTree`, `kan publish`,
`ClaimBody::Publication`, the schema-evolution contract), staying a semver
pre-release for the same reasons as ADR-28/34/39/41.
**Scope, stated honestly:** this ships **half a transport**.
`GitTree::publish` works and `kan publish` writes a subject's claims into a
tracked `.claims/`. `GitTree::subscribe` exists, compiles, is tested — and
**nothing calls it**. `Workspace` does not know about `Transport` at all, so
a clone's kan will never read a published tree; the fold still sees only the
local log. A repo can therefore *share* claims and cannot yet *consume*
shared ones. Wiring `Transport` through `Workspace` is M2 (v0.7.0-beta.1) in
`.design/sync-layer-architecture-and-staging.md`, and is precisely what M0
deferred until a second implementation existed. Releasing without it is
deliberate, not an oversight, and the release notes say so — ADR-43's claim
that `GitTree` "exercises the multi-actor path" describes the design, not
what is currently wired.
**Why ship now rather than after the wiring:** the schema-evolution contract
(ADR-44) is a **prerequisite for two other issues being safe to land**. #60
(an "in tension with" `RelationKind`) and #67 (a claim's time) are both
schema changes, and until unknown-kind tolerance is released, either one
strands older readers exactly as `Publication` just did. The wiring is
additive and does not get harder by waiting; the contract does, because every
release without it is another version that can be stranded. Delivering the
originating request — claims visible and reviewable in the repo — needs only
the publish half.
**One thing this release cannot fix:** v0.5.0-beta.1 in the wild has no
unknown-kind tolerance, so it cannot read a log containing any claim kind it
does not know. That is unfixable retroactively; v0.6 is the release from
which forward compatibility *starts*. Anyone on v0.5 should upgrade before
being handed a v0.6-written log.
**Consequences:** the staging table's version map shifts — M1.5 is inserted
at v0.6, `Workspace` wiring becomes M2 at v0.7, per-agent identity (#30)
moves to v0.8 behind #69 (keychain friction, which #30 would multiply), and
`HostedRelay` to v0.9. `cargo publish --dry-run` confirmed clean packaging
before tagging.

## ADR-46 — `InTensionWith`: asserted directed, read as a projection
**Date:** 2026-07-21
**Context:** Tension between subjects is the central relation in `day`'s
telos model — several teloi normally apply to one project at once and pull
against each other, and that tension is information rather than a defect.
It had no representation: day recorded it as a `decide` claim citing both
subjects, which is attributable but not queryable (#60).
**Decision:** a sixth domain `RelationKind`, `InTensionWith`, **asserted
directed and read symmetric**. Tension is symmetric in *meaning* — if A
pulls against B then B pulls against A — while the *grounds* are
perspectival, because two actors can hold the same pair in tension for
different reasons. So the assertion keeps its direction in the store and
symmetry is applied on read (`fold::relations::in_tension_with`). Collapsing
at write time would discard which side observed what, which is exactly the
raw data a frames-aware reader needs.
**No degree field and no reason field**, both deliberately. The reason is
the claim the edge `cites` — `cites` is already the witness layer on every
claim, and a `reason` field would duplicate it while making one
`RelationKind` structurally unlike the other five. A degree, once anything
needs one, is *derived* by composing over those witnesses under a chosen
enriching base, exactly as §4.3 derives identity confidence. A stored degree
would assert a fold output as input and foreclose every other base — the
same category error as writing a status instead of letting the fold compute
one.
**The general rule, now stated:** `docs/SPEC.md` §4.5.1 — relation claims
are stored exactly as asserted and any symmetric, transitive, or weighted
reading is a projection computed on demand. `telos/raw-data-and-projections`
in this repo's own log (published to `.claims/`) states the principle
generally: raw attested data retained in full, every simplification a
determined projection parameterised by a viewer-chosen base, and therefore
swappable.
**What it surfaced (#72):** §4.3 already specifies identity as an enriched,
witness-retaining object with trust as the enriching base — and the other
five relation kinds get bare booleans. That asymmetry is the anomaly.
Enriched domain relations are therefore not an architectural shift but the
**completion of a pattern the spec already commits to**. Deferred because
nothing consumes domain edges today (the fold reads `SameAs` and `Status`
only), and day's frames work is the likely first real consumer — the
witnesses are already being recorded, so enrichment can be added over them
later without re-recording anything.

## ADR-47 — Withdraw the `merge=union` guidance: it destroys both sides

**Date:** 2026-07-21
**Status:** Accepted — supersedes the `merge=union` half of ADR-43
**Context:** An adversarial review of the shipped v0.6.0-beta.1 GitTree
transport tested ADR-43's own divergence story against a real `git merge`,
with `.gitattributes` set exactly as `GITATTRIBUTES_LINE` instructed.

**What was found:** the merge exits 0, reports "4 insertions", raises no
conflict — and both concurrent claims are gone. `merge=union` is **line**-
based. Every record in a `.claims/` file begins with the same boilerplate
lines (`---`, `{`, `"cid": …`), so git aligns the two sides' record
boundaries against each other and unions *inside* a record, welding two
claims into a single malformed record with duplicate `cid`/`sig` keys and a
concatenated body. Parsing it yields `duplicate field 'cid'`.

Without the driver, the same merge raises an ordinary conflict — nine
markers, visible, recoverable by hand. **The guidance we shipped made the
outcome strictly worse than shipping nothing**, converting a visible
conflict into silent destruction.

An aggravating cause, recorded because it matters beyond this ADR:
`Log::iter_all` walks the MST keyed by content CID, so `write_subject`
emits records in CID-lexicographic order, not append order. A new claim
therefore lands at an arbitrary offset mid-file rather than at the tail —
which independently falsifies ADR-43's premise that "a conflict at a file's
tail is itself informative."

**Decision:** ship no merge-driver guidance for `.claims/` at all.
`GITATTRIBUTES_LINE` becomes empty, `gitignore_guidance()` actively warns
against setting one, and the repo's own `.gitattributes` is removed.

**Why not fix the driver instead:** union merge could only be safe if a
record were a single line, or if record boundaries were unique enough that
git could never align across them. Both are format changes, and neither is
true today. Between "no guidance" and "guidance that loses claims," no
guidance wins immediately and unconditionally; a real concurrent-merge
story is part of the v0.7.0-beta.1 correctness release, designed against
this evidence rather than assumed.

**What ADR-43 got right, and keeps:** claims are immutable and additive, so
keeping both sides *is* the correct resolution, and kan still never rewrites
history and still runs no git commands. The error was reasoning from "both
sides should survive" directly to a line-based tool, without checking what
that tool does to this file format.

**Consequence for the invariant:** this is the third confirmed instance of
the same shape — a lossy operation treated as authoritative, resolved
last-writer-wins, in a module that writes bytes rather than one that reads
morphisms. `CLAUDE.md`'s "no operation destroys a subject" was enforced in
`fold/` and never applied to `store/`, `transport/`, or `sign/`. The
v0.7.0-beta.1 correctness release is organized around that boundary rather
than around the defect list.

## ADR-48 — v0.7.0-beta.1: the correctness release, and the boundary it found

**Date:** 2026-07-22
**Status:** Accepted
**Design doc:** `.design/v0.7-milestone.md` (24 requirements, 26 acceptance
criteria)

**Context:** three independent adversarial reviews of the shipped
v0.6.0-beta.1 (issue #48's method — hostile by default, north star recited
from the record, evidence verified rather than accepted) found roughly twenty
confirmed defects, about half of which destroy data. None came from the test
suite; all 105 tests passed throughout. Every one came from running the
binary.

**The finding, which is the point of this ADR.** All three tracks converged
on the same boundary without being told to:

> kan is correct exactly where the design attention went — the fold and the
> cryptographic core — and absent everywhere data is keyed, framed, or
> rendered.

Track 1 counted five lossy derivations in the codebase and found four treated
as authoritative and resolved last-writer-wins; the only one handled
correctly was the one *designed* as a heuristic. Track 3: "the cryptographic
core is sound; the framing layer around it is not." Track 2: "every read
surface reports its filtered view as if it were the whole log."

`CLAUDE.md`'s non-negotiable invariant — *no operation destroys a subject* —
was enforced with real care in `fold/`, the one module that reads morphisms,
and never applied to `store/`, `transport/`, or `sign/`, the modules that
write bytes. **One boundary never crossed, not twenty independent slips.**
That is why this release was organized around the boundary rather than around
the defect list, and it is the most useful thing to carry forward: the next
audit should start wherever a value is derived and then treated as unique.

**What shipped**, by area (PR numbers in parentheses):

*Local spine* — `recorded_at` in signed content, ending the collision where
identical content overwrote itself and could void a retraction (#79); an
`flock` around append plus HEAD revalidation under it, ending concurrent
claim loss (#80); `sync_all` ordering and atomic HEAD replacement (#80);
recovery from a torn CAR tail or lost HEAD, so a damaged log opens instead of
bricking (#82); identity retrievable across a repo move, and an explicit
`KAN_IDENTITY_FILE` escape from a keychain that hangs non-interactively
(#81).

*GitTree* — `text_len` framing, so the writer's own output stops failing its
own reader on trailing whitespace and prose cannot inject a record boundary
(#83); injective filenames (#83); a record format version (#83); header
fields authenticated against the claim they describe (#84); deletion
detection (#84); `publish` folding before it writes (#84); `publish --all`
and a tested merge story (#85).

*Read surfaces* — `cites`/`artifacts`/author/time finally visible, CID
lookup, `context` ranking globally and naming what it omitted, superseded
statuses marked, relations visible from both ends, and descriptions that stop
promising what the surface cannot deliver (#86).

**Format breaks, taken once and deliberately.** `recorded_at` and
`KnownBody`'s `deny_unknown_fields` changed the shape of every newly written
claim, and the GitTree record format went to v2. All were enumerated in the
design doc up front rather than discovered during implementation, because the
argument permitting them expires: the beta has exactly one user, who made
this call about their own data. **This is the last release where that
argument is available.** `docs/SPEC.md` §7.1's coexistence contract carries
everything afterwards, and this release is its first real exercise — which is
also why ADR-44's own worst case had to be closed here (see below).

**ADR-44 was half-implemented and this release found it.** `deny_unknown_fields`
landed on `ClaimContent` and not on the `KnownBody` mirror, so a *known* kind
carrying a field from a newer kan deserialized, silently dropped the field,
and was reported as "altered since it was signed" — verbatim the behaviour
ADR-44 measured and claimed to have eliminated, still live one level down.
§7.1 now states the rule at both levels.

**Two things deliberately not overclaimed:**

- Deletion detection is envelope metadata, not signed. It catches accidental
  loss and naive removal; an editor who rewrites every remaining record's
  `seq`/`of` defeats it. Authenticated deletion detection needs the publisher
  to sign over the record set — a new claim shape, and therefore its own
  design pass rather than something smuggled into a fix.
- `Contested`/`Confirmed` remain unreachable. They need the `PeerContested`
  trust surface, which is v0.8. This release only stopped *promising* them.

**`KAN_AGENT` removed rather than repaired.** Its own source called it "not a
real keypair and nothing verifies it against anything," kan's own `.mcp.json`
set it, and the shipped configuration therefore made the agent surface and
the human surface read disjoint views of one log by default. v0.9's per-agent
identity replaces it wholesale. Repairing something already scheduled for
deletion, in the release whose theme is that provisional patches cause data
loss, would have been the wrong lesson.

**Process notes worth keeping:**

- **Negative controls became mandatory.** PR 3's concurrency test *passed
  against the broken code* on its first run — the child processes serialized
  on their own startup jitter and never actually raced. Every concurrency and
  corruption test in this release is now checked by disabling the fix and
  confirming the test fails. The same omission is why
  `tests/log_cross_process_stress.rs`, sequential despite its name, never
  caught the defect it looks like it covers.
- **A test encoded a defect as a guarantee.** ADR-47's fix had to change
  `assert!(GITATTRIBUTES_LINE.contains("merge=union"))`. The suite was
  verifying the code did what the design said, and the design was wrong.
- **Third confirmed instance of the crate-trust rule paying for itself**
  (after ADR-11/12 and ADR-25): `fs4`'s API does not match what its docs
  suggest — `FileExt` sits at the crate root, not `fs_std`, and the exclusive
  method is `lock()`, not `lock_exclusive()`. Found by reading the source.
- **One defect was nearly misattributed.** The keychain hang surfaced as
  "build a new binary, run it, watch it hang," which is indistinguishable
  from a regression in the change under test. Only reversing the order across
  two scratch copies proved the change was innocent.

**Issue #62 closed as non-reproducible**, not fixed. Retracting every claim
on a subject correctly drops it from `issues`, as do the narrower triggers
tried. Changing code that was right, to close a ticket, is how a defect list
grows fictions.

## ADR-49 — The pre-release review: what it found, and what the record got wrong

**Date:** 2026-07-22
**Status:** Accepted — corrects claims made in ADR-48 and `docs/SPEC.md` §7.1

**Context:** an independent adversarial review of the v0.7 release candidate,
run before the release PR was cut, returned **BLOCK**: nine defects, three of
them data loss, three acceptance criteria failing, and several claims in the
record that the code did not support.

**The finding that matters most is that ADR-48's own thesis held, against
ADR-48.** That thesis: *kan is correct where the design attention went, and
absent everywhere data is keyed, framed, or rendered.* Two of the three worst
defects were in code **this release added**, in exactly those modules, and one
was in the recovery path written to satisfy REQ-4. Fixing a boundary is not
the same as crossing it.

### The recovery code created a worse defect than the one it fixed

After a tolerant read of a damaged CAR, `persist_new_blocks` still opened the
file `append(true)` and wrote *past* the damaged region, so every subsequent
block was unreachable to the same tolerant read that had recovered the rest.
Six appends after a truncation all returned success and all vanished.

v0.6 bricked reads on a torn tail — loud, and recoverable. v0.7 converted that
into **silent, unbounded, permanent loss at exit 0**. The CAR is now repaired
before the first write past it, under the write lock, never on open.

**And the test could not fail.** It appended after recovery and asserted
against the *same in-memory* `Log`, whose MST is in RAM, so the count was `+1`
by construction. It now drops the `Log` and reopens from disk; disabling the
repair makes it fail.

This is the sharpest available correction to ADR-48's claim that *"every
concurrency and corruption test in this release is now checked by disabling
the fix and confirming the test fails."* The concurrency test was. The
corruption test was not, and its author believed otherwise. **A negative
control asserted in prose is not a negative control.**

### A read command could roll the log back

`open_or_create` read the CAR and then `HEAD`, neither under the lock, so a
concurrent append between them left a reader holding an old CAR and a new
`HEAD` — a torn view of a healthy log — whereupon the recovery path fired and
rewrote `HEAD` backwards with a plain `fs::write`. Reads now re-read both
before concluding damage and **never write**: a recovered root is held in
memory and persisted by the next append under the lock. The doc comment
claiming readers "never see a torn state" was false and is corrected in place.

### `publish`'s fix broke the layer below it

Folding before publishing was right — it filters retracted and untrusted
claims (REQ-12). But the fold's unit is the merge *class*, so taking its
output wholesale put every `SameAs`-merged subject's claims into each of their
files, duplicated every claim, and made publishing one subject rewrite
another's file. **Decision: a `.claims/<subject>.md` file is subject-exact.**
The merge still travels — as the `SameAs` claim, published like any other and
folded on read — which is where kan puts everything else. That decision is
what made REQ-13's second half (authenticate the filename against the records)
implementable at all; it is now implemented, having been silently dropped.

### Claims corrected

- ADR-48 said *"relations visible from both ends."* False for the case REQ-21
  states: `inbound_edges` sat inside the arm for subjects that have a merge
  class, and a subject with no claims of its own has none. Relations are
  precisely the thing that can arrive before a subject does. Fixed.
- ADR-48 said *"descriptions that stop promising what the surface cannot
  deliver."* `schemars` rationale still shipped in seven tools' schemas via
  `SubjectKind` — the identical fix was applied to `StatusValue` twelve lines
  below and missed. Fixed.
- ADR-48's honesty note on deletion detection conceded only that *"an editor
  who rewrites every remaining record's `seq`/`of` defeats it,"* framed as an
  adversary. **kan's own `publish` is that editor**, which makes the accidental
  republish case — the one REQ-10 names in its own text — exactly what the
  mechanism cannot catch. Filed rather than patched: honest detection needs
  the publisher to sign over the record set.
- `docs/SPEC.md` §7.1, amended in this same release, mandates a test
  constructing a *known* kind with an unknown field. The behaviour works; the
  mandated test did not exist. Filed.
- REQ-18 was reinterpreted from "resolve a retraction's target" into "accepts
  CID syntax" — it searched the live view, which by definition excludes the
  retracted claim it exists to show. Fixed by searching the log.
- The `KAN_IDENTITY_FILE` branch lacked the refuse-to-mint-a-second-identity
  guard the keychain branch had, so following `KeychainUnreachable`'s own
  recommended remedy produced a new DID and "no subjects yet" at exit 0 —
  verbatim REQ-5's failure mode via the release's own advice. Fixed.

### Process

**PR #89 shipped without an ADR**: encryption-at-rest reversed ADR-25's
explicit decision, added a top-level `identity` verb outside ADR-32's
vocabulary, and sat outside all 24 REQs — at the tail of a release whose theme
is that provisional patches cause data loss. This ADR supersedes ADR-25's
"leave the plaintext file in place" and records `identity` as setup/tooling
alongside `mcp`, not a fifth phase of the claim-graph vocabulary.

**Two decided items were lost in a re-scope** — the stale-binary error message
and the subject-argument unification — both recorded as decisions in kan's own
log, neither carried into the design doc, which was written from the session
rather than from the log. The error message was recovered only because the
defect it fixes caused a false data-loss alarm hours later. Nothing in `day
design check` compares a design doc against the `decide` claims already on its
subject; that gap is filed against `day`.

**The design doc's own escape condition was met and not fired.** It said the
GitTree reader moves into v0.7 if REQ-9, REQ-10 or REQ-13's criteria could not
be demonstrated without a shipped reader. All three required linking the crate
directly. The condition is now acknowledged: the reader stays in v0.8, and the
release states plainly that those three ACs are demonstrated at the library
level only. Leaving a stated condition silently unfired is how a design doc
stops being evidence.

## ADR-50 — Structured output: kan's prose stops being an accidental API

**Date:** 2026-07-22
**Status:** Accepted

**Context:** `day` shells out to the `kan` binary rather than linking it
(ADR-42) — the right boundary — and then parsed kan's `show` **output** to get
claims back, because prose was the only thing on offer. v0.7's read-surface
work (REQ-17, REQ-22) changed that output, and `day` broke silently: `day
assess docs` reported "no docs schema is declared" against a log that plainly
declared one. `day`'s parser read the subject label where the kind used to be,
found no `text:` field, and returned every claim empty. `day doctor` still
passed, because it only checks reachability.

**The finding is the coupling, not the break.** Every word kan printed was a
de-facto API with no contract attached. The changes that broke it were
improvements by every measure a human cares about, which is the trap: a
project cannot improve its human-facing output and keep a machine consumer
working, unless the machine consumer is reading something else.

Both repos' tests missed it for the same reason from opposite sides. `day`'s
`tests/kan_conformance.rs` *does* catch it — it fails against the current
binary — but skips when kan is not installed, and kan's CI never runs it.

**Decision:** the read verbs (`show`, `status`, `issues`, `context`) gain
`--json`. The rendered form stays what it is, for people, and stays free to
improve; anything programmatic reads the structured form.

**What makes it a contract rather than another accident:**

- **Versioned.** Every payload carries `v` (`json::SCHEMA_VERSION`), so a
  consumer can refuse a shape it does not understand instead of silently
  misparsing it — precisely what `day` could not do, for want of a version to
  check.
- **Additive-only, `Option` omitted rather than null** — the same discipline
  `docs/SPEC.md` §7.1 applies to claims, so a consumer pinned to an older
  shape keeps working. Adding a field does not bump `v`; that is the point.
- **Named fields for things prose conflated.** `kind` and `subject` are
  separate, and each claim keeps the subject it was *filed under* rather than
  the queried name — the prose renderer attributed every claim in a merge
  class to whichever name you asked for.
- **Structure instead of stringified prose.** Relation kind and target,
  retraction targets, subject titles, status values, and supersession are
  fields, not text a consumer re-parses.
- **The predicate is shared, not duplicated.** `is_open_issue` was factored
  out of `issues` so the rendered and structured surfaces cannot drift on
  *what an issue is* — only on how it is presented. Duplicating it would have
  recreated this ADR's own bug one layer down.

**What this is not.** Not the claim wire format. `transport::git_tree` carries
signed, verifiable records; this carries a rendered *view* — the fold's
output, decategorified, unsigned. Anything that needs to verify a claim reads
the log or a published record. Keeping that line clear is why this lives in
`json.rs` and not near the transport.

**Rejected: freezing the prose.** It would have meant v0.7's read-surface
improvements were unshippable, and every future one too — paying for a
consumer's parsing choice with the legibility of the tool's primary surface.

**Follow-up, not resolved here:** kan's CI does not run `day`'s conformance
suite, so the next break is still caught by the repo that suffers it rather
than the repo that causes it. That is a cross-repo CI question and gets filed
rather than improvised.

## ADR-51 — Seventh release: v0.7.0-beta.1, the correctness release

**Date:** 2026-07-22
**Status:** Accepted

**What it is:** the release ADR-48 describes and ADR-49 corrects — roughly
twenty defects found by three adversarial reviews of v0.6.0-beta.1, about half
destroying data, plus nine more found by a fourth review of the release
candidate itself. 32 commits, 105 → 173 tests.

**Why beta again, not stable:** the format broke twice on purpose.
`ClaimContent` gained `recorded_at`, `KnownBody` gained
`deny_unknown_fields`, and the GitTree record format went to v2. The
coexistence rule (`docs/SPEC.md` §7.1) makes those survivable in one
direction only, and the asymmetry is worth stating precisely:

- **v0.7 reads a v0.6 log.** Verified against this repo's own: 14 subjects, 61
  `spine` claims, zero errors, and appending to that legacy log works.
  Pre-v0.7 claims keep their exact CIDs, because `recorded_at` is `Option`
  with `skip_serializing_if`.
- **v0.6 cannot read a v0.7 log**, and says so: *"this kan is older than the
  log it is reading… the log is not damaged."* That is the contract working,
  not a defect — but it means upgrading is one-way in practice, which is a
  beta property, not a stable one.

**Shipped ahead of a re-review, deliberately, and this is the honest part.**
The recommendation after ADR-49 was to re-run the adversarial review against
the fixes, on the reasoning that the last review found its worst defects in
the *previous* round's fixes. That recommendation stands and is not
withdrawn. It was overridden for a concrete cost: `day`'s CI is blocked, and
`day` cannot migrate off parsing kan's prose (day#42) until the `--json`
surface exists in a *published* version. Every BLOCK finding is fixed and
verified against the reviewer's own reproductions; what is being skipped is
prudence about the fixes, not a known defect.

**The re-review is therefore owed before v0.8**, and before anyone who is not
the author depends on this. Recorded here rather than left as an intention,
because "we'll re-check it later" is the shape of promise this whole release
exists to stop making.

**Also in this release, and not in the milestone doc:** ADR-50's structured
output. It was not planned; it exists because v0.7's own read-surface
improvements silently broke `day`, which revealed that kan's prose had been a
de-facto API all along. A release whose theme is unexamined guarantees
finding one more on its way out is fitting, if not comfortable.

## ADR-52 — The re-review: Wave 1 held, the migration fix did not

**Date:** 2026-07-23
**Status:** Accepted

**Context:** an independent adversarial review of the four commits that landed
after `v0.7.0-beta.1` (Wave 1 ergonomics, and the #107 migration fix), run
before cutting the point release those commits are for. Verdict: REDIRECT.

**Wave 1 held under attack**, which is worth recording as much as the defects:
the both-forms subject argument refuses the ambiguous case on all six verbs
and lands claims on the subject meant; the recovery phrase is genuinely off
argv (EOF-clean, no echo, no alternate path); `--version` matches. And the
ADR-49 fixes re-verified — D1 (append-after-recovery survives a reopen from
disk) and D4 (a `SameAs`-merged publish is subject-exact) both hold on the
binary.

**The migration fix reintroduced the exact class it was fixing.** #107 existed
because `file_name` was lossy and let two subjects collide into one file. The
fix keyed the *deletion* of the superseded file on `legacy_file_name` — the
same lossy mapping — so publishing `telos/x` deleted a different subject
`telos_x`'s file and reported that it had rewritten those claims. A write path
destroying another subject's data, keyed on a value that is not unique. The
non-negotiable invariant, violated by the fix for a bug of the same shape.

**This is the fifth instance in one development cycle** of one pattern:
*a value derived from richer data, then trusted as a unique key for an
operation that mutates or destroys.* MST key from content CID; `.claims`
filename from sanitized subject; keychain account from path; `HEAD` as a
single cell; and now the legacy filename as a deletion key. ADR-48 named the
class; ADR-49 found two more instances in its own fixes; this one makes the
rule explicit and permanent:

> **`legacy_file_name` is lossy by construction. It may be a read hint and
> nothing else — never a key for a delete, an overwrite, or an
> authorization.** Any operation that removes or authorizes must key on the
> content (the CID, the record's own signed subject), never on a name derived
> from it.

**Also from this review, worth keeping:** D-B was a *tautological guard* —
`bytes == import(bytes).export()` — on a key-deletion path, which never
compared the file it was about to delete. It passed every test because it was
trivially true. A guard that cannot be false is not a guard, and it is the
same failure as ADR-49's test that could not fail: a check written in the
shape of a check, verifying nothing. Both are now caught only because the
review runs the tool rather than reading the assertions.

**Process note:** the re-review was run because ADR-49 established that the
previous round's *fixes* were where the worst defects lived. That reasoning
held again — every defect this round was in code the prior round added, none
in the original v0.7 surface. The standing conclusion: a round of fixes to a
BLOCK/REDIRECT gets its own review before it is trusted, not a presumption of
correctness because it is "just the fixes."

## ADR-53 — Eighth release: v0.7.1-beta.1

**Date:** 2026-07-23
**Status:** Accepted

**What it is:** the point release v0.7.0-beta.1's four unreviewed commits were
building toward, cleared by two further adversarial reviews (ADR-52 and the
third-round deletion-guard audit). Contents:

- **Wave 1 ergonomics** — the subject argument accepted both positionally and
  as `--subject` on every write verb (ending the failed-command/lost-write
  class two independent sessions hit); `kan --version`; the recovery phrase
  read from stdin instead of argv (a private key was reaching shell history
  and `ps` output); and removal of a lingering, unencrypted plaintext key copy
  on the keychain-hit path.
- **The `.claims/` migration path** (#107) so existing repos upgrade without
  orphaned, diverging files — and the REDIRECT fixes that made it safe
  (ADR-52): retirement and the keychain deletion guard both stopped keying
  destructive operations on lossy derived values.

**Why patch, not minor:** unlike v0.7.0, nothing here breaks the on-disk
format. `ClaimContent`, the CID computation, and the GitTree record format are
all unchanged; a v0.7.0 log and a v0.7.1 log are byte-identical in shape. The
change is ergonomics, one security fix, and migration handling — additive and
compatible in both directions with v0.7.0. This is the first non-minor release
(ADR-19's scheme allowed it; nothing had qualified until now).

**Why it matters operationally:** this is the release the *other* repos
upgrade to. It carries the phrase-off-argv security fix and the `.claims/`
migration handling, without which an upgrading repo leaks a key on restore and
accumulates duplicate published files. v0.7.0 should be treated as
superseded for any repo that publishes.

**The review chain that produced it, recorded because it is the point:**
v0.7.0 shipped ahead of a re-review (ADR-51) under schedule pressure. That
re-review (ADR-52) returned REDIRECT and found the migration fix reintroduced
the very class it fixed. Its fixes got their *own* review, which returned
APPROVE. Three rounds, each finding real defects in the prior round's fixes
until the last — which is the empirical case for ADR-49's rule that a round of
fixes to a BLOCK/REDIRECT is reviewed before it is trusted, not presumed
correct. Two non-blocking follow-ups remain filed (#111, #112).

## ADR-54 — The sync remote and the publicness ladder

**Date:** 2026-07-28
**Status:** Accepted

**Context:** the durability design pass (`.design/durability-log-recovery.md`,
#93/#88) asked, as its one open question (Q3), whether the complete-durability
answer is a machine-only complete mirror or just the curated `.claims/` plus a
visibility column. Pulling on that surfaced the larger question kan had
deferred: what is kan's version of a *git remote* — the "server-side,
non-atproto component" — and how does it relate to the eventual atproto/social
layer. This ADR records the shape resolved in that session
(`.design/sync-remote-and-publicness-ladder.md`).

**The realization that organizes everything: encryption dissolves the
durability-vs-sharing tension #93 treated as permanent.** #93 posed durability
(complete, automatic, no judgement) and sharing (curated, deliberate, judgement
is the point) as wanting opposite defaults. They conflict *only in plaintext*.
An end-to-end-encrypted backup carries **zero privacy cost**, so durability can
be total-by-default while sharing stays a separate, deliberate act — the two
are distinguished by *encryption state*, not *completeness state*. The wall #93
saw was a plaintext wall.

**The complete-durability answer is a personal encrypted backup remote, not an
in-repo mirror.** The CAR is pushed to a remote over an API and never enters the
git tree — which sidesteps the durability doc's REQ-6 (a plaintext complete
dump either destroys `.claims/`'s curation or reintroduces the binary-in-git
merge conflict ADR-3 rejects) entirely. `.claims/` stays purely the sharing
layer. This supersedes the durability pass's Q3.

**The remote is `HostedRelay` at N=1** (`.design/sync-layer-architecture-and-staging.md`
M4, ADR-35), the multi-actor fold turned off. "Private teams" is the N>1
deployment of the identical server and sync protocol, reached by subscribing to
other authors' logs. So the personal backup is not a new epic — it is
HostedRelay's first and simplest deployment, designable and shippable ahead of
the hard multi-actor story.

**The wire shape is atproto repo-sync, not a git-remote protocol, and this is
what makes it lighter than git.** The log is an append-only Merkle Search Tree
with no history rewriting (the non-negotiable invariant). Git's remote weight is
mutable refs and history rewriting — force-push, rebase, pack negotiation over a
rewritable DAG — none of which kan has. Two MSTs reconcile by comparing root
CIDs and descending only where subtrees differ, which is exactly what
`com.atproto.sync` already does and what kan's on-disk artifact (already an
atproto repo) is already shaped for. The eventual atproto/PDS transport (M5) is
therefore a continuation of the same wire, not a rewrite.

**The publicness ladder** — every downward rung an explicit, user-controlled
escalation, riding kan's existing publish/curate boundary (ADR-43) extended one
notch (publishing already means "legible to others"; escalation extends *to
whom*):

- **L0 Local** ↔ **L1 encrypted backup** (server-blind) — fully reversible,
  total, the durability answer.
- **L2 kan server / permissioned relay** — server reads escalated subjects;
  mostly reversible (the user controls the relay).
- **L3 atproto permissioned** → **L4 atproto public** — practically
  *irreversible* (cached, indexed, federated externally). kan retracts in its
  own model but cannot un-ring an external bell; the escalation surface must
  mark the one-way rungs as distinct from the reversible ones.

**The two server postures are a genuine fork, not one server in two modes.** A
blind backup (L1) wants the server to hold opaque bytes; an AppView relay (L2+)
must read plaintext to fold. They pull opposite directions on E2EE and may be
different services; the HostedRelay design pass must state which it is at each
rung rather than assume a single posture.

**What this hands the identity pass (#105).** The rungs need *different*
encryption capabilities — L1 encrypt-to-self, L2/L3 encrypt-to-a-recipient-set,
L4 plaintext-signed — so #105's master-seed derivation must yield recipient/group
encryption, not only self-encryption (`.design/durability-log-recovery.md`
IREQ-5). A remote holding the log is also a new threat-model actor
(curious/malicious provider) #105 must enumerate. This is the point the
durability, identity, and sync/remote passes merge, recorded so #105 designs
against it from the start rather than discovering it (the #107 failure mode).

**Deferred to future passes, deliberately:** the fully-blind-whole-CAR vs.
structure-preserving-E2EE choice (kan's tiny logs make whole-CAR viable, unlike
git — resolved in the HostedRelay pass); and whether multi-device under one
identity is a sync problem or handled entirely by per-device sub-identities
(#30) plus the fold (the preferred shape — multi-device becomes multi-agent
becomes a fold). Pricing and infra remain out of scope (`kan-infra`); this ADR
records only the architectural consequences *for* monetization — that L1 is a
trust/privacy product and L2+ is a collaboration/intelligence product, and kan
can credibly be both because the user draws the line per-subject.

## ADR-55 — Identity architecture: one root, derived keys, the enclave demoted

**Date:** 2026-07-28
**Status:** Accepted

**Context:** the #105 identity design pass (`.design/identity-architecture.md`),
opened threat-model-first (the mandate: every past identity decision was made
against an unstated model, which is why they don't compose). It supersedes the
framing of #7/#30/#69/#90/#96/#104 as one problem. Two forks were worked
through and resolved in-session; this ADR records them and the threat model
they were decided against.

**Threat model (stated before any mechanism):** T1 local attacker / stolen
disk; T2 curious-or-malicious sync remote (new with ADR-54 — a remote that holds
the log); T3 malicious repo remote / hostile `.claims/` (forgery already caught
by signature verification, the residual risk is a *restore* trusting the wrong
identity, #90); T4 hostile or buggy local agent (writes indistinguishable from
the human's — `KAN_AGENT` was removed, not replaced); T5 compromised dependency
exfiltrating key material at signing time.

**Q1 — the enclave cannot be the root.** The three candidate resolutions were
framed as a menu, but two assumed the Secure Enclave could hold the root key,
which the hardware forbids: the enclave never imports externally-derived keys,
is Apple-hardware-only (kan runs in CI/containers/Linux and under `day`
subprocesses), and its no-prompt path needs a stable code-signing identity a
locally-rebuilt binary and a `day` subprocess lack — the actual mechanism of
#96. The real structure is an **impossibility triangle**: a single key cannot be
phrase-reproducible (REQ-3) **and** no-prompt-everywhere (REQ-4) **and**
non-extractable (T5). REQ-3+REQ-4 are load-bearing for agents and durability, so
they win and **T5 is accepted as residual at the root**.

- **The root** is a phrase-derived, file-resident seed → signing key,
  reproducible and no-prompt on every platform; at-rest protection is OS file
  permissions plus the existing keychain path where present, **not** the
  enclave.
- **The enclave returns later**, only for *signing* and only as the deferred
  **two-layer end-state**: an escrowed phrase-reproducible root that *certifies*
  enclave-held per-device signing sub-keys (non-extractable → closes T5 for
  signing), claims signed by the device key and attributed to the root. This is
  the same machinery as REQ-6 (per-agent keys) and the sync doc's multi-device
  question — multi-device is multi-signing-key-under-one-root, a fold. It
  touches the fold, `AuthorId`, and `TrustBase`, so per the "don't touch the
  fold without a measured reason" rule it is its own later milestone, named not
  built here.

**Q2 — HPKE to derived X25519 keys, per-space-epoch wrapping.** kan is
append-only, so sharing is monotonic: an immutable claim cannot be
re-encrypted, a reader who could decrypt it keeps that ability, and removal
stops *future* access only. **Revocation is future-only by construction** — the
same truth as the L3/L4 ratchet, stated as kan's stance rather than hidden. This
rules out MLS (forward-secrecy/churn machinery kan cannot honor over immutable
claims, plus a delivery service it lacks) and a static group key (no membership
story). The primitive is **HPKE (RFC 9180)** wrapping a per-space-epoch content
key to each member's derived **X25519** encryption key; membership change starts
a new epoch for future claims while past epochs stay readable by prior members,
with an optional explicit grant-history re-wrap. `age` was the runner-up (same
recipient model, off-the-shelf) but is a file format rather than a KEM
primitive. The full protocol is the HostedRelay/#7 E2EE pass (ADR-35 M1); this
pass names the primitive.

**Key separation, done right (and the footgun avoided).** The signing key stays
**P-256** (`did:key`, ADR-4, REQ-8, unchanged); the encryption key is a derived
**X25519** key — the textbook sign/encrypt split, which *avoids* the
Ed25519→X25519 conversion footgun by deriving independently rather than
converting. The encryption key is per-*identity* (all of one human's devices
derive the same one from the phrase, so any device decrypts shared spaces),
while the two-layer signing sub-keys are per-*device* — multi-device adds
attribution keys without multiplying encryption recipients.

**Migration (first-class, because #107 proved that is where these break).**
Today's phrase encodes the P-256 key directly; a seed-derived scheme changes
that. Resolution: **grandfather each existing signing key** verbatim as the
signing slot (every existing DID and signed claim stays valid), introducing the
seed only for the new encryption/sub-keys. Existing identities are
`{grandfathered signing key + new seed}`; only new identities get full "one seed
derives everything." This preserves the DID by construction — the only form that
makes the #90/#107 failure impossible, not merely discouraged. Migration must
prove existing claims stay readable on a real log with a negative control (a
fresh binary must not silently mint a new DID — the #90 guard at
`sign::load_or_create` extended to the seed path), per ADR-52's rule.

**What stays open, by design (not this pass's questions):** the HPKE
epoch/grant-history protocol and relay wire (HostedRelay/#7 pass), and the
`did:plc` migration (atproto pass, ADR-35 M5). REQ-8 keeps a `did:key` so that
road stays open.

**Status of the build:** none. This is a design pass; implementation is its own
later work, and the two-layer signing end-state is a separate milestone from the
root-and-encryption-keys work because only the former touches the fold.

## ADR-56 — The repo goes public, at v0.7.1-beta.1
**Date:** 2026-07-29
**Status:** Accepted

**Decision:** `kan-tools/kan` is a public GitHub repository. The private repo
was the anomaly, not the policy: the crate has been MIT-licensed and published
to crates.io since v0.1, so every release already shipped the full source to
anyone who ran `cargo vendor`. The repo staying private only hid the *history* —
the ADRs, the design docs, and the issue list — while the code itself was
already public.

**What was audited before flipping**, recorded so it isn't re-derived next time
the question comes up for a sibling repo:

- Credential patterns (`ghp_`, `github_pat_`, `sk-ant-`, `AKIA`, `xox[baprs]`,
  PEM private-key headers) across all 91 tracked files **and** across every blob
  in every commit of every ref — 98 distinct paths ever committed. Clean; every
  hit in the working tree was prose *about* secrets.
- `.kan/` was never committed. The `.gitignore` entry (ADR-3) held for the
  repo's entire history, so no log, index, or signing key was ever tracked.
- Personal identifiers: only `kan-test@example.com` and `t@example.com`, both in
  test fixtures. No home-directory paths.
- `.claims/hard-claims.md` contains signed records and the author `did:key:`.
  That is a *public* key and publishing it is the point of ADR-43, not a leak.
- `CARGO_REGISTRY_TOKEN` is scoped to the `crates-io` GitHub Environment
  (ADR-20), not repo-wide, and its job triggers only on `v*.*.*` tags. Public
  visibility means `pull_request` CI now runs for forks; ADR-20's scoping is
  exactly what keeps that safe, which is the payoff for a choice made when the
  repo had no forks to worry about.

**Two exposures accepted deliberately**, not overlooked:

1. **The issue list is now public, including kan's own security-shaped
   weaknesses** — #30 (per-agent identity is still the v0.2 temporary patch),
   #90 (a binary upgrade can silently mint a new identity), #96/#69 (the OS
   keychain is unusable non-interactively), #121 (the default fold silently
   hides other identities' claims). Publishing the known-weakness list next to a
   pre-1.0 crate that signs things is a real trade. It is accepted because the
   alternative — a signing tool whose limitations are discoverable only by
   reading the source — is worse, and because the candor is the same property
   the tool itself is built to provide. Revisit if kan is publicized beyond
   beta; the exposure question changes with the audience, not with the code.
2. **`forecast-bio/crosslink` is named** in ADR-34, and `docs/SPEC.md` opens
   with a direct critique of crosslink's sync model. crosslink is MIT-licensed
   open source, so the citation and the critique are both fine as they stand.

**Consequences:** none for the build. Nothing in the codebase, CI, or release
process changes. What changes is that the design record — SPEC, 56 ADRs, the
`.design/` docs — is now readable by anyone evaluating the crate, which was
always the argument for keeping it in the repo rather than in a notebook.
