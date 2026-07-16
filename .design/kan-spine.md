# Feature: kan spine (v1 local-only build)

## Summary
The first buildable slice of kan: the `Claim` model + content addressing, a local
append-only signed log as source of truth, a disposable SQLite index, the
categorical fold (identity-before-state, same enrichment, decategorify only at
render), git-derived anchors + computable relation providers, and a CLI + MCP
server exposing budgeted context assembly. Scope is one human, one-or-more local
agents, one repo, no sync (`docs/SPEC.md` §11, `docs/HANDOFF.md` "first build").
This doc resolves the crate/dependency choices and the two spec-flagged OPEN
choices, and specifies the concrete Rust types, fold pipeline, `RelationProvider`
trait, CLI surface, and fixtures test plan `docs/HANDOFF.md` asks the initial
design pass to deliver.

## Requirements

- REQ-1: Claim content-addressing uses DAG-CBOR canonical encoding (atproto
  map-key ordering) via the `atrium-rs` crate family; CID excludes signature and
  CID itself; signature signs the CID. (`docs/SPEC.md` §3)
- REQ-2: `Claim`'s kind and payload collapse into one closed `ClaimBody` enum —
  structural variants (`Subject`, `Status`, `Relation`, `Retraction`) are typed;
  narrative variants (`Observation`, `Plan`, `Decision`, `Result`, `Blocker`) hold
  opaque text. `ClaimKind` is a derived method, not a separate field, so an
  invalid kind/body pairing is unrepresentable. (`docs/SPEC.md` §7, §12.1; ADR-5)
- REQ-3: `SubjectRef` is `Local(Rkey) | Anchor(Anchor)`; `Local` refs never cross
  log boundaries; cross-log linkage is exclusively via `cites` and typed
  `Relation` claims. (`docs/SPEC.md` §4.1)
- REQ-4: `Anchor` is a closed enum `{Workspace(GenesisCid), Commit(Sha), Blob(Cid),
  FileAt(Path, Sha), LineRangeAt(Path, Sha, Span)}` carrying strict identity,
  decided by construction rather than asserted. (`docs/SPEC.md` §5)
- REQ-5: `Relation::SameAs` is the only identity-conferring edge; the identity
  fold builds a directed witness graph (not union-find), producing per-viewer
  `M(A,B)` path-space objects retaining witnesses. (`docs/SPEC.md` §4.2–§4.4)
- REQ-6: The fold runs the identity fold, then the state fold over each
  merge-class, both under one `TrustBase`; decategorification to a flat view
  happens only at `render`, never in the store. (`docs/SPEC.md` §9)
- REQ-7: A `RelationProvider` trait supplies computable edges (`GitAncestry`,
  `GitSameFile`) that union with attested edges inside the fold, high-trust by
  default and named/disableable. (`docs/SPEC.md` §6)
- REQ-8: Local-only identity is a self-generated `did:key` keypair (via
  `atrium-crypto`), stored at `.kan/identity`, upgradeable to `did:plc` later
  without re-signing history.
- REQ-9: The local log and the disposable SQLite index live at `.kan/`
  (`.kan/log/`, `.kan/index.sqlite`), gitignored, sibling to `.git/`.
- REQ-10: `Retraction` is `ClaimBody::Retraction { supersedes: Cid }`; only
  self-retraction exists (keyed on full `AuthorId`); cross-author suppression is
  `Relation::Rejects`, honored only by folds that trust the rejecter; retracting
  a `Retraction` is the undo mechanism — no separate `Restore` kind is needed,
  since exclusion-from-state-reduction composes correctly over the strictly
  backward-only `cites` DAG. (`docs/SPEC.md` §8, §12.2)
- REQ-11: Hard-delete (true erasure, no tombstone) is supported at the storage
  layer only; v1 exposes no CLI verb for it.
- REQ-12: `kan` ships as a single binary (one crate); `kan mcp` is a subcommand
  that starts the MCP server (via `rmcp`) over stdio — no separate binary.
- REQ-13: CLI vocabulary is exactly: `observe`, `plan`, `decide`, `resolve`,
  `same`, `show`, `issues`, `status`, `session start`/`session end`,
  `context [--budget N]`. (`docs/HANDOFF.md` vocabulary table; `CLAUDE.md`)
- REQ-14: The MCP server exposes claim-append and **budgeted context assembly**
  — query the claim graph under a token budget for the maximal-value claim set —
  as the core product surface for agents. (`docs/HANDOFF.md` "first build" item 7)

## Acceptance Criteria

- [ ] AC-1: Two `Claim`s with identical content produce identical CIDs across
      runs and process restarts (determinism property test).
- [ ] AC-2: A claim with tampered content fails signature verification; its
      recomputed CID differs from the CID that was actually signed.
- [ ] AC-3: Fixture — one log, no `SameAs`, all subjects `Local` — folds to a
      trivial latest-wins view with the contest stage never entered. This is the
      local-only smell test from `CLAUDE.md`.
- [ ] AC-4: Fixture — two `AgentKey`s under one `Did`, contested status — folds
      to `Contested{resolved, open}` under `PeerContested`, and to `Settled`
      under `SoloTrust` restricted to the human's own claims.
- [ ] AC-5: Fixture — a `SameAs` merge followed by retraction of the `SameAs`
      claim — re-derives the split component from the retained witness edge set,
      not from a stale cached union-find state.
- [ ] AC-6: `kan observe "..." --cites <path>` appends a claim; after deleting
      `.kan/index.sqlite` and rebuilding, `kan show <subject>` reflects the same
      claim (proves the index is a disposable projection).
- [ ] AC-7: `kan context --budget N` returns a claim set whose total token
      estimate is ≤ N and is deterministic for a fixed claim set + budget.
- [ ] AC-8: `kan mcp` serves over stdio; an MCP client can list tools and
      successfully call the claim-append tool.
- [ ] AC-9: Retracting a `Retraction` claim restores the original claim to the
      live set on the next fold, with no special-cased "undo" code path.
- [ ] AC-10: A `GitAncestry`-computed edge correctly orders two claims anchored
      to different commits on the same branch with zero attested `cites` between
      them.

## Architecture

### Crate layout (single binary — ADR-2)

```
kan/
  Cargo.toml
  src/
    lib.rs               # public API: Claim, fold, Store
    claim.rs              # Claim, AuthorId, SubjectRef, Anchor, ClaimBody, RelationKind
    sign.rs                # did:key generation, signing/verification (wraps atrium-crypto)
    cid.rs                  # DAG-CBOR canonicalization + CID
    store/
      mod.rs                # Store trait
      log.rs                # local append-only signed log (wraps atrium-repo MST/CAR)
      index.rs               # disposable SQLite projection (rusqlite)
    fold/
      mod.rs                # fold(), render()
      identity.rs            # identity fold: witness graph, M(A,B), merge-classes
      state.rs                # state fold: poset -> antichain -> classify
      trust.rs                 # TrustBase / Enrichment: SoloTrust, PeerContested
    relations/
      mod.rs                  # RelationProvider trait
      git_ancestry.rs
      git_same_file.rs
    cli/
      mod.rs                  # clap dispatch
      observe.rs, plan.rs, decide.rs, resolve.rs, same.rs,
      show.rs, issues.rs, status.rs, session.rs, context.rs
    mcp.rs                    # `kan mcp`: rmcp server, claim-append + context tools
    main.rs                   # binary entrypoint; dispatches to cli:: or mcp::
  tests/
    fixtures/                 # fold fixtures (Phase 4, built alongside Phase 3)
```

`store/log.rs`'s wrap of `atrium-repo` is provisional — see Open Question Q1.
`.kan/` layout (ADR-3):

```
myrepo/
  .git/
  .kan/
    log/            # signed claim records (atrium-repo MST/CAR)
    index.sqlite    # disposable projection, rebuildable
    identity        # local did:key keypair (ADR-4) — back this up like any signing key
```

### Concrete Rust types

```rust
type Did = String;          // "did:key:z6Mk..." (ADR-4); did:plc later, unchanged shape
type AgentKey = VerifyingKey;

struct AuthorId {
    did: Did,
    agent: Option<AgentKey>,
}

type Cid = atrium_repo::Cid; // pending Q1 spike; placeholder alias until verified

struct Claim {
    author: AuthorId,
    sig: Signature,
    workspace: Anchor,          // Anchor::Workspace(GenesisCid)
    subject: SubjectRef,
    body: ClaimBody,            // kind is ClaimBody::kind(), not a separate field (ADR-5)
    cites: Vec<Cid>,
    artifacts: Vec<ArtifactRef>,
}

enum SubjectRef {
    Local(Rkey),
    Anchor(Anchor),
}

enum Anchor {
    Workspace(GenesisCid),
    Commit(Sha),
    Blob(Cid),
    FileAt(PathBuf, Sha),
    LineRangeAt(PathBuf, Sha, Span),
}

enum ClaimBody {
    Subject { title: String, subject_kind: SubjectKind },
    Observation { text: String },
    Plan { text: String },
    Decision { text: String },
    Blocker { text: String },
    Resolution { text: String },
    Result { text: String },
    Status { value: StatusValue },
    Relation { kind: RelationKind, target: SubjectRef },
    Retraction { supersedes: Cid },
}

enum RelationKind {
    SameAs,      // the ONLY identity-conferring edge
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
    Rejects,     // cross-author local suppression, honored only by trusting folds
}

enum TrustBase {
    SoloTrust,                          // enrich over Bool: any trusted path -> flat merge
    PeerContested { weights: HashMap<AuthorId, f64> },  // enrich over [0,1]/quantale
    // spec caps v1 at exactly these two reference enrichments (SPEC.md §11)
}
```

### The fold: signature + four-stage pipeline

```rust
fn fold(claims: &ClaimSet, enrichment: &TrustBase) -> FoldedView;
fn render(view: &FoldedView, policy: &RenderPolicy) -> FlatView;
```

`fold` is the pure, deterministic reduction; `render` is the only place the
categorical view collapses to something flat for display (`docs/SPEC.md` §9,
"decategorify only at render"). Internally, `fold` is four stages, matching
`docs/HANDOFF.md`'s "gather → order → reduce → contest," nested inside the
spec's identity-then-state composition:

1. **Gather** — identity fold: build the directed trusted-`SameAs` witness graph
   under `enrichment`; compute merge-classes (`M(A,B)` objects), cached per the
   two-tier invalidation in `docs/SPEC.md` §4.5.
2. **Order** — for each merge-class, order claims: intra-`AuthorId` by log
   revision (strict); cross-author by the union of attested `cites` and
   `RelationProvider`-computed edges (`docs/SPEC.md` §6), never an imposed clock.
3. **Reduce** — compute the live set as the maximal antichain of unsuperseded
   claims under `enrichment` (retractions/rejections applied here).
4. **Contest** — classify each merge-class's status as
   `Settled{x} | Confirmed{x, by:[...]} | Contested{resolved:[...], open:[...]}`.

`render` then applies `RenderPolicy` to flatten stage 4's output for display —
this is the *only* lossy step; the store never sees it.

### `RelationProvider` trait

```rust
trait RelationProvider {
    fn relations(&self, claims: &ClaimSet, substrate: &GitSubstrate) -> Vec<ComputedEdge>;
}

struct GitAncestry;   // claims anchored to git objects inherit git's DAG ordering
struct GitSameFile;   // claims touching the same file/lines get About-strength edges
```

Both are default-on and high-trust, but named inputs a `TrustBase` can
down-weight or disable (`docs/SPEC.md` §6.2).

### CLI surface

| Command | Maps to |
|---|---|
| `kan observe "<text>" [--cites <cid\|path>...] [--subject <ref>]` | append `ClaimBody::Observation` |
| `kan plan "<text>" [--cites ...] [--subject ...]` | append `ClaimBody::Plan` |
| `kan decide "<text>" [--cites ...] [--subject ...]` | append `ClaimBody::Decision` |
| `kan resolve <subject> "<text>"` | append `ClaimBody::Resolution` |
| `kan same <a> <b>` | append `ClaimBody::Relation{kind: SameAs, target: b}` on subject `a` |
| `kan show <subject>` | fold + render a single subject's view |
| `kan issues` | fold + render the issue-like view across subjects |
| `kan status [<subject>]` | fold + render status classification |
| `kan session start` / `kan session end --notes "<text>"` | session lifecycle claims |
| `kan context [--budget N]` | budgeted context assembly (REQ-14) |
| `kan mcp` | start the MCP server over stdio (REQ-12) |

No `kan forget`/delete verb in v1 (REQ-11).

### MCP server

`kan mcp` exposes (exact tool boundary is Open Question Q3):
- a claim-append tool parameterized by kind (mirrors the CLI verbs above),
- a budgeted-context tool implementing REQ-14/AC-7.

## Resolved (formerly Open Questions)

### Q1: `atrium-repo`/`atrium-crypto`/`atrium-identity` API fit — RESOLVED, fits
Spiked against the real source (not just crates.io metadata) on 2026-07-16.
Confirmed:
- `atrium_repo::Repository::create(db, did)` builds a **new** repo from
  scratch (not just reading a hosted one) — returns a `RepoBuilder`.
- `Repository::add`/`Tree::add`/`update`/`delete` operate directly on the MST.
- Signing is **external**: `CommitBuilder::finalize(sig: Vec<u8>)` and
  `RepoBuilder::finalize(sig: Vec<u8>)` take a raw signature — no
  atproto-network dependency, plugs directly into an `atrium_crypto::Keypair`.
- `blockstore::CarStore` persists to a single on-disk CAR file over any
  `AsyncRead + AsyncSeek (+ AsyncWrite)` — exactly the "same on-disk artifact"
  local-only-and-future-sync property `docs/SPEC.md` §10 wants. `.kan/log/`
  is one CAR file.
- `atrium_crypto::keypair::Keypair::create(rng)` + `.sign(msg)` + the `Did`
  trait's `.did()` give did:key generation and signing directly — REQ-8/ADR-4
  implementable with no extra crate.
No roll-own fallback needed. See ADR-8.

### Q2: Token-budget estimation — RESOLVED, tiktoken-rs behind a trait
`tiktoken-rs` (v0.12.0, MIT) confirmed real and usable — BPE cl100k/o200k
encodings. Not model-exact for every consumer, but a consistent estimator is
sufficient for a soft budget. Wrapped behind a `TokenEstimator` trait so the
concrete tokenizer is swappable per-model later without touching call sites.
See ADR-9.

### Q3: MCP tool surface shape — RESOLVED, one tool per CLI verb
`rmcp`'s `#[tool]` + `#[tool_router]` macros make each tool a doc-commented
async method with a typed `Parameters<T: JsonSchema>` struct — boilerplate
per tool is near zero, which changes the calculus from what this doc originally
assumed. Went with one `#[tool]` per CLI verb (10 tools total), mirroring
REQ-13's CLI vocabulary 1:1: schema-typed params catch malformed `cites`/
`subject` before execution rather than after (protects the "provenance is
sacred" invariant on the write verbs), and kan's surface is deliberately
capped small enough (~10 verbs) that this isn't the regime where narrow-tool
sprawl becomes a problem. See ADR-10 for the alternatives considered
(query-tool consolidation for reads only; single CLI-passthrough tool).

## Out of Scope

- Sync of any kind (`HostedRelay`, `AtProto` transport, firehose, lexicons) —
  `docs/SPEC.md` §11.
- TUI, web dashboard, editor extensions — `docs/SPEC.md` §11.
- More than 2 trust policies, config presets, enforcement hooks — `docs/SPEC.md` §11.
- Incremental/streaming fold — reference recompute first, `docs/SPEC.md` §11.
- `kan.dev`/`kan.cat` domain and PDS deployment — `docs/SETUP-TODO.md` Phase 1/5,
  a separate, parallel track.
- Hard-delete CLI verb — storage-layer support only in v1 (REQ-11).
