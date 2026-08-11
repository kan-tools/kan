# kan — Dev Setup TODO

*Getting from "name planted" to "building the spine." Ordered so nothing blocks on something later. Check off as you go.*

---

## Phase 0 — Reserve & scaffold (mostly done)

- [x] Confirm crate name free (`cargo search kan`)
- [x] Reserve crate name (`cargo publish` a `0.0.0` stub)
- [ ] Create GitHub repos on a clean namespace (no `forecast-bio` / Kira):
  - [x] `kan` — the crate (public) — `github.com/kan-tools/kan`
  - [ ] `kan-infra` — Railway/atproto ops (**private**)
- [x] Push stub `lib.rs` + real `README.md` so the parked repo reads as WIP, not abandoned
- [x] Pick license (`MIT`) and add `LICENSE`

## Phase 1 — Domains

- [ ] Register **`kan.dev`** (or confirm) — the boring infra + lexicon-namespace root
- [ ] (optional) Register **`kan.tools`** as fallback namespace root
- [ ] Register **`kan.cat`** — handle alias + mirror site (the bit)
  - [ ] Fill the `.cat` declaration of intended use honestly (site presents content in Catalan among other languages)
  - [ ] Note: real Catalan content required — blurb drafted (`kan-landing-blurb-en-ca.md`), get a native-speaker pass

## Phase 2 — Hand the design spec to Claude Code

- [ ] Start a Claude Code session with:
  - [ ] `kan-design-handoff.md` (brief — read first)
  - [ ] `agent-memory-substrate-spec.md` (authoritative spec)
- [ ] Point it at the **`atproto-repo` crate** docs so it evaluates build-on vs. roll-own for MST/CAR/CID
- [ ] Ask it to resolve the two OPEN choices (body typing §12.1, retraction §12.2) with recommended defaults
- [ ] Expected back: crate layout, core Rust types, `fold` signature + 4-stage pipeline, `RelationProvider` trait + git-provider stubs, fixtures test plan, CLI command surface

## Phase 3 — First build (spine only — the v1 fence) — DONE, M1–M5

*Dependency order. This is the "one human, one agent, one repo, no sync" target.*

- [x] `Claim` struct + DAG-CBOR canonicalization + CID (content-excluding-sig) + signing (M1)
- [x] Local append-only signed log = source of truth (atproto-style record collection on disk) (M1, ADR-12/13)
- [x] Disposable SQLite index (pure projection; rebuildable) (M2)
- [x] The **fold**:
  - [x] identity fold (witness-retaining, NOT plain union-find; clique-cached) + `SoloTrust` + `PeerContested` (M4a)
  - [x] state fold (poset → maximal antichain → `Settled | Confirmed | Contested`) (M4b)
  - [x] identity-before-state, same enrichment; decategorify only at `render` (M4a/M4b)
- [x] Anchors (git: Workspace/Commit/Blob/FileAt/LineRangeAt) + admissibility invariant (M4b, ADR-14)
- [x] Computable relation providers: `GitAncestry` + `GitSameFile` (default-on) (M4b) — wired up and default-on; per-provider trust down-weighting/disabling (`docs/SPEC.md` §6.2) isn't built yet, see `src/relations.rs`'s doc comment
- [x] CLI (git-like verbs: `kan observe|plan|decide|block|resolve|result|same|relate|mark|retract|reject|show|status|issues|context|publish`) (M3/M4b/M5). Note: `session` was removed (ADR-18) — process/session concepts live in the companion tool `day`, not kan.
- [x] MCP server: claim-append + **budgeted context assembly** (the actual product) (M5, ADR-15)

**Do NOT build yet:** sync/atproto/lexicons, TUI, web dashboard, VS Code ext, >2 policies, enforcement hooks, incremental fold.

**Smell test:** local-only path must be *dramatically* simpler than multi-actor. If it isn't, the abstraction is wrong.

## Phase 4 — Tests (write alongside Phase 3, not after) — DONE

- [x] Fixture: local-only trivial case (one log, latest-wins) — `tests/index_and_fold.rs::ac3_local_only_smell_test`
- [x] Fixture: two-actor contested status (the poset/antichain case) — `tests/state_fold.rs::ac4_contested_under_peer_settled_under_solo`
- [x] Fixture: `SameAs` merge + retraction-split (witness retention + component re-derivation) — `tests/identity_fold.rs::ac5_sameas_merges_then_retraction_resplits`
- [x] Property: `fold` is deterministic in (claim set, enrichment) — `tests/fold_determinism.rs`
- [x] Guardrail test: identity component size > N flags instead of enumerating — `tests/identity_fold.rs::oversized_component_is_flagged`

## Phase 5 — Identity & infra (parallel track, `kan-infra` repo)

*Full detail in `kan-identity-infra.md`. Key ordering below.*

- [ ] Deploy PDS on Railway → `pds.kan.dev`, **persistent volume**, TLS verified
- [ ] Create account → obtain `did:plc:…` (NOT `did:web`)
- [ ] **⚠ Back up rotation keys offline, multi-location, before anything else**
- [ ] Set handle `kan.cat`; DNS TXT `_atproto.kan.cat`; verify bidirectional resolution
- [ ] Web deploy: `kan.dev` canonical + `kan.cat` mirror with Catalan toggle (static, not a PDS)
- [ ] Volume backups off-Railway + test CAR export
- [ ] Dry-run a PDS migration once (confirm DID/handle/repo survive)

## Phase 6 — Lexicons (only after the spine works locally)

- [ ] Design NSID tree under `dev.kan.*`: `claim`, `relation.sameAs`, `relation.blocks`, `trust.policy`, `subject.anchor`, …
- [ ] Then: `HostedRelay` transport → `AtProto` transport → firehose ingest → AppView = the fold over subscribed logs

---

## Toolchain sanity (once, up front)

- [ ] Rust toolchain pinned (`rust-toolchain.toml`), `cargo clippy` + `cargo fmt` clean
- [ ] `justfile` or `Makefile` for `test` / `lint` / `fmt` / `run`
- [ ] CI: build + test + clippy on push
- [ ] Decide: use `kan` itself for its own issue tracking once it self-hosts (dogfood milestone 🎯)

---

## The one-line priorities

1. **Repos + `kan.dev` + hand the spec to Claude Code.** (unblocks everything)
2. **Build the local-only spine.** (the actual product, one machine)
3. **Keys backed up before identity goes live.** (the survival invariant)
4. Everything else — sync, lexicons, `.cat` bit — is after the spine works.
