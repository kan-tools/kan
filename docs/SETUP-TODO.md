# kan — Dev Setup TODO

*Getting from "name planted" to "building the spine." Ordered so nothing blocks on something later. Check off as you go.*

> **Status:** Historical bootstrap checklist. Phases 0–4 explain how the
> shipped local spine was assembled. Current network/publication work is
> governed by `docs/ROADMAP.md` and RFC 3; the active items in Phases 5–6 below
> point to that issue graph rather than preserving the original `dev.kan.*` /
> `did:plc` sketch as a plan.

---

## Phase 0 — Reserve & scaffold (mostly done)

- [x] Confirm crate name free (`cargo search kan`)
- [x] Reserve crate name (`cargo publish` a `0.0.0` stub)
- [ ] Create GitHub repos on a clean namespace (no `forecast-bio` / Kira):
  - [x] `kan` — the crate (public) — `github.com/kan-tools/kan`
  - [x] `kan-lexicon` — Lexicon source and fixtures (public)
  - [ ] `kan-appview` — portable reference AppView (public; issue #239)
  - [ ] `kan-infra` — Railway/atproto ops (**private**)
- [x] Push stub `lib.rs` + real `README.md` so the parked repo reads as WIP, not abandoned
- [x] Pick license (`MIT`) and add `LICENSE`

## Phase 1 — Namespace authority

- [ ] Complete issue #237: `_lexicon.kan.tools` resolves exactly to
      `did=did:web:kan.tools`.
- [ ] Host `https://kan.tools/.well-known/did.json` outside Railway and bind it
      to the authoritative PDS service endpoint.
- [ ] Keep other domains, handles, and service DIDs separate from Lexicon
      authority unless an accepted RFC explicitly joins their lifecycles.

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

**Not part of the local spine:** sync/atproto/lexicons, TUI, web dashboard,
VS Code extensions, >2 enrichments, enforcement hooks, incremental fold.
Separately governed follow-on work is listed in `docs/ROADMAP.md`.

**Smell test:** local-only path must be *dramatically* simpler than multi-actor. If it isn't, the abstraction is wrong.

## Phase 4 — Tests (write alongside Phase 3, not after) — DONE

- [x] Fixture: local-only trivial case (one log, latest-wins) — `tests/index_and_fold.rs::ac3_local_only_smell_test`
- [x] Fixture: two-actor contested status (the poset/antichain case) — `tests/state_fold.rs::ac4_contested_under_peer_settled_under_solo`
- [x] Fixture: `SameAs` merge + retraction-split (witness retention + component re-derivation) — `tests/identity_fold.rs::ac5_sameas_merges_then_retraction_resplits`
- [x] Property: `fold` is deterministic in (claim set, enrichment) — `tests/fold_determinism.rs`
- [x] Guardrail test: identity component size > N flags instead of enumerating — `tests/identity_fold.rs::oversized_component_is_flagged`

## Phase 5 — Authority and recoverable infrastructure

- [ ] Complete #237's DNS/static-DID authority route.
- [ ] Complete #240's separate Railway staging and production environments.
- [ ] Deploy persistent PDS state, the private publisher, and a pinned public
      AppView artifact.
- [ ] Inventory credentials and recovery artifacts across GitHub, Railway,
      the PDS volume, and an independent protected vault.
- [ ] Keep an independently restorable recovery copy outside Railway and test
      full reconstruction before production promotion.

## Phase 6 — RFC 3 implementation

- [ ] #235 — `kan-atproto` wire boundary and claim-envelope migration.
- [ ] #236 — versioned `tools.kan.*` Lexicons and codec/lens registers.
- [ ] #237 — DNS and `did:web` namespace authority (parallel foundation).
- [ ] #238 — release-verified atomic publisher.
- [ ] #239 — portable reference AppView.
- [ ] #240 — Railway deployment and recovery.
- [ ] #241 — end-to-end release qualification and scheduled drift probes.

HostedRelay, firehose ingest, and hosted-private-scope product design remain
separate follow-ons; RFC 3 does not silently absorb them.

---

## Toolchain sanity (once, up front)

- [ ] Rust toolchain pinned (`rust-toolchain.toml`), `cargo clippy` + `cargo fmt` clean
- [ ] `justfile` or `Makefile` for `test` / `lint` / `fmt` / `run`
- [ ] CI: build + test + clippy on push
- [ ] Decide: use `kan` itself for its own issue tracking once it self-hosts (dogfood milestone 🎯)

---

## The one-line priorities

1. **Keep the shipped local spine and its read/write contract green.**
2. **Complete RFC 3 review; then start #235 and #237 in parallel.**
3. **Do not publish production state before #241's whole-route qualification.**
4. **Keep independent recovery material before sealing runtime credentials.**
