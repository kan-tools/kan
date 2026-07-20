# Feature: Sync layer architecture and staging plan

## Summary
kan's local-only spine (M1–M6, shipped through v0.3.0-beta.1) deliberately
deferred the multi-actor half of the original vision: `docs/SPEC.md` §10's
`Transport` trait sketch (`LocalOnly` → `HostedRelay` → `AtProto`) has never
been formalized in code — `store/log.rs` talks to local disk directly, with
no seam for a second transport to plug into. This doc is the staging plan
for issue #29's epic (sync/atproto layer), replacing that placeholder issue
with a concrete milestone sequence, each with its own future `/design` pass
where the work is genuinely undecided — plus one immediately buildable
slice: formalizing the `Transport` trait and making the current local-disk
path its explicit, tested `LocalOnly` implementation. Scope is kan's own
codebase only; `kan-infra` (PDS deploy, `did:plc`, domains), the companion
dev-tools plugin, and the kan website are explicitly out of scope, to be
bootstrapped by a later, separate design pass.

## Requirements
*(Milestone 0 only — the one slice this doc actually specifies for
implementation. Milestones 1+ are staged, not specified, below.)*

- REQ-1: `src/transport.rs` (new top-level module, peer of `relations.rs`/
  `workspace.rs`, not nested under `store/` — `Transport` is about *where*
  claims come from/go to, a different axis than `store/`'s *how they're
  persisted once here*) defines `trait Transport` per `docs/SPEC.md` §10's
  sketch, adapted from the spec's pseudocode (`fn publish(&self, &[Claim])`;
  `fn subscribe(&self, &[Did]) -> Stream<Claim>`) to kan's actual established
  conventions: `async fn`, `Result<_, Error>` returns, matching
  `store::log::Log::append`/`iter_all`'s existing shape — not a literal
  transcription of the spec's illustrative signatures.
- REQ-2: `LocalOnly` (in `src/transport.rs`) implements `Transport` by
  wrapping `store::log::Log`: `publish` delegates to `Log::append`.
  `subscribe` is **not a stub** — for `LocalOnly` specifically there is no
  other actor's log to subscribe to (one author, one log), so it correctly
  returns an empty/immediately-complete result. This is the honest answer
  for this transport, not a placeholder waiting to be filled in later.
- REQ-3: Zero change to `Workspace`'s public shape, `actions.rs`, the CLI,
  or MCP surface. `Transport`/`LocalOnly` are additive — not yet threaded
  through `Workspace` (which still holds a concrete `log: Log` field, as
  every existing test file that constructs `Workspace { .. }` directly
  already assumes). Wiring `Transport` into `Workspace` is deliberately
  deferred to Milestone 2 (`HostedRelay`), where a second real
  implementation exists to design the wiring against — guessing the
  wiring shape now, against only one implementation, risks getting it
  wrong the way `.design/kan-spine.md`'s Q1 spike (ADR-8) avoided by
  checking real crate source instead of assuming.
- REQ-4: `LocalOnly`'s behavior is proven equivalent to today's direct
  `Log::append`/`Log::iter_all` usage — same CIDs, same claim content —
  via a dedicated test, not asserted by inspection alone.

## Acceptance Criteria
- [ ] AC-1: `cargo build --workspace --all-targets` succeeds with
      `src/transport.rs` added and declared in `src/lib.rs`; no existing
      file outside the new module is modified.
- [ ] AC-2: `cargo test --workspace` — every existing test still passes
      unchanged (mechanically proves REQ-3's non-regression claim, not
      just "should be fine because nothing else was touched").
- [ ] AC-3: A new test appends claims through `LocalOnly::publish`, then
      reads them back (via `Log::iter_all` or an equivalent `LocalOnly`
      read path) and confirms CID/content equivalence to what appending
      directly through `Log::append` already produces today (REQ-4).
- [ ] AC-4: A new test confirms `LocalOnly::subscribe` on a freshly-created
      log returns an empty result with no panic and no hang (REQ-2 — proves
      "correct empty answer," not "unimplemented").

## Architecture

### Milestone 0 (specified above): `Transport` trait + `LocalOnly`
`src/transport.rs` sits at the same level as `relations.rs`/`context.rs`/
`workspace.rs` in `src/lib.rs`'s module list. `LocalOnly` wraps
`store::log::Log` (`src/store/log.rs`) — `Log::append`
(`src/store/log.rs:207`) and `Log::iter_all` (`:294`) already have exactly
the `async fn ... -> Result<_, Error>` shape `Transport`'s methods should
match, so this is adaptation of an existing pattern, not a new one.

**The M0 trait signature is not trying to be final.** `docs/SPEC.md` §10's
sketch is illustrative pseudocode; the real shape `HostedRelay` needs
(auth tokens, real streaming semantics, retry/backoff, partial-failure
handling across a network boundary) isn't knowable yet from `LocalOnly`
alone, and `HostedRelay`'s own `/design` pass (Milestone 2) may need to
widen the trait. M0's job is proving the *pattern* — a real seam exists,
`LocalOnly` is its first honest implementation, nothing downstream breaks
— not nailing a signature that survives every future transport unchanged.

### Milestones 1+ (staged here, specified later — each gets its own `/design` pass)

**Sequencing rationale** (resolved in this design session's interview,
superseding issue #29's "not a commitment, just what was originally
sketched" framing with an actual order and the reasoning behind it):

- **`HostedRelay` before `AtProto`**, per `docs/SPEC.md` §10's own listed
  order. `HostedRelay` is a protocol kan fully controls — no external
  PDS/firehose wire format to depend on. It's the cheaper way to prove
  "does AppView-as-fold-over-multiple-actors'-logs actually work" before
  also taking on `AtProto`'s entire external ecosystem surface (XRPC,
  firehose event-stream parsing, real PDS hosting). Confirmed during
  exploration: `atproto-repo`/`atproto-dasl` (the crates kan already
  depends on, ADR-1/ADR-11/ADR-12) provide MST/CAR/CBOR **repository
  structure only** — no PDS/XRPC networking client, no firehose
  subscription client exists anywhere in kan's current dependency tree.
  Every bit of `HostedRelay`'s and `AtProto`'s actual wire-protocol work is
  net-new build surface, confirmed by reading the crate source
  (`~/.cargo/registry/.../atproto-repo-0.14.5/src/lib.rs`), not assumed
  from crates.io's description.
- **Issue #7 (E2EE) needs its own `/design` pass before `HostedRelay`'s
  detailed protocol design begins**, not just before it ships. E2EE
  decides what `HostedRelay`'s wire format actually looks like (what's
  encrypted, what metadata the relay can see, how keys map onto
  `TrustBase`/`Enrichment`) — designing the transport assuming plaintext
  and retrofitting encryption later means redesigning the protocol, not
  extending it. This is the "sync design will fight the crypto design"
  risk #7's own issue text already names.
- **Issue #30 (real per-agent cryptographic identity) runs as an
  independent parallel track**, not a hard blocker for starting
  `HostedRelay`'s design or early build. The cross-*human* trust story is
  already cryptographically real today (`did:key`, ADR-4, verified by
  `sign::verify`) — `HostedRelay`'s "private teams" framing
  (`docs/SPEC.md` §10) is fundamentally about that layer. #30 fixes
  *sub*-identity within one human's account (agent vs. agent), which
  matters more once multiple agents collaborate through a
  network-exposed relay, not before. It should land before `HostedRelay`
  ships to real multi-agent use — a release gate, not a start gate.

**Staged order**, now mapped onto an actual version roadmap (resolved in a
follow-up session to this design pass — `docs/DECISIONS.md` records the ADR):

| Milestone | Scope | Version | Status |
|---|---|---|---|
| — | Unrelated small cleanup (#41 `ClaimBody::Result` reachability, #26 `Workspace::open` full-rescan perf, subject-naming fuzzy-match nudge from #47) — kept as its own release so each release stays one coherent theme, not folded into the sync epic | v0.4.0-beta.1 | Next up |
| M0 | `Transport` trait + `LocalOnly` (this doc, REQ-1..4) | v0.5.0-beta.1 | Specified, ready to build |
| M1 | Issue #7 `/design` pass — E2EE architecture, scoped to what constrains `HostedRelay`'s wire shape (not a full crypto implementation) | *(no version — design-only, feeds M3)* | Not started; can run in parallel with M0 |
| M2 | Issue #30 `/design` + build — real per-agent identity | v0.6.0-beta.1 | Not started; parallel track, gates M3 shipping, not M3 starting. Shipped *before* `HostedRelay` deliberately |
| M3 | `HostedRelay` `/design` pass + build, informed by M1's resolution. Threads `Transport` through `Workspace` for the first time (deferred from M0 per REQ-3) | v0.7.0-beta.1 | Not started; depends on M1 |
| **1.0** | *(stability declaration, not new scope)* — local-only spine + `HostedRelay` + real identity + E2EE, nothing left provisional (no more `KAN_AGENT`-style honest-but-temporary patches) | **v1.0.0** | Declared once v0.7's line is genuinely stable, not a fixed calendar target |
| M4 | `AtProto`/PDS/firehose transport, `docs/SPEC.md` §10.1's lexicon separation (`*.claim`/`*.relation.sameAs`/`*.trust.*`) | v1.x / v2 | Not started; depends on M3 proving the AppView/sync mechanics. Deliberately *not* a 1.0 blocker — `docs/SPEC.md` §10 frames `AtProto` as ecosystem expansion ("lexicons = evangelism"), `HostedRelay` as the core product ("the monetizable one") |

## Open Questions
None blocking M0. Every genuinely open architectural question surfaced
during this design pass (HostedRelay-vs-AtProto ordering, where #7/#30 sit
in the sequence, whether to formalize `Transport` now vs. wait, whether
`kan-infra`/website/companion-tool bootstrap belongs in this doc) was
resolved in conversation before this doc was written. M1/M2/M3/M4's own
internal design questions are explicitly *not* answered here — they're
staged as their own future `/design` passes, not guessed at.

## Out of Scope
- **`kan-infra` (PDS deployment on Railway, obtaining a real `did:plc`,
  `kan.dev`/`kan.cat` domain registration, key backup procedures)** —
  `docs/SETUP-TODO.md` already calls this "a parallel track, `kan-infra`
  repo." Explicitly confirmed out of scope for this doc during the design
  interview: infra/deployment planning is a different kind of decision
  than kan's own codebase architecture, and gets its own future design
  pass alongside the companion dev-tools plugin and kan website bootstrap.
- **The companion dev-tools plugin's repo bootstrap** (ADR-18's boundary
  rule; issues #24/#47/#48) — same future design pass as `kan-infra`, per
  this session's explicit scoping decision, not this one.
- **Issue #7's actual E2EE design** (what's encrypted, key management
  scheme) — staged as Milestone 1, its own `/design` pass, not decided
  here beyond its sequencing position.
- **Issue #30's actual identity-system design** (per-agent keypairs,
  SPIFFE/SPIRE-style research, revocation/rotation) — staged as Milestone
  2, its own `/design` pass, not decided here beyond its sequencing
  position.
- **`HostedRelay`'s and `AtProto`'s actual protocol/wire-format design** —
  staged as Milestones 3 and 4, their own future `/design` passes.
- **Wiring `Transport` into `Workspace`/`actions.rs`** — deferred to
  Milestone 3, once `HostedRelay` gives a second real implementation to
  design the wiring against (REQ-3).
- **Issue #15 (vector index)** — unrelated to the sync layer (a pure local
  read-projection, same category as the existing SQLite index), not
  folded into this epic.
