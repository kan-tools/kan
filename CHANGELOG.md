# Changelog

All notable changes to kan are recorded here.

Every release so far is a **beta prerelease** (`-beta.1`) published to
crates.io. kan is pre-1.0: the log format carries a stated compatibility
contract (`docs/SPEC.md` §7.1 — existing claim fields are frozen, new ones are
additive and optional, unknown claim kinds are preserved as verifiable opaque
claims), but the CLI surface is still moving.

This file was reconstructed from the git history, the release tags, and the
issues closed in each release window. The authoritative record of *why* each
decision was made is `docs/DECISIONS.md`; the ADR numbers below point into it.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

Nothing here changes the binary: both entries are the verification harness.

- The migration matrix selects its historical writers by **content**, not by
  ref name — a tag is a writer iff it builds something other than this build
  (ADR-91). This is what kan#205 turned out to be: a cell whose writer and
  reader compiled from the same source put one binary in both roles and
  scored `ok`, which looked like nondeterminism for two days.
- `keychain-blocked` is renamed `keychain-modal`, and every keychain row is
  pinned to the blocked side. Nothing prevents the read; the OS waits on a
  human decision a headless runner cannot make, and a permanently red gate
  is one nobody reads (ADR-78).

## [v0.12.0-beta.4] — 2026-08-11

**kan owns its MST.**

### Changed

- The merkle search tree moves in-tree to `src/mst/`.
  `atproto-repo` 0.14.5's `insert_recursive` computed each key's layer,
  discarded it into `_target_height`, and never recursed — so every key
  landed in one flat root node rewritten in full on every insert. That is
  ~52n² CAR growth, a hard write-failure cliff at ~1,431 claims against
  `atproto-dasl`'s 100 MiB cap, and a root CID no conformant implementation
  agrees with ([#204](https://github.com/kan-tools/kan/issues/204), ADR-90).
  Measured at 800 claims: **274 ms/append against 430 ms, CAR 3.1 MB against
  32.4 MB**, growth linear rather than quadratic.
- The house rule for storage crates widens from one check to two:
  reachability (ADR-11/12) asks *did we lose data*, conformance asks *is what
  we wrote the thing we claim it is*. `atproto-repo` 0.14.5 passed the first
  cleanly. `tests/mst_conformance.rs` pins our root CID against
  `@atproto/repo` 0.10.10's **output**, not against our reading of the spec —
  which earned its keep immediately, because our first spec-derived reference
  used the wrong layer convention and was confidently wrong.

### Added

- A read says so when a claim is present but unreachable, rather than
  returning a quietly short answer.
- The migration matrix **writes** as well as reads, so an upgrade write is
  exercised rather than assumed.

### Note

- Vendoring plus `[patch.crates-io]` was tried and rejected: a `[patch]`
  section is honoured only in the root manifest of the crate being *built*,
  so it fixes local and CI builds while leaving `cargo install kan` broken.
  `Cargo.toml` and `Cargo.lock` are unchanged; `atproto-repo` remains for
  `Commit`, `RecordPath` and `compute_cid`.

## [v0.12.0-beta.3] — 2026-08-10 — review fixes

A full six-dimension cold review (`review/full-pass-v0.12`,
`.design/v0.12.0-beta.3-review-fixes.md`) found one data-loss blocker and a
set of contract, safety, and honesty defects. All fixes ship with a test
that fails without them.

- **Data loss (blocker):** a writer that opened while the log was recovering
  a missing `HEAD` — which includes every concurrent first-append to a fresh
  workspace — rewrote `HEAD` to its stale recovered lineage under the lock,
  stranding claims other writers had committed in between. It now re-reads
  and prefers the on-disk root when walkable.
- **Recovery honesty:** repairing a damaged CAR keeps the pre-repair file
  aside, and the recovery messages no longer claim "no claim was lost" when a
  mid-file corruption may have dropped later blocks. A zero-byte CAR gets a
  named refusal instead of a raw decoder error.
- **Transport robustness:** a malformed record in the tracked `.claims/`
  directory now warns and is skipped instead of panicking every command in
  every clone (integer-overflow and UTF-8-boundary faults, pre-verification).
- **MCP vocabulary:** enum parameters accept the kebab-case values every tool
  description teaches (PascalCase kept as aliases), and caller mistakes
  surface as `invalid_params` rather than `internal_error`.
- **Trust honesty:** a `--trust` weight below 1.0 warns that weights are not
  yet folded; the surface no longer implies weighted composition it does not
  perform.
- **Silent writes:** `kan observe <existing-subject>` with the text forgotten
  is refused instead of recording the subject name on `general`, and
  `kan publish <typo>` on a subject with no claims is refused instead of
  minting one.
- **Fold ordering:** the fold orders by `(rev, cid)` so it is a function of
  the claim set, not its enumeration order; retracting a
  retraction-of-a-retraction correctly reinstates the first; and `kan show`
  classifies supersession under the same computed edges `kan status` uses.
- **Hardening & docs:** claim-derived git SHAs are validated as hex before
  reaching `git`; several errors drop internal tokens for actionable text;
  and `docs/SPEC.md` §2/§4.2/§5.1.1/§7/§11, the README (new quickstart, the
  v0.12 identity model), `CLAUDE.md`, and `docs/SETUP-TODO.md` were corrected
  against the shipped code.

## [v0.12.0-beta.2] — 2026-08-10

**The keychain axis measures again, and refuted its own model.**

- The migration matrix's keychain cell now **opts in**, as REQ-3 asks an
  operator to. A v0.12+ writer roots in a plaintext seed and never reaches
  the keychain on its own, which had quietly turned that axis green while
  measuring nothing — the cell asked for a plane it never touched and scored
  `ok` for it.
- beta.1's four keychain rows convert PREDICTED → MEASURED, **and the
  prediction was wrong**. The control that proves it is in the same run.

## [v0.12.0-beta.1] — 2026-08-09

**The at-rest flip, and role declarations.**

### Changed

- **The signing key defaults to a plaintext `0600` seed file**, and the OS
  keychain becomes opt-in via `kan identity protect` / `unprotect`
  ([#183](https://github.com/kan-tools/kan/issues/183), ADR-87 — kan follows
  the ssh model: a key on disk with file permissions, not a vault a headless
  process cannot open).
- Identity resolution is specified as three functions, one question each
  (ADR-88), replacing the accreted patching of the previous milestones.
- The role registry moves out of `.kan/roles` and into the log;
  `ClaimBody::RoleDeclaration` is the schema change that carries it
  ([#200](https://github.com/kan-tools/kan/issues/200)).

### Added

- A declared MSRV, with a CI job that keeps the declaration true.
- OSS infrastructure: issue templates and a field-report label.
- A keychain axis on the migration matrix — on Linux both existing modes
  degrade to a plaintext key, so the OS-keychain plane where #90, #96, #107
  and #170 all lived had never been executed by any cell.

### Fixed

- Every identity-minting path now routes through one function, so a path that
  forgets the second-identity guard cannot exist
  ([#180](https://github.com/kan-tools/kan/issues/180)).
- `kan identity adopt` runs without the identity it repairs, and actually takes
  effect rather than reporting success while the keychain keeps signing
  ([#153](https://github.com/kan-tools/kan/issues/153)).
- The read-side resolver consults the keychain, so `--trust me` works on the
  default macOS layout ([#170](https://github.com/kan-tools/kan/issues/170)).
- `kan show` no longer spends 141 s computing `GitAncestry` edges it discards —
  8,540 git subprocesses per read, on a real log
  ([#181](https://github.com/kan-tools/kan/issues/181)).
- The keychain hang is re-scoped to its actual cause: kan's binaries are
  unsigned, so a macOS "Always Allow" grant never matches after a rebuild
  ([#96](https://github.com/kan-tools/kan/issues/96),
  [#69](https://github.com/kan-tools/kan/issues/69)).

## [v0.11.0-beta.1] — 2026-08-05

The identity surface. Identity resolution stopped being patched and got
specified.

### Added

- `TrustBase::Local` becomes the default trust base, with a `--trust` vocabulary
  (`me`, `roles`, `local`, a DID with optional weight) over it.
- The index table is versioned, so two kan binaries can share a workspace.
- A golden fixture freezing single-author read output.

### Changed

- **A read resolves no identity and computes no git anchor.** This removed a
  ~28 ms `genesis()` cost from every read, stopped reads minting identities, and
  stopped an MCP read blocking on a keychain prompt nobody can answer.
- A workspace's identity now comes into being at its first *write*, and subject
  names are validated before anything is minted — on the MCP surface too.
- `kan identity adopt` and `kan identity authors` run without `KAN_IDENTITY_FILE`.

### Fixed

- Two write-path projection bugs exposed by the freshness test, and a flaky
  ancestry-cache assertion.

## [v0.10.0-beta.1] — 2026-08-01

Relations and read honesty (ADR-82).

### Added

- `RelationKind::Supersedes` and `RelationKind::Refutes`
  ([#116](https://github.com/kan-tools/kan/issues/116)).

### Fixed

- `kan status --json` emitted an extra subject whose name was every other
  subject name newline-joined
  ([#144](https://github.com/kan-tools/kan/issues/144)).
- In a git repo with no commits, every verb failed with a raw `git rev-list`
  error and minted a workspace before failing. It now names the requirement and
  writes nothing ([#141](https://github.com/kan-tools/kan/issues/141)).
- `show --all` is documented and test-pinned as **all-or-nothing**: a subject is
  never silently omitted (ADR-81,
  [#143](https://github.com/kan-tools/kan/issues/143)).

## [v0.9.2-beta.1] — 2026-08-01

The corruption fixes (ADR-78).

### Fixed

- `KAN_NO_KEYCHAIN` bypassed the second-identity guard, reopening
  [#90](https://github.com/kan-tools/kan/issues/90) through the escape hatch
  added to make the keychain avoidable
  ([#146](https://github.com/kan-tools/kan/issues/146)). The guard is now stated
  once rather than per-mechanism, and ADR-77 records the rule: an escape hatch
  may not bypass a data-safety guard.
- A read under a declared role identity permanently bricked a workspace that had
  published its own claims. The overlay no longer ingests what the log already
  holds, and an already-poisoned workspace recovers instead of refusing to open
  ([#150](https://github.com/kan-tools/kan/issues/150)).
- Refusal messages name a remedy that can actually be run.

## [v0.9.1-beta.1] — 2026-07-30

The bulk read (ADR-72).

### Added

- `kan show --all --json` — one invocation returning every subject. The cost
  being measured as fixed process startup is what made this the right fix:
  41 invocations took 1.33 s, one takes 0.06 s
  ([#123](https://github.com/kan-tools/kan/issues/123)).

## [v0.9.0-beta.1] — 2026-07-30

Durability you can use, and one root of trust (ADR-69).

### Added

- `kan restore` rebuilds a log from the published `.claims/` tree, refusing if
  nothing in it was signed by this identity — because that is what a lost key
  looks like from the inside (ADR-63, ADR-64).
- A durability column on `kan status`: per subject, `unpublished`, `published`
  or `stale`, compared against the file rather than a timestamp.
- `kan identity adopt` — verify before switching, never destroy a root.
- A derived X25519 encryption key, rooted in the signing key.
- Seed-rooted new identities, with existing key-rooted ones grandfathered.
- A CI migration matrix: every released kan's workspace, read by this build.

### Fixed

- A blocking keychain read now says what it is waiting on
  ([#90](https://github.com/kan-tools/kan/issues/90)).

## [v0.8.0-beta.1] — 2026-07-30

The reader, the trust surface, multi-role (ADR-62). The release where sharing
started working in both directions.

### Added

- **The reader.** `Workspace::open` reads the tracked `.claims/` tree, verifies
  each record against its own author, and ingests foreign-authored ones into an
  overlay beside the log. A clone can now fold claims its own log never wrote
  ([#97](https://github.com/kan-tools/kan/issues/97),
  [#114](https://github.com/kan-tools/kan/issues/114)).
- **Multi-role writes by declaration** — `kan identity role add <name>`, plus
  `--trust roles` to read every declared role's claims attributed
  ([#115](https://github.com/kan-tools/kan/issues/115)).
- **The `PeerContested` trust surface**, and a view that states its own frame.
- Every read reports what its trust base excluded (`excluded_by_trust`), so a
  partial view cannot pass for a complete one (ADR-57).
- The `--json` contract is pinned by test rather than by intention.

### Changed

- Durability and identity architecture designs landed as ADR-54 and ADR-55
  ([#88](https://github.com/kan-tools/kan/issues/88),
  [#93](https://github.com/kan-tools/kan/issues/93),
  [#105](https://github.com/kan-tools/kan/issues/105)).
- The repository went public as of v0.7.1-beta.1 (ADR-56).

### Fixed

- `show --json` returns inbound edges as structured claims, not rendered strings
  ([#103](https://github.com/kan-tools/kan/issues/103)).
- `publish` refuses to overwrite a file that is not entirely this subject's,
  keyed on contents rather than a lossy 32-bit filename digest
  ([#111](https://github.com/kan-tools/kan/issues/111)).
- A macOS-gated test asserts a different-key plaintext file survives a keychain
  hit ([#112](https://github.com/kan-tools/kan/issues/112)).

## [v0.7.1-beta.1] — 2026-07-23

Wave 1 ergonomics, phrase security, `.claims/` migration (ADR-53).

### Added

- `kan --version` ([#100](https://github.com/kan-tools/kan/issues/100)).
- Every claim-writing verb accepts its subject **positionally or as
  `--subject`**; giving both is refused rather than silently resolved, and a
  missing subject names both forms and quotes the text back so a long claim
  need not be retyped ([#78](https://github.com/kan-tools/kan/issues/78),
  [#94](https://github.com/kan-tools/kan/issues/94),
  [#101](https://github.com/kan-tools/kan/issues/101)).

### Fixed

- **`kan identity restore` no longer takes the recovery phrase as argv**, where
  it landed in shell history, `ps` output and agent transcripts
  ([#104](https://github.com/kan-tools/kan/issues/104)).
- A v0.6 `.claims/` file verifies again, and republishing retires it instead of
  orphaning it beside a new one
  ([#107](https://github.com/kan-tools/kan/issues/107)).
- The re-review's REDIRECT findings: data loss in the migration fix, and a
  tautological key guard that never read the file it claimed to compare
  (ADR-52). ADR-52 also makes the lossy-key rule permanent.
- The test SPEC §7.1 mandated and did not have — a *known* kind carrying an
  unknown field, round-tripped through GitTree
  ([#95](https://github.com/kan-tools/kan/issues/95)).

## [v0.7.0-beta.1] — 2026-07-22

The correctness release (ADR-51). Roughly twenty defects from three adversarial
reviews, about half of them destroying data.

### Added

- **`--json` on the read verbs** — kan's prose stops being an accidental API
  (ADR-50).
- **`recorded_at` inside `ClaimContent`** — the observer's clock, signed and
  inside the CID, ending silent claim loss when one author recorded identical
  content twice (ADR-48, [#67](https://github.com/kan-tools/kan/issues/67)).
- `RelationKind::InTensionWith`, asserted directed and read symmetric
  ([#60](https://github.com/kan-tools/kan/issues/60)).
- Encrypted at rest by default, a recovery phrase, and an actionable
  stale-binary error.
- `publish --all`.
- `KAN_IDENTITY_FILE`, naming a key file directly so the keychain is never
  consulted ([#99](https://github.com/kan-tools/kan/issues/99)).

### Changed

- **`KAN_AGENT` was removed rather than repaired.** It hashed an environment
  variable into `AuthorId.agent`, and since `Solo` trust compares whole
  `AuthorId`s it **silently partitioned the log** — kan's own shipped
  `.mcp.json` set it, so the agent and human surfaces read disjoint views of one
  log, each reporting a complete-looking view.
- Read surfaces tell the truth about the log: `kan show` exposes `cites`,
  `artifacts`, author and recorded-at, and resolves a CID
  ([#61](https://github.com/kan-tools/kan/issues/61)).
- The `merge=union` guidance is withdrawn — it destroys both sides (ADR-47).

### Fixed

- GitTree trust: authenticated headers, deletion detection, injective
  filenames, byte-exact bodies, uninjectable records.
- Appends are serialized and the root pointer is durable.
- A damaged log is recovered rather than bricked on.
- `kan issues` listing fully-retracted subjects could not be reproduced under
  any trigger and was closed as not-reproducible rather than "fixed"
  ([#62](https://github.com/kan-tools/kan/issues/62)).

## [v0.6.0-beta.1] — 2026-07-21

### Added

- **The GitTree transport** — the committed tree as a sharing layer. Signed
  claims serialized into a tracked `.claims/` directory, verified by CID re-hash
  plus signature check (ADR-43,
  [#63](https://github.com/kan-tools/kan/issues/63)).
- **Schema evolution as a stated contract** (ADR-44, `docs/SPEC.md` §7.1):
  unknown claim kinds are preserved as opaque, CID-verifiable claims rather than
  skipped or rejected, and `deny_unknown_fields` turns a silently-dropped struct
  field into an honest error
  ([#66](https://github.com/kan-tools/kan/issues/66)).

### Changed

- The companion tool [`day`](https://github.com/kan-tools/day) exists and is
  recorded as ADR-42 ([#24](https://github.com/kan-tools/kan/issues/24),
  [#48](https://github.com/kan-tools/kan/issues/48)).

## [v0.5.0-beta.1] — 2026-07-20

### Added

- The `Transport` trait and `LocalOnly`.

### Changed

- Documentation caught up with CLI vocabulary and status framing that had gone
  stale across v0.2–v0.4.

## [v0.4.0-beta.1] — 2026-07-20

### Added

- `kan result <subject> <text>`, writing `ClaimBody::Result` — kept rather than
  removed, because the distinction from `Observation` and `Resolution` is real
  (ADR-36, [#41](https://github.com/kan-tools/kan/issues/41)).
- A subject-naming similarity nudge on write verbs: a non-blocking warning when
  a subject name normalizes to an existing one but is not spelled identically,
  catching the `f1-c1` / `F1-C1` / `f1_c1` fork reported in
  [#47](https://github.com/kan-tools/kan/issues/47) (ADR-38).

### Changed

- `Workspace::open` skips the index rebuild when the log's root CID matches what
  the index was built from — content-addressing proving the log has not changed,
  not a heuristic (ADR-37,
  [#26](https://github.com/kan-tools/kan/issues/26)).
- The sync-layer architecture, staging plan and version roadmap through 1.0
  landed as ADR-35.

## [v0.3.0-beta.1] — 2026-07-19

### Added

- **`kan relate <a> <kind> <b>`** for the five non-identity `RelationKind`s.
  `Rejects` turned out not to belong in `RelationKind` at all and was reshaped
  into its own `ClaimBody::Rejects`, with a `kan reject` verb and a trust-gated
  fold (ADR-29, [#31](https://github.com/kan-tools/kan/issues/31)).
- `--title`/`--kind` construct `ClaimBody::Subject` claims (ADR-30,
  [#32](https://github.com/kan-tools/kan/issues/32)).
- `--status` generalizes the narrative+status pairing to `observe`/`plan`/`decide`.

### Changed

- The verb lexicon is reorganized by AX phase, and the MCP tool surface catches
  up to the CLI (ADR-32).

### Fixed

- `kan issues` listed `spine` — a subject never resolved but never opened — as
  open. `SubjectKind` now carries real behavioural weight.
- `GitAncestry::relations` caches `is_ancestor` results per call, turning n²
  claim-pairs into k² commit-pairs (ADR-33,
  [#27](https://github.com/kan-tools/kan/issues/27)).

## [v0.2.0-beta.1] — 2026-07-17

The release that made three fully-built, fully-tested, unreachable subsystems
reachable.

### Added

- **The signing key moves to the OS keychain** (ADR-25,
  [#6](https://github.com/kan-tools/kan/issues/6)).
- Write-surface completion: `resolve`/`block` pair-write a `Status` claim,
  plus `retract`, `mark` and `cites`
  ([#21](https://github.com/kan-tools/kan/issues/21)).
- Git artifact auto-attachment — `ArtifactRef::Commit(HEAD)` by default, `--file`
  on top, so the computable-relation providers finally have data
  ([#22](https://github.com/kan-tools/kan/issues/22)).
- Subject claims exposed as an MCP resource, `kan://claims/{subject}`
  ([#28](https://github.com/kan-tools/kan/issues/28)).
- Witness provenance through the fold.

### Fixed

- `SameAs` where either side is an `Anchor` is rejected as a witness, enforcing
  SPEC §5.1's admissibility invariant
  ([#23](https://github.com/kan-tools/kan/issues/23)).

## [v0.1.1-beta.1] — 2026-07-17

First release. The local-only spine: claim substrate through budgeted context
assembly.

### Added

- **M1** — the claim substrate: types, DAG-CBOR CIDs, signing, append-only log.
- **M2** — a disposable SQLite index and a trivial local-only fold.
- **M3** — the minimal CLI.
- **M4a** — the identity fold: `SameAs`, merge-classes, `kan same`.
- **M4b** — the state fold, git-genesis anchors, `RelationProvider`s, `kan resolve`.
- **M5** — budgeted context assembly and the MCP server.
- **M6** — fixtures and polish, plus an agent-experience pass and the
  kan/companion-tool scope boundary (ADR-18).

### Changed

- **The storage layer switched from `atrium-repo` to `atproto-repo`** (ADR-12).
  `atrium-repo`'s MST silently and permanently lost previously-inserted entries
  — about 24% of random key sequences lost data within 20 sequential inserts.
  Filed upstream as [atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343)
  and recorded as ADR-11 ([#5](https://github.com/kan-tools/kan/issues/5)).

### Fixed

- `Log::append` writes only new blocks instead of rewriting the whole CAR file,
  so append latency stopped scaling with log size — flat at ~4–6 ms as the file
  grew from 817 B to 229 KB across 60 appends (ADR-13,
  [#8](https://github.com/kan-tools/kan/issues/8)).
- Cross-author `Retraction` was never gated by same-author or by trust.

[Unreleased]: https://github.com/kan-tools/kan/compare/v0.12.0-beta.4...HEAD
[v0.12.0-beta.4]: https://github.com/kan-tools/kan/compare/v0.12.0-beta.3...v0.12.0-beta.4
[v0.12.0-beta.3]: https://github.com/kan-tools/kan/compare/v0.12.0-beta.2...v0.12.0-beta.3
[v0.12.0-beta.2]: https://github.com/kan-tools/kan/compare/v0.12.0-beta.1...v0.12.0-beta.2
[v0.12.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.11.0-beta.1...v0.12.0-beta.1
[v0.11.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.10.0-beta.1...v0.11.0-beta.1
[v0.10.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.9.2-beta.1...v0.10.0-beta.1
[v0.9.2-beta.1]: https://github.com/kan-tools/kan/compare/v0.9.1-beta.1...v0.9.2-beta.1
[v0.9.1-beta.1]: https://github.com/kan-tools/kan/compare/v0.9.0-beta.1...v0.9.1-beta.1
[v0.9.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.8.0-beta.1...v0.9.0-beta.1
[v0.8.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.7.1-beta.1...v0.8.0-beta.1
[v0.7.1-beta.1]: https://github.com/kan-tools/kan/compare/v0.7.0-beta.1...v0.7.1-beta.1
[v0.7.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.6.0-beta.1...v0.7.0-beta.1
[v0.6.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.5.0-beta.1...v0.6.0-beta.1
[v0.5.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.4.0-beta.1...v0.5.0-beta.1
[v0.4.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.3.0-beta.1...v0.4.0-beta.1
[v0.3.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.2.0-beta.1...v0.3.0-beta.1
[v0.2.0-beta.1]: https://github.com/kan-tools/kan/compare/v0.1.1-beta.1...v0.2.0-beta.1
[v0.1.1-beta.1]: https://github.com/kan-tools/kan/releases/tag/v0.1.1-beta.1
