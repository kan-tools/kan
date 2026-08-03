# Feature: The identity surface — a read that needs no identity

## Summary

Four open issues (#149, #153, #90, #136) and one deferred decision (#121) are
one defect seen from five directions: **kan's default fold is defined in terms
of "me"**, so every read must resolve an identity to know whom to trust, and
everything downstream follows from that. Replacing the default with `Local` —
every author that has written in this workspace — removes the reason a read
needs an identity at all, and the four issues stop being separate fixes.

The consequence worth stating first: **#90's failure mode disappears rather
than being guarded against.** "A binary upgrade silently mints a new identity,
taking the whole log out of every read" is a description of `Solo`. Under
`Local`, a re-minted identity is a nuisance — the claims already in the log are
still authored by authors in the log, so they stay visible. The mint remains
wrong and the ADR-77 guard remains, but it stops being a data-visibility event.

For a single-author workspace this is a **no-op**: `Solo` and `Local` coincide.
kan's own log has exactly one author, as does day's. The default differs only
in the cases where today's answer is already wrong.

## Requirements

- REQ-1: `TrustBase` gains `Local` — every `AuthorId` appearing on a claim in
  `.kan/log` — and it becomes the base every read folds under when no `--trust`
  argument is given. It is computed from claims the fold already holds
  (`fold::excluded_by_trust` and `fold::fold` both take `&[(Cid, StoredClaim)]`),
  never from `Workspace::my_author`.

- REQ-2: No read path resolves, derives, or persists a signing identity.
  `Workspace` gains a read-only construction that opens `log`, `overlay` and
  `index` with no `Identity`, and every read verb (`show`, `status`, `issues`,
  `context`) uses it.

- REQ-3: A minted identity is persisted only after the write it was minted for
  has succeeded. A failed or refused write leaves no key, no `seed-id`, and no
  `identity-id` behind.

- REQ-4: `kan identity adopt` runs without `KAN_IDENTITY_FILE` set, in exactly
  the state that produces the ADR-77 refusal — it opens the workspace it is
  repairing without first resolving the identity it is repairing.

- REQ-5: The `--trust` vocabulary distinguishes four things, each doing one
  job: `local` (the default, every author in the log), `me` (the active
  identity alone — today's `Solo`), `roles` (only identities declared in
  `.kan/roles`), and `role:<name>` (one declared role, named rather than
  spelled as a `did:key:…`). A bare `did:key:…` continues to work unchanged.

- REQ-6: `.kan/overlay` authors are never members of `Local`. A claim that
  arrived as a committed `.claims/` file is disclosed by
  `fold::excluded_by_trust` but not folded, until admitted by an explicit
  `--trust`.

- REQ-7: Claims carrying a legacy `AuthorId { agent: Some(_) }` (v0.2–v0.6 with
  `KAN_AGENT` set) are visible under `Local` without any DID-matching special
  case, because those claims are in the log.

- REQ-8: The read envelope names `Local` as its base, in the same shape ADR-57
  established (`trust: {base, authors:[{did, weight}]}`), so a consumer reads
  which frame produced a view rather than assuming it.

- REQ-9: `local` minus `roles` is the set of authors present in the log but
  never declared. That difference is reachable from the CLI, because it is the
  signal that an unexpected identity has written here — the #90 and #136
  anomaly, surfaced as data rather than as an absence.

## Acceptance Criteria

- [ ] AC-1: A single-author workspace produces byte-identical `show`, `status`,
  `issues` and `context` output before and after the change, on both the human
  and `--json` surfaces except for the `trust.base` field. Covers REQ-1.

- [ ] AC-2: #121's reproduction — two role identities against one workspace,
  each appending to one subject — returns **both** claims under the default
  read, from either role and with no `--trust` argument. Covers REQ-1, REQ-5.

- [ ] AC-3: `kan status` in a git repo with a commit and no `.kan/` exits
  successfully, reports no subjects, and creates **no** `.kan/` directory, no
  key file and no `seed-id`. Covers REQ-2, REQ-3.

- [ ] AC-4: In the state that produces `WouldMintSecondIdentity` (log
  non-empty, no key file, `KAN_NO_KEYCHAIN` set), `kan identity adopt --key K`
  succeeds with `KAN_IDENTITY_FILE` unset, and a subsequent default read shows
  the log's claims. Covers REQ-4.

- [ ] AC-5: A workspace whose log contains claims authored under
  `AuthorId { did: D, agent: Some(h) }` and others under
  `AuthorId { did: D, agent: None }` returns **all** of them under the default
  read, with no `--trust` argument and no adopt step. Covers REQ-7.

- [ ] AC-6: A workspace holding a `.claims/` file authored by a DID that has
  never written to the log excludes those claims from the default read and
  reports them in `excluded_by_trust`; naming that DID in `--trust` includes
  them. Covers REQ-6.

- [ ] AC-7: `--trust roles` returns only declared identities, and in a
  workspace with an undeclared log author the `local` and `roles` results
  differ by exactly that author's claims. Covers REQ-5, REQ-9.

- [ ] AC-8: `show --all --json` and `status --json` report
  `trust.base == "Local"` by default, and every author they list is one with a
  claim in the log. Covers REQ-8.

- [ ] AC-9: A write refused by the ADR-77 guard, and a write that fails after
  identity resolution, both leave the workspace with no newly-persisted key,
  `seed-id` or `identity-id`. Verified by comparing the `.kan/` file set before
  and after. Covers REQ-3.

- [ ] AC-10: A workspace whose active identity has been re-minted (the #90
  shape: `identity-id` present, key absent, log non-empty) still returns every
  claim in the log under the default read. Covers REQ-1.

## Architecture

**`src/fold/trust.rs`** holds `TrustBase` (`Solo { trusted }`,
`PeerContested { weights }`) plus `SELF_ALIAS` (`me`) and `ROLES_ALIAS`
(`roles`). `Local` joins them as a third variant. `TrustBase::trusts(author)`
is the single predicate the fold consults (`trust.rs:166`), so `Local`'s
membership test lands there. Because `Local` is defined over the claim set
rather than over a stored author, the variant carries the author set computed
at fold entry rather than a reference to the workspace.

**`src/workspace.rs`** is where the coupling lives today.
`Workspace::solo_trust()` returns `TrustBase::solo(self.my_author())`, and
`my_author()` reads `self.identity.did()` — this is the line that makes a read
need an identity. `Workspace::open` currently resolves identity at line ~135,
before the log is even opened; v0.10.0 already moved `GitSubstrate::open` and
`genesis()` ahead of it for #141, which is the same reordering this extends.
The read-only construction (REQ-2) opens `log`, `overlay` and `index` and skips
`Identity::load_or_create_for_workspace` entirely.

`ingest_published` is the boundary REQ-6 rests on: it skips records whose
author matches the active identity and ingests the rest into `overlay`. Note
that this function *does* consult identity — under a read-only open it must
either be skipped (the overlay is already populated from prior opens) or use a
membership test against the log rather than against "me". The latter is
preferable and is a small generalisation of the fix v0.9.2 already made for
#150, which replaced part of that author test with a log-membership check.

**`src/sign.rs`** holds `Identity::load_or_create_for_workspace`,
`load_or_create`, the four minting paths, and `refuse_second_identity`
(ADR-77). REQ-3 changes *when* `save`/`Seed::create` persist, not whether the
guard applies. The guard stays: minting a second identity is still wrong, it
simply stops being catastrophic.

**`src/actions.rs`** holds `adopt_identity(ws: &Workspace, key_path)`, whose
`&Workspace` parameter is the whole of #153 — it forces `Workspace::open`, and
with it identity resolution, before adopt can repoint anything. Under REQ-2 it
takes the read-only workspace instead. `status`, `show`, `show_all_json`,
`status_json`, `issues` and `context` are the read verbs to move.

**`src/cli/mod.rs`** and **`src/mcp.rs`** carry the `--trust` surface and its
MCP mirror. REQ-5's `role:<name>` spelling parses in `Workspace::trust_from`,
which is the only layer that reads `.kan/roles` — `fold` never reads a file
(`trust.rs:44-47`).

**`.kan/roles`** (`sign.rs:ROLES_FILE`) survives for the one thing it uniquely
holds: the binding from a `did:key:…` to a human name. Membership becomes
derivable from the log; naming never was.

**Tests.** `tests/multi_role.rs` already carries #121's reproduction shape and
the role/publish flow; `tests/guard_every_minting_path.rs` carries the four
minting paths and the adopt-remedy check; `tests/write_guards.rs` carries the
"nothing was written" assertions AC-9 extends; `tests/trust_surface.rs` covers
`--trust`. AC-1's byte-identical claim wants a fixture workspace and a
golden-output comparison rather than a hand-written assertion.

## Resolved Questions

Each bullet is the decision as recorded; the prose beneath is the reasoning.

- RQ-1: A read with no `--trust` argument shows **every author in `.kan/log`** —
  the new `Local` base. `Solo` is the reason a read needs an identity at all, so
  #149 cannot be fixed while `Solo` is the default. Keeping `Solo` and merely
  making identity resolution non-persisting was rejected: it leaves
  `excluded_by_trust` as the load-bearing safety mechanism, and that is one line
  of stderr standing between a user and the failure class kan keeps
  re-encountering.

- RQ-2: The default draws its boundary at **the log only; overlay authors
  require explicit admission**. The first framing was answered on the reasoning
  that `Solo` defends against foreign claims arriving over *sync*, which does
  not exist yet — but that premise is half wrong. Foreign claims already arrive
  without sync, as `.claims/` files committed to the repo and ingested into
  `.kan/overlay`, so a merged pull request carrying a claims file would
  otherwise inject a stranger's claims into the maintainer's default view. The
  line is not a storage convenience: **the log is what was written *through*
  this workspace, the overlay is what *arrived at* it as a file.** Those are
  different acts, and the difference is the trust-relevant one.

- RQ-3: `--trust roles` becomes a **narrowing rather than a widening** — "only
  the identities I declared", not "everything this workspace wrote". Under
  `Local` the registry's membership is derivable from the log, but its *names*
  are not: `.kan/roles` is the only binding from a DID to a human name. `local`
  minus `roles` is then the set of authors present but never declared, which is
  exactly the anomaly #90 and #136 describe, reachable as data rather than
  inferable from an absence. This defuses ADR-61 rather than contradicting it:
  ADR-61 widened `roles` to include `primary` because omitting it gave "the
  wrong answer to the obvious question", and under `Local` the *default* answers
  that question, so `roles` is free to be narrow without being a trap. A new
  `role:<name>` spelling names one declared role instead of pasting a `did:key`.

- RQ-4: The third base is called **`Local`** in the JSON envelope. ADR-57
  established that a view names the base that produced it, with `Solo` reporting
  its single author at weight `1.0` so both variants parse identically. `Local`
  reports every log author at weight `1.0` and parses the same way, so the
  envelope shape is unchanged and this is a new value rather than a new field.

- RQ-5: A read **eliminates both identity and anchor**, and **keeps ingestion**
  behind a provably-fresh key. Three parts, in the order they matter.

  *Eliminate `genesis()` from the read path.* Measured on a scratch workspace:
  kan's fixed per-invocation cost is ~42ms against a 2.2ms bare process spawn,
  and `genesis()`'s three `git` subprocesses are **28.2ms of it** — roughly 70%,
  spent computing a value that cannot change for a repo and that a read does not
  need, since claims carry their own anchors. `kan identity did`, `status --json`
  and `show --all --json` all cost the same, so log size is irrelevant and this
  is the whole cost. The anchor is a *write-time* concern, exactly as identity
  is; v0.10.0 already moved git ahead of identity for #141, and this finishes the
  move by taking both off reads. One of those three spawns
  (`rev-parse --verify --quiet HEAD`) was added in v0.10.0 for #141's error
  message — ~10ms, a 25% increase in fixed cost on the path #151 had already
  flagged — and moves to the write path, where #141's error still lands before
  anything is written.

  *Keep ingestion on reads, gated by a content hash of `.claims/`.* The first
  resolution of this question deferred ingestion to an explicit refresh, on the
  reasoning that no cheap provably-fresh witness existed — because
  `file_name(subject)` is a sanitized prefix plus a digest **of the subject
  name**, so publishing more claims rewrites the same file and a filename-set
  fingerprint would miss updates. That reasoning was wrong about the cost, not
  the mechanism: reading every published file in full measures **0.66ms** for 40
  files, 15x cheaper than a single `git` spawn. So the key is a hash of the bytes
  — provably fresh, no format change, no dependency on the `.claims/` naming work
  in #131/#92. The expensive part of ingestion is parse and signature
  verification, and that is what the key skips.

  *Drop identity from the own-vs-foreign test*, generalising the log-membership
  check v0.9.2 already introduced for #150.

  The tripwire: the hash is O(published bytes), cheap at current scale and not
  forever. A repo with thousands of published subjects wants a readdir-level key,
  which is where content-addressed filenames would earn their keep. Recorded here
  so it is met as a known boundary rather than rediscovered as a slowdown.

## Open Questions

<!-- OPEN: Q6 -->
### Q6: Does `Local` change what `publish` writes?

`kan publish` writes a subject's claims into `.claims/`. Under `Solo` the
claims a subject "has" were the active identity's; under `Local` a subject may
hold claims from several log authors, so publishing it would export other
identities' claims too.

That is probably correct — they are all this workspace's claims, which is what
publishing a subject means — but it changes what a published file contains for
any multi-role workspace, and `.claims/` is a tracked format, so a change here
is a migration with a matrix row. It also interacts with #131 (two actors
colliding on one published filename), which is already queued for v0.12.0.

**To resolve**: Edit this section with your decision and remove the
`<!-- OPEN -->` marker.
<!-- /OPEN -->

## Out of Scope

- **ADR-75's vouching claims and the `author -> weight` to `claim -> weight`
  generalisation of `TrustBase`.** `Local` gives that design the non-circular
  root it needs — "explicitly trusted" can now mean "has written to this log" —
  but the fold change is its own pass with its own negative controls, as ADR-75
  already states.
- **#131 and #92, the `of` field.** Queued for v0.12.0; they change the tracked
  `.claims/` format and want their own release boundary.
- **#30's per-agent cryptographic identity.** REQ-7 makes legacy `agent` values
  readable; it does not build the replacement.
- **Sync, and any medium beyond `log` and `overlay`.** `Local` is defined over
  the local log deliberately; what a mounted remote medium does to a default
  trust base is `.design/medium-architecture.md`'s question, not this one.
- **#151's read-cost work.** Adjacent (it also touches `Workspace::open`) but a
  separate concern with its own measurements.
