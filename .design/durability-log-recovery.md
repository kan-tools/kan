# Feature: Durability — rebuilding a log from `.claims/`, and making the gap visible

## Summary

kan's source of truth is one gitignored directory (`.kan/`) with exactly one
copy on one machine; the tracked `.claims/` sharing layer holds only what
someone chose to publish. This pass gives kan a way to *rebuild a log from
`.claims/`* and a way to *see, before any loss, what would not survive it* —
without conflating durability (complete, automatic, no judgement) with sharing
(curated, deliberate). It defines one verbatim-insert primitive whose
destination is keyed on each record's own signed author, splitting *restore*
(my own claims, back into `log/`) from *ingest* (another author's claims, into
a read-time overlay), and it emits a hard requirements block that the identity
architecture pass (#105) must satisfy, because identity recovery gates log
recovery.

## Requirements

- REQ-1: A verbatim-insert primitive on `store::log::Log` (call it
  `ingest`) accepts a fully-formed `StoredClaim` (claim + `rev`), verifies its
  signature **against the record's own `content.author.did`**, and inserts it
  without re-signing. This is the primitive both restore and ingest share and
  is the thing today's `Log::append` cannot be: `append_locked`
  (`src/store/log.rs:689`) signs with the *local* identity, so re-appending a
  restored or foreign claim reproduces the same content CID but replaces the
  signature, and `Log::get`'s own-author verification (`Error::ClaimSignatureInvalid`,
  `src/store/log.rs:75`) then rejects it.
- REQ-2: A restore entry point reconstructs the local log from `.claims/`:
  it reads every record via `git_tree::GitTree::read_all`
  (`src/transport/git_tree.rs:739`), which already returns byte-complete,
  signature-verified `(Cid, Claim)` pairs plus each record's `rev`, and
  `ingest`s each record **whose author matches this repo's identity** into
  `log/repo.car`. The result is a repo of my own records — atproto-clean,
  and it preserves #88's verified property that a backup of `log/` alone is
  sufficient.
- REQ-3: Restore refuses, writing nothing, when the local identity's DID
  (`sign::Identity::did`, `src/sign.rs::did`) does not match the author of the
  `.claims/` records it is asked to restore. The message names the recovery
  phrase (`kan identity restore`, `src/cli/mod.rs:759`) as the fix. This is
  the "identity recovery gates log recovery" rule (#93) enforced at the one
  place it bites, and it is the #90 failure ("a binary upgrade silently mints
  a new identity, taking the whole log out of every read") made loud instead
  of silent.
- REQ-4: A foreign-authored record — one whose author is **not** this repo's
  identity, arriving via `Transport::subscribe` — lands in a read-time
  **overlay** store beside `log/repo.car`, never inside it. The fold reads the
  union of `log/` and the overlay. `log/repo.car` stays *claims I authored*,
  which is what atproto repo semantics require (CLAUDE.md: "local-only and
  future atproto are the same on-disk artifact") and is where the eventual
  HostedRelay/AppView (`.design/sync-layer-architecture-and-staging.md`) reads
  from. This REQ is shared with v0.8's transport wiring and is the reason the
  two passes run together.
- REQ-5: `kan status` gains a per-subject **durability state** —
  `unpublished` (lives only in `.kan/`), `published` (in `.claims/`, current),
  or `stale` (in `.claims/`, but the log holds newer live claims not yet
  published) — computed by comparing the fold's live claims per subject
  against `git_tree::published_subjects` (`src/transport/git_tree.rs:900`).
  It surfaces in both `actions::status` (`src/actions.rs:1088`) and
  `actions::status_json` (`src/actions.rs:1392`). This is the kan-native move:
  make the gap **data**, a column, not a nag or a hook — the same shape as
  `context`'s omission reporting, the tool refusing to let a partial picture
  look complete.
- REQ-6: This pass adds **no** auto-publish and does **not** un-ignore
  `.kan/`. Publishing stays opt-in and curated (ADR-43); `.kan/` stays
  gitignored in full (ADR-3, re-affirmed in #93 point 4 — the CAR is binary
  and append-only, would bloat the repo and conflict on every concurrent
  write). Durability coverage is exactly what was published, and REQ-5 is what
  keeps that coverage honest by making its edges visible.
- REQ-7: Restore and log-open must **name a format-version gap** rather than
  hard-abort on a record written by a newer kan. #88 measured this blocking an
  actual restore (`unknown field recorded_at`, a hard load abort). The record
  format already carries a version (`RecordHeader.v`, `FORMAT_VERSION`,
  `src/transport/git_tree.rs`) and a reader meeting a higher version already
  says so by number; restore must extend that honesty to the whole-log read
  path (ADR-44's schema-evolution posture), skipping an unreadable record with
  a named reason rather than abandoning the log.

## Acceptance Criteria

- [ ] AC-1: A unit test constructs a `StoredClaim` signed by author A, calls
  `Log::ingest` on a log owned by identity A, and `Log::get` returns it
  verified — with no second signing step, and the content CID unchanged from
  the record on disk. (REQ-1)
- [ ] AC-2: An end-to-end test authors N claims, writes them to `.claims/`,
  deletes `log/` while keeping `.claims/` and the identity, runs restore, and
  the fold reports the same N subjects with the same content CIDs as before
  the deletion. (REQ-2)
- [ ] AC-3: Restore against a repo whose identity DID differs from the
  `.claims/` records' author exits non-zero, writes nothing to `log/`, and the
  message contains the recovery-phrase instruction. **Negative control:**
  with the DID-match guard reverted, the same test observes the wrong-identity
  records being ingested — confirming the guard is load-bearing, not
  tautological (ADR-52's discriminating-test rule). (REQ-3)
- [ ] AC-4: A foreign-authored claim delivered through `Transport::subscribe`
  is readable in the fold but leaves `log/repo.car` byte-identical; an
  assertion over the log's authored-CID set shows the foreign CID absent from
  `log/` and present in the overlay. (REQ-4)
- [ ] AC-5: With three subjects — one never published, one published and
  current, one with an unpublished newer claim — `kan status` and
  `status_json` report `unpublished`, `published`, and `stale` respectively;
  publishing the stale one flips it to `published`. (REQ-5)
- [ ] AC-6: A test asserts restore writes nothing to `.claims/` and does not
  invoke publish, and that `.kan/` remains gitignored (the shipped
  `.gitignore` still lists it). (REQ-6)
- [ ] AC-7: A record bearing a `RecordHeader.v` greater than `FORMAT_VERSION`
  is skipped during restore with an error naming the version number, and the
  remaining records still restore — the load does not abort wholesale. (REQ-7)

## Requirements handed to the identity pass (#105)

These are hard inputs to `.design/*.md` for #105, stated here so that pass does
not rediscover them (the failure #107 proved). They follow from durability, not
from identity's own threat model, and #105 must satisfy them whatever
enclave/escrow shape it lands on:

- IREQ-1 (identity gates log): the restore path of REQ-2/REQ-3 assumes the
  signing DID can be reproduced *before* the log is read. Any identity design
  must make identity recovery a precondition of, and never a consequence of,
  log recovery.
- IREQ-2 (one secret reproduces the DID): restore is only a restore if one
  escrowed secret reproduces the exact signing DID. This holds today
  (`sign::from_recovery_phrase` → `did`, `src/sign.rs:485`). Every #105
  candidate resolution — enclave-held derived key, escrowed master seed, device
  key + escrowed identity — must preserve it; a design under which the phrase
  cannot reproduce the DID breaks REQ-2 outright.
- IREQ-3 (phrase and claims survive together): #93 point 2 — a log restored
  without its original key is one you read as someone else's and cannot retract
  your own claims in. The identity pass must state where the phrase lives
  relative to `.claims/` so the two are recoverable as a pair, not
  independently losable.
- IREQ-4 (no interactive prompt on any read/restore path): restore and every
  fold read must complete with no GUI/keychain prompt (#96, three incidents).
  This constrains where restore may read key material from.
- IREQ-5 (encryption for escalation, not only self): the publicness ladder
  (see Q3's resolution) has rungs with different key operations — the L1
  encrypted backup is encrypt-to-self, the L2/L3 permissioned rungs are
  encrypt-to-a-team/recipient-set, L4 public is plaintext-signed. The identity
  pass must derive an encryption capability that supports recipient/group
  encryption, not only self-encryption, or the permissioned middle of the
  ladder cannot be built on it. This is the point where #105 and the sync/
  remote design genuinely merge.

## Architecture

The change is three seams, all against existing modules; none touches the fold
(the one layer three reviews found sound), and none adds a destroy path — the
non-negotiable invariant holds because ingest is insert-only and restore writes
a fresh `log/` from records it verified first.

**The primitive (REQ-1).** `store::log::Log` grows `ingest(stored:
StoredClaim)`. It differs from `append_locked` (`src/store/log.rs:689`) in
exactly one way that matters: it does not call `identity.sign` over the
content. It verifies `sign::verify(&stored.claim.content.author.did,
&content_cid.to_bytes(), &stored.claim.sig)` (`src/sign.rs:510`) and, on
success, writes the block and commits — the commit itself is still signed by
the local identity (`src/store/log.rs:717`), which is correct: the commit
attests to the repo's current state, while each record keeps its own author's
signature. `append`'s existing `recorded_at` guard (`get_or_insert`,
`src/store/log.rs:677`) already anticipated this ingest path in its comment;
`ingest` is that path.

**Restore vs. ingest, keyed on the author (REQ-2, REQ-3, REQ-4).** The
destination is chosen by a single content-derived-but-signed value — the
record's `content.author.did`, compared against `Workspace::my_author`
(`src/workspace.rs:110`). This is ADR-52's rule applied *positively*: the
placement key is the content's own signed identity, never a name derived from
it. Same author → `log/repo.car` (restore). Different author → the overlay
(ingest). The overlay is a second store beside `log/`; the simplest honest form
is a separate CAR (`.kan/overlay.car`) folded in alongside `log/` by
`Workspace::open` (`src/workspace.rs:53`), with the index rebuilt over the
union — the index is already disposable and rebuilt from the log on open, so
extending its input set is the small change, not a new persistence model. The
overlay is the local shard of the future AppView, so nothing here is undone when
`.design/sync-layer-architecture-and-staging.md`'s HostedRelay lands.

**Reading `.claims/` (REQ-2, REQ-7).** `GitTree::read_all`
(`src/transport/git_tree.rs:739`) is the reader and needs no change to be one —
it already verifies signatures, authenticates each filename against its records
(REQ-13 from the prior transport pass), and returns `Err` in place rather than
dropping a bad record. Restore consumes its output, partitions by author, and
`ingest`s. `Transport::subscribe` (`src/transport/git_tree.rs:843`) is the same
read for the foreign-author case; wiring it through `Workspace` is v0.8's build
and REQ-4 is where the two passes meet. REQ-7 extends the version-gap honesty
that already exists per-record (`RecordHeader.v` vs `FORMAT_VERSION`) to the
whole-log restore loop so one future-versioned record cannot abort the restore.

**The durability column (REQ-5).** `actions::status` (`src/actions.rs:1088`)
already folds live claims per subject and already has the machinery to compare
against `.claims/`: `git_tree::published_subjects` (`src/transport/git_tree.rs:900`)
returns the published set. The state is a pure comparison — live-claim CIDs per
subject vs. the CIDs present in that subject's `.claims/` file — yielding
`unpublished` / `published` / `stale`. It threads into the existing per-subject
render (`write_state`) and the JSON path (`status_json`, `src/actions.rs:1392`).
No new claim, no new fold: this is a read projection over data kan already holds,
which is squarely kan-owned under ADR-18.

**Relationship to #92.** #92 (honest deletion detection: a publisher signing
over its record set) is a *different* mechanism and stays out of scope here —
REQ-5's `stale` state reports "the log has more than `.claims/` does," which is
the durability-exposure question, not "records went missing from `.claims/`
across a republish," which is #92's and needs a new signed claim shape.

## Resolved Questions

**Q1 (resolved): one store or two for ingested claims?** Neither globally —
the record's `author.did` decides. Restore is my own claims back into `log/`
(atproto-clean, keeps #88's `log/`-alone-is-sufficient property); ingest is
another author's claims into a read-time overlay (what an AppView holds). One
verbatim-insert primitive (REQ-1), destination keyed on the signed author. This
dissolves the commit-signing objection: restoring my own records signs a normal
commit over my own records, and the overlay is a cache with no atproto-repo
commit semantics to violate. Recorded as REQ-1/REQ-4.

**Q2 (resolved): does restore refuse on identity mismatch?** Yes — a hard
stop that writes nothing and names the recovery phrase, because a mismatch
means the identity was not restored first, and silently folding your own
history in as "someone else's" is exactly the #90 failure. Recorded as REQ-3
and IREQ-1.

**Q3 (resolved): curated `.claims/` here; the complete mirror is an E2EE
backup remote, its own pass.** This pass ships the visibility column (REQ-5)
over the curated `.claims/` for the local-only present, and does **not** add
an in-repo complete mirror (REQ-6 stands — a plaintext complete dump either
destroys `.claims/`'s curation or reintroduces the binary-in-git conflict).
The complete-durability answer is instead a **push to a personal encrypted
backup remote** — the CAR leaves for a remote over an API and never enters the
git tree, which sidesteps REQ-6 entirely and keeps `.claims/` as purely the
sharing layer.

The realization that resolves the original tension: #93 posed durability
(complete, automatic) and sharing (curated, deliberate) as wanting opposite
defaults, and treated that as permanent. They only conflict *in plaintext*.
An **E2EE** backup carries zero privacy cost, so durability can be
total-by-default while sharing stays a separate, escalated act — the two live
at different *encryption states*, not different *completeness states*.

That backup is the base of a user-controlled **publicness ladder**, each rung
an explicit escalation the user controls:

- **L0 Local** ↔ **L1 encrypted backup** (server blind) — reversible, complete,
  default; the durability answer.
- **L2 kan server / permissioned relay** — server reads, scoped to escalated
  subjects; mostly reversible.
- **L3 atproto permissioned** → **L4 atproto public** — practically
  *irreversible* (cached, indexed, federated); the escalation surface must mark
  the one-way rungs as distinct from the reversible ones.

The personal backup remote is `HostedRelay` at N=1 (the multi-actor fold turned
off); its wire shape is atproto repo-sync semantics, which the append-only MST
makes the natural — and lighter-than-git — form. All of this is a **separate
design pass** (the sync/remote vision), not scope here; it is named so this doc
does not silently absorb it. Recorded against IREQ-5 (the identity pass must
support recipient/group encryption for the L2/L3 rungs, not only self-encryption).

## Open Questions

None — Q3 resolved below.

## Out of Scope

- Honest cross-republish deletion detection (#92) — needs a new signed
  record-set claim shape; different mechanism.
- The full `PeerContested` trust *surface* and v0.8's complete transport
  wiring — REQ-4 defines the ingest destination the two passes share, but the
  CLI/MCP trust surface is v0.8's build.
- The identity architecture itself (#105) — this pass emits requirements to
  it (IREQ-1..4) but does not design the enclave/escrow mechanism.
- Un-ignoring `.kan/` — rejected (REQ-6, ADR-3, #93 point 4).
- Incremental fold/index over the overlay (#25) — the overlay rebuilds with
  the index on open, same as `log/` today; making that incremental is a
  separate, measured optimization.
