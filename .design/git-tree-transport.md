# Feature: `GitTree` transport — claims published into the committed repo

## Summary

Publishing a claim into the committed git tree is not a rendering or a
projection — it is **moving that claim to another sharing layer**, the same
category of act as publishing to a `HostedRelay` or an atproto PDS, with git
as the substrate instead of a server. This doc designs `GitTree`: a second
real `Transport` implementation that writes signed claims as
YAML-frontmatter Markdown into a tracked `.claims/` directory, reads other
actors' claims back out of it after a `git pull`, and leaves the fold to do
what it already does with claims from multiple authors.

It is the cheapest possible first non-local transport: git already provides
distribution, history, and access control, so there is no wire protocol to
invent, no server to run, and no relay that can see data it shouldn't.

## Motivation

The originating observation: teloi (and other defining claims) naturally
belong *inside* the code they are about — visible in `git diff`, reviewable
in a PR, readable by someone who does not have kan installed. That is real,
but framing it as "render a claim to Markdown" gets the semantics wrong and
would have produced a second, unsigned source of truth sitting next to the
signed one.

The right frame: the git tree is a **sharing layer**. A claim in it is not a
view of a claim — it *is* the claim, in another place. Which means it must
arrive there the way claims arrive anywhere else: signed, verifiable, folded,
and subject to the same contest and trust machinery as any other actor's
claims. `docs/SPEC.md` §10's "local-only and atproto-ready are the SAME
on-disk artifact" extends to this cleanly: git is one more place the same
artifact lives.

**Why it should come before `HostedRelay`** (currently M3, v0.7.0-beta.1 in
`.design/sync-layer-architecture-and-staging.md`):

- `src/transport.rs`'s own doc comment defers wiring `Transport` into
  `Workspace` until "a second real implementation exists before the wiring
  shape can be designed against something real rather than guessed at from
  one implementation alone." `GitTree` is that second implementation, at a
  fraction of `HostedRelay`'s cost.
- It exercises the entire multi-actor path — claims from several authors,
  `SameAs` stitching, the contest stage, a trust policy that is not
  `SoloTrust` — with **zero infrastructure**. Every one of those code paths
  is currently unexercised by anything real.
- It is the first genuine test of `CLAUDE.md`'s smell test ("the local-only
  path must be *dramatically* simpler than the multi-actor path"), while the
  cost of discovering the abstraction is wrong is still low.
- **Issue #7 (E2EE) does not block it.** E2EE gates `HostedRelay` because a
  relay is an untrusted intermediary that can see traffic. A git remote you
  already trust with your entire source tree is a different threat model, and
  repo access control is the boundary. This is a genuine distinction, not a
  convenient one.
- **Issue #30 (per-agent identity) is a release gate, not a start gate** —
  the same call the staging doc already made for `HostedRelay`. Cross-*human*
  identity is already cryptographically real (`did:key`, ADR-4, verified by
  `sign::verify`); #30 fixes sub-identity within one human's account.

## Requirements

- REQ-1: A new `ClaimBody` variant declaring that a subject is published to a
  sharing layer (working name `Publication { layer }`, where `layer` is a
  closed enum whose only variant for now is `GitTree`). Publication is a
  decision *about* a subject, so it is a claim: attributable, retractable,
  and itself publishable — a clone can see who chose to share a subject and
  why. This is the data-model change the feature genuinely needs; a local
  config list would be unattributable, unsynced state in a system where
  everything else is a signed claim.
- REQ-2: A wire format for a claim in the tree: one file per subject at
  `.claims/<subject>.md`, containing one YAML-frontmatter block per claim,
  each carrying the complete claim record (`cid`, author `did`, signature,
  `kind`, `subject`, `cites`, `artifacts`, timestamp) with the narrative text
  as the Markdown body beneath it. The file is human-legible *and* a complete
  signed record — a reader sees prose, kan sees claims it can verify. Nothing
  in the file is derived-but-unverifiable.
- REQ-3: `GitTree: Transport` in `src/transport.rs`. `publish` appends a
  claim's serialized block to its subject's file, creating the file if
  absent; the claim is written **verbatim** — same CID, same signature, same
  bytes as in the local log. Publishing copies a claim to another layer; it
  never creates a new or altered one.
- REQ-4: `GitTree::subscribe` reads every file under `.claims/`, parses each
  block back into a `Claim`, and yields them as the same
  `Stream<Item = Result<Claim, _>>` `LocalOnly` returns. Claims from other
  authors arrive by ordinary `git pull` — kan performs no network I/O and
  runs no git commands to fetch.
- REQ-5: Every claim read from the tree is verified before it is yielded: its
  serialized form must re-hash to its stated CID, and its signature must
  verify against its stated author DID (`sign::verify`). A claim that fails
  either check is yielded as an `Err`, never silently dropped and never
  silently trusted — a hand-edited file is thereby detectable rather than
  merely discouraged.
- REQ-6: Claims arriving from the tree are folded exactly as any other
  actor's claims are: no special-casing, no implicit trust. A tree claim
  authored by someone else is subject to the same `TrustBase`/`Enrichment`
  machinery as a claim arriving from any future transport, which means using
  `GitTree` with more than one author requires a policy other than
  `SoloTrust`.
- REQ-7: Divergence is treated as kan already treats divergence between
  sources, not as drift to be repaired. Because claims are immutable and
  additive, a git merge that keeps both sides is the correct resolution, and
  a conflict at a file's tail is itself informative — it means two actors
  wrote concurrently. `.gitattributes` guidance ships with the feature (a
  union merge driver for `.claims/*.md`) so the common case resolves
  automatically, and the fold's contest stage handles the semantics. kan
  never rewrites history to resolve a conflict.
- REQ-8: File and block ordering carry no meaning. The fold consumes a claim
  *set*, ordered by `cites` where order matters at all, so two clones whose
  merges interleaved blocks differently must produce identical folds.
- REQ-9: CLI surface: `kan publish <subject>` (append a `Publication` claim
  and write the subject's live claims into `.claims/`), `kan publish --all`
  (bring every published subject's file up to date), and integration into
  `kan status` reporting subjects that are published and whether their tree
  files are current. kan writes files; it never runs `git add` or `git
  commit` — staging and committing stay the user's, matching kan's standing
  posture as git's sibling rather than its driver.
- REQ-10: `docs/SPEC.md` §10 and ADR-3 are updated. §10 gains `GitTree` in
  the transport list; ADR-3's "gitignored `.kan/`" reasoning is extended, not
  contradicted — `.kan/` stays entirely ignored and the shared layer lives in
  a separate tracked top-level `.claims/`, so the two never overlap.

## Acceptance Criteria

- [ ] AC-1: A `Publication` claim can be appended and appears in the
      subject's fold; retracting it is honored the same way any retraction is.
      (REQ-1)
- [ ] AC-2: `kan publish bug-42` creates `.claims/bug-42.md` containing one
      block per live claim on that subject, each with a CID matching the
      claim's CID in the local log. (REQ-2, REQ-3, REQ-9)
- [ ] AC-3: A claim's bytes round-trip: writing a claim to the tree and
      parsing it back yields a `Claim` whose re-computed CID equals the
      original's. (REQ-2, REQ-3)
- [ ] AC-4: `GitTree::subscribe` over a fixture `.claims/` directory yields
      every claim in it, and folding those claims produces the same
      `FoldedView` as folding the same claims from a `Log`. (REQ-4, REQ-6)
- [ ] AC-5: A block whose Markdown body has been edited by hand yields an
      `Err` from `subscribe` naming a CID mismatch; a block whose signature
      does not verify against its stated DID yields an `Err` naming the
      signature failure. Neither is dropped silently. (REQ-5)
- [ ] AC-6: Claims by a second author in the tree are not accepted under
      `SoloTrust` and are accepted under a peer-trusting enrichment — proving
      tree claims run the same trust path as any other. (REQ-6)
- [ ] AC-7: Two `.claims/` directories representing both sides of a
      concurrent write, unioned, fold to a view containing both claims, with
      the affected subject classified `Contested` rather than one claim
      winning silently. (REQ-7)
- [ ] AC-8: Shuffling the block order within a file, and the file order
      within `.claims/`, produces byte-identical fold output. (REQ-8)
- [ ] AC-9: `kan publish` leaves the git index untouched — verified by
      checking `git status --porcelain` shows the new file as untracked or
      unstaged, never staged. (REQ-9)
- [ ] AC-10: `kan status` names published subjects whose tree file is missing
      claims present in the log. (REQ-9)
- [ ] AC-11: A `.gitattributes` fragment shipping with the feature declares a
      union merge for `.claims/*.md`, and a test merges two divergent fixture
      trees to confirm both sides' claims survive. (REQ-7)
- [ ] AC-12: `docs/SPEC.md` §10's transport list names `GitTree`; a new ADR
      records the sharing-layer framing and extends ADR-3 rather than
      superseding it; `.gitignore` still ignores `.kan/` in full, and
      `.claims/` is not ignored — checked by `git check-ignore` on both paths
      in a test. (REQ-10)

## Architecture

**`src/claim.rs`** gains the `Publication` body variant and its `Layer` enum
(REQ-1) — the one data-model change, and the reason this is kan's feature and
not day's under ADR-18's rule. Everything else here is transport and
serialization.

**`src/transport/git_tree.rs`** (promoting `transport.rs` to a module
directory, `LocalOnly` moving alongside unchanged) holds `GitTree`, the block
serializer/parser, and verification. It depends on `sign::verify` and on the
same DAG-CBOR encoding `cid.rs` already uses, because the CID in a block must
be computed from exactly the bytes kan already computes CIDs from — a second
encoding path would be a second source of truth about what a claim *is*.

**The verification chain is the whole safety story.** Frontmatter carries the
CID; the CID is recomputed from the parsed claim; the signature is checked
against the author's DID. That is what lets an unsigned-looking Markdown file
be a first-class claim carrier rather than a forgery surface. It is also what
makes hand-edits detectable instead of merely discouraged — the original
"rendered file" framing had no answer to a tampered file at all.

**Nothing here destroys or mutates.** `publish` appends blocks; retraction
appends a retraction claim that also publishes; conflicts resolve by union.
There is deliberately no path by which publishing rewrites or removes a claim
already in the tree, which is what makes union merge a *correct* resolution
rather than a lossy convenience.

**Wiring.** This is the second `Transport` implementation M0 deliberately
waited for (`src/transport.rs`'s doc comment, `.design/v0.5-milestone.md`
REQ-5), so the `Workspace` integration shape gets designed here against two
real implementations rather than guessed from one. `Workspace` gains a
transport set rather than a single transport, since `LocalOnly` and `GitTree`
are both active simultaneously in any repo using this.

**Milestone placement.** Slots into
`.design/sync-layer-architecture-and-staging.md` between M0 and `HostedRelay`
as the new M1.5 (its own version, ahead of v0.7.0-beta.1's `HostedRelay`).
Does not depend on M1 (E2EE) resolving; does not block on M2 (issue #30)
starting, though the same "before real multi-agent use" release gate applies.

## Open Questions

None blocking. Four resolved during this pass and recorded as `decide` claims
on the `hard-claims` subject: the sharing-layer framing (this is a transport,
not a rendering, which is what makes the data-model change necessary); one
file per subject accumulating signed blocks; a separate tracked top-level
`.claims/` rather than a carve-out inside gitignored `.kan/`; and divergence
handled as ordinary source divergence with the raw conflict informative,
rather than as drift to be silently repaired.

The directory name `.claims/` is the one deliberately-reversible choice —
picked for discoverability (dotted-but-tracked, the `.github/`/`.claude/`
convention) over `kan/` or a configurable path, and cheap to change before
implementation.

## Out of Scope

- E2EE (issue #7). Not needed here: the git remote is a trust boundary the
  user has already accepted for their source. It remains a `HostedRelay`
  prerequisite.
- `HostedRelay` and `AtProto` transports, and `docs/SPEC.md` §10.1's lexicon
  separation — M3 and M4, unchanged by this.
- Per-agent sub-identity (issue #30) — parallel track, release gate.
- kan running git commands. No fetch, pull, add, commit, or merge; kan reads
  and writes files in the working tree and nothing else.
- Rendering claims *for humans only* — every block in the tree is a complete
  verifiable claim. A prettier read-only view is a separate concern, and
  `day` is the natural home for it.
- Incremental publish (only writing changed blocks). Correctness first;
  rewrite the whole subject file until profiling says otherwise, matching
  kan's standing "reference recompute first" rule.
