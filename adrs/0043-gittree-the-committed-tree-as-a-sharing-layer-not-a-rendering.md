# ADR 0043: `GitTree`: the committed tree as a sharing layer, not a rendering

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-43

## Context

Not recorded contemporaneously.

## Decision

Not recorded contemporaneously.

## Rationale

Not recorded contemporaneously.

## Consequences

Not recorded contemporaneously.

## Evidence

Not recorded contemporaneously.

## Alternatives considered

Not recorded contemporaneously.

## Supersession

Not recorded contemporaneously.

## Historical record

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
