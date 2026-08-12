# Feature: The published `.claims/` format and its wire contract

## Summary

Rework the published record format so that (a) a subject's claims live at a
path that mirrors the subject's own name, one file per publishing author, and
(b) the header fields git-tree-transport REQ-9 authenticates carry an explicit serde shape instead
of `format!("{:?}")`. These are one change because kan#195 states it is upstream
of git-tree-transport REQ-9 (kan#131 + kan#92): the layout decides what a record's position
metadata means, and F4's header rewrite lands inside whatever framing the layout
leaves. Doing F4 first would migrate a published format twice.

Serves `telos/raw-data-and-projections`. A published file is a *projection* of
claims whose raw datum is the DAG-CBOR in `content`; this design keeps that
datum untouched and makes every derived, human-facing field in the projection
explicitly specified rather than incidentally defined by a Rust formatting
trait.

## Requirements

- REQ-1: A subject's published records live at `.claims/<subject>/<author>.md`,
  where `<subject>` is the subject's own name with its `/` separators preserved
  as real directories, and `<author>` is the publishing author's DID with the
  `did:key:` prefix removed. One file per publishing author.
- REQ-2: `write_subject` (`src/transport/git_tree.rs:645`) writes only the
  publishing author's own file, and never reads, rewrites, or deletes a file
  belonging to another author.
- REQ-3: The subject-to-path mapping preserves `/`, so `telos/legible-process`
  becomes a nested path rather than collapsing to `telos_legible-process`. The
  4-byte digest suffix `file_name` appends today is removed: it existed to
  restore injectivity after that collapse, and the collapse is gone.
- REQ-4: Where the mapping is still not injective — case-insensitive
  filesystems fold `Bug42` and `bug42` together below kan entirely — the
  existing content-keyed guard (`retirable`, `src/transport/git_tree.rs:661`)
  refuses the write rather than clobbering. A lossy path is never *trusted* as a
  unique key for a destructive write; it is verified against the file's actual
  records first.
- REQ-5: The record header serializes `subject`, `kind` and `cites` through
  declared `serde` shapes on `RecordHeader` (`src/transport/git_tree.rs:232`),
  not through `format!("{:?}")` at lines 181-182.
- REQ-6: git-tree-transport REQ-9's authentication (`src/transport/git_tree.rs:391-423`) compares
  *decoded values* against the claim's own fields, not formatted strings, so
  header verification cannot fail because a formatting implementation changed.
- REQ-7: No `std` `Debug` output appears in any byte a reader compares, parses,
  or uses as a path. This includes the `SubjectRef::Anchor` arm of the path
  mapping, which today derives a **path component** from
  `format!("{anchor:?}")`; an anchor subject gets a declared path form.
- REQ-8: The header format version rises to 3. A reader accepts v1, v2 and v3
  records, and `FORMAT_VERSION` (`src/transport/git_tree.rs:297`) governs what a
  writer emits, preserving the existing "a reader meeting a higher version says
  so by version number" behaviour at lines 334-338.
- REQ-9: Reading discovers records under both layouts — the flat
  `.claims/<slug>.<digest>.md` files v0.6.0..v0.12.x published, and REQ-1's
  nested per-author directories. `read_all`'s `read_dir`
  (`src/transport/git_tree.rs:837`) walks the tree rather than one flat level,
  and treats a directory entry as a directory rather than a malformed record.
- REQ-10: `seq`/`of` remain scoped to one author's record set for one subject —
  which is what they already mean — and REQ-1 makes that scoping structural, so
  `missing_records` (`src/transport/git_tree.rs:606`) cannot be tripped by a
  second author publishing.
- REQ-11: Publishing is git-mergeable: two authors publishing the same subject
  concurrently produce changes to disjoint paths, so `git merge` resolves
  without conflict and without either side's records being dropped.
- REQ-12: In v3 records, `content` is base64-encoded rather than hex. A reader
  decodes hex for v1/v2 records and base64 for v3, selected by the header's own
  `v` field rather than by sniffing the payload.
- REQ-13: The v3 record separator contains no `---` run, so a scan for the
  frontmatter fence cannot re-enter on it. The v1/v2 separator `---8<---`
  (`src/transport/git_tree.rs:130`) remains understood when reading those
  versions.

## Acceptance Criteria

- [ ] AC-1: A test publishes subject `s` as author A, then as author B into the
  same tree, and asserts both authors' records are readable afterwards and that
  A's file is byte-identical before and after B's publish. (REQ-1, REQ-2)
- [ ] AC-2: A test publishes `telos/legible-process` and asserts the record
  lands under a `telos` directory containing a `legible-process` directory, with
  no digest component anywhere in the path. (REQ-1, REQ-3)
- [ ] AC-3: A test publishes both `a` and `a/b` into one tree and asserts both
  are readable — a subject directory holds author files and child subject
  directories side by side. (REQ-1, REQ-9)
- [ ] AC-4: A test publishes `Bug42` and then `bug42` as the same author and
  asserts the second is refused with a collision error rather than overwriting,
  and that the first subject's records survive. (REQ-4)
- [ ] AC-5: A test asserts the serialized header parses as JSON in which
  `subject` is a structured value rather than a `Debug`-formatted string such as
  `Local("work")`. (REQ-5)
- [ ] AC-6: A test mutates a header's `subject`, `kind`, or `cites` to a
  well-formed but wrong value and asserts `HeaderMismatch` is still returned —
  git-tree-transport REQ-9's forgery defence survives structural comparison. (REQ-6)
- [ ] AC-7: A test publishes an anchor subject and asserts its path contains no
  `Debug`-shaped token, and that the subject round-trips from the path form.
  (REQ-7)
- [ ] AC-8: A fixture file in the flat v2 layout with a v2 `Debug`-shaped header
  is read successfully by the new reader, with its claims verifying. (REQ-8,
  REQ-9)
- [ ] AC-9: A fixture tree containing both a flat v2 file and a nested v3
  directory is read, and every claim from both is returned exactly once.
  (REQ-9)
- [ ] AC-10: A test writes a header with `v: 4` and asserts the reader reports
  the version by number rather than failing on hex or CID decoding. (REQ-8)
- [ ] AC-11: A test simulating two authors publishing the same subject from
  divergent clones performs a real `git merge` of the two trees and asserts it
  succeeds with no conflict and both authors' records present. (REQ-11)
- [ ] AC-12: A test asserts `missing_records` does not fire when a second author
  publishes the same subject. (REQ-10)
- [ ] AC-13: A test round-trips a v3 record and asserts `content` decodes as
  base64 and that a hex-encoded payload in a v3 record is rejected rather than
  silently misread. (REQ-12)
- [ ] AC-14: A test asserts a v2 fixture's hex `content` still decodes, selected
  by its `v` field. (REQ-12, REQ-8)
- [ ] AC-15: A test asserts the v3 separator contains no `---` substring, and
  that a record whose narrative body contains the literal text `---` still
  splits correctly. (REQ-13)

## Architecture

Everything here is `src/transport/git_tree.rs` (1013 lines) plus its tests
(`tests/git_tree.rs`, `tests/git_tree_framing.rs`, `tests/git_tree_merge.rs`,
`tests/git_tree_trust.rs`). Nothing touches `ClaimContent`, the log, or the
fold, so `docs/SPEC.md` §7.1's frozen-fields contract (ADR-44) is not engaged
for the claim itself — only for the *envelope*, which has its own version field
and has already been through one bump.

**Layout (REQ-1 … REQ-4).** `file_name` currently sanitizes the subject into a
single flat component — every character outside `[alnum].-` becomes `_` — and
appends a 4-byte digest to restore the injectivity that sanitizing destroyed.
The digest's own comment names the collision that forced it:
`telos/legible-process` and `telos_legible-process` sharing one file, where
`telos/<slug>` is exactly day's naming convention (ADR-42).

Preserving `/` as a directory separator removes that collision at its source
rather than compensating for it, and makes `.claims/` mirror the subject names
people actually use — `telos/…`, `atom/…`, `agents/handoff/…`, `review/…`. The
digest then has no job left and goes.

One hazard survives and is handled rather than hidden: case-insensitive
filesystems (APFS by default) fold `Bug42` and `bug42` together, which the
existing comment correctly says no character mapping can fix. The answer is not
another derived key but the guard that already exists — `retirable` refuses to
overwrite a file that is not entirely this subject's, keyed on the records'
content rather than on the filename. ADR-52's lesson is about *trusting* a lossy
derived value as a unique key on a destructive path; verifying before writing is
the opposite of trusting. The cost is a refusal the operator resolves by
renaming a subject, and the claims are safe in the log and in git either way.

Cross-author safety stops depending on a guard at all. Today the file is keyed
on subject alone, so kan#111's check sees a file that is legitimately this
subject's and permits the overwrite — measured tonight, a second author's
`publish` silently removed the first author's records from the tracked tree, and
re-publishing ping-ponged them back. Under REQ-1 two authors never address the
same path, so kan#131 stops being a defect to defend against and becomes a state
that cannot be reached.

That also removes the line-level git conflict inside a JSON header which turned
the only non-discarding manual resolution into two malformed records (kan#211).
The corruption path becomes rare rather than routine — it does not disappear,
since a hand-edit or a truncated write can still produce it, which is why
kan#211's disclosure gap stays open independently of this design.

**Header (REQ-5 … REQ-7).** `RecordHeader`'s `content` field remains the
authority: hex-encoded DAG-CBOR of the `ClaimContent` with the narrative text
blanked. The change is confined to the three legibility fields above it. Their
doc comments currently read "Derived, ignored on read", which has been **stale
since git-tree-transport REQ-9** made them authenticated at lines 391-423; correcting that comment
is part of this work, in the same spirit as kan#177.

The `Debug`-to-serde move is not a `Display` swap. `SubjectRef` and the claim
kind get declared wire shapes that become frozen surface, and verification
decodes the header's value and compares it to the claim's — so the contract is
the shape, not the rendering. `Cid` cannot be serialized through `serde_json`
directly (ADR-44 measurement 1: it becomes `{"": [0, 1, 113, …]}`), so `cites`
stays a list of CID *strings*, which is already what it is and is already
stable.

**Compatibility (REQ-8, REQ-9).** The envelope's `v` field exists and works:
absent means 1, current is 2, and a reader meeting a higher version says so by
number. v3 uses the same lever. Because `publish` rewrites a whole file, an
author's own records migrate to the new layout and header on their next publish
with no migration command — but an author cannot rewrite a *peer's* file under
REQ-2, and that is the point. So the reader keeps accepting the flat v2 layout
indefinitely rather than for a window, and this is stated as a contract rather
than a temporary accommodation.

**Invariant check.** No operation here destroys a subject: `.claims/` is a
projection, every claim remains in its author's append-only log, and REQ-2
strictly reduces what one actor's write can reach — from "any author's records
for this subject" to "my own". That direction is the one CLAUDE.md's
non-negotiable asks for.

## Open Questions

None remaining.

## Resolved Questions

- **Layout is per (subject, author).** A directory per subject, one file per
  publishing author, chosen over merging foreign records into one file and over
  merely refusing to overwrite them. It makes kan#131 unreachable rather than
  guarded, and makes concurrent publishes disjoint in git.
- **Subject paths nest naturally.** Subject names already carry `/`, so they map
  to real directories instead of being flattened and then disambiguated by a
  digest. The digest is removed.
- **Injectivity against case folding is enforced by refusal, not by a derived
  key.** The content-keyed guard already refuses to clobber; a second lossy
  unique-key scheme would repeat the pattern ADR-52 and kan#111 exist to
  correct.
- **The author leaf is the full DID minus `did:key:`.** Injective by
  construction, no collision analysis, and the DID is already inside the file
  and already authenticated.
- **v3 re-encodes `content` as base64 and adopts a separator with no `---` in
  it.** Both are v3-shaped changes, so deferring them would cost a v4 and a
  second migration of a published format — the exact cost this combined pass
  exists to avoid. base64 over base32 for density; the CIDs beside it stay
  base32, so the two are visually distinguishable rather than confusable.
- **Header legibility fields get explicit serde shapes, compared structurally.**
  Chosen over a kan-owned canonical string (which moves the trap rather than
  removing it) and over dropping the fields entirely (which would cost the
  human-scannable frontmatter the format exists for).

## Out of Scope

- **kan#211's `--json` disclosure of skipped records.** Real, filed, and
  independent: it is a property of the read envelope rather than of the file
  format, and it should be fixed whichever way this design resolves. REQ-1 makes
  its trigger rarer without addressing it.
- **kan#212's trust selector for peers.** Same surface, different layer — a
  question about how a reader asks for a view, not about what is on disk.
- **Authenticated deletion detection.** `seq`/`of` detect deletion rather than
  preventing it, and the header's own comment is explicit that an editor who
  rewrites every remaining record defeats them. Signing over the record set is a
  new claim shape and its own design pass.
- **Any change to `ClaimContent`, CID computation, or the log.** The frozen
  fields stay frozen; this is envelope work only.
- **Sync, PDS, or lexicons.** `.claims/` over git remains the only transport.
