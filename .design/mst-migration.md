# Migrating existing logs to a conformant MST

**Status:** design, repair and post-condition landed, not yet run against any
real log.
**Cites:** kan#204, ADR-90, `src/mst/mod.rs`, subject
`mst-conformance-defect`.

## Summary

`atproto-repo` 0.14.5's MST never split: every key went into one flat root node.
Fixing it changes the shape of the tree every existing log holds. This document
is about what that costs, and the answer turned out to be *almost nothing* —
except for one path that made a claim silently unreadable, which is most of what
follows.

The conclusion: **migration is an append.** The first conformant write produces a
canonical tree by itself, the old CAR is a byte-exact prefix of the new one, no
commit is re-signed, and the overlay needs nothing. The only real hazard is a
log written by both a conformant and a non-conformant binary, which is repaired
by sorting the walk before rebuilding.

## Requirements

- REQ-1: **No claim becomes unreadable.** Every claim readable before a shape
  change is readable after it, by ordered descent and not merely present in the
  CAR. This is the non-negotiable invariant applied to storage layout.
- REQ-2: **The upgrade needs no migration step.** An existing flat log is
  carried forward by ordinary writes, without a separate command, a flag day, or
  re-signing history.
- REQ-3: **A log a non-conformant binary has written into is repaired**, not
  propagated and not refused. Reads of such a log must keep working.
- REQ-4: **Nothing attested is rewritten.** Old commits and the flat nodes they
  reference are retained; the CAR grows by append only.

## Acceptance Criteria

- AC-1: (REQ-1, REQ-3) A tree spliced the way a flat-MST writer splices it
  is repaired by the next write, with every pre-existing key, the spliced key,
  and the newly written key all reachable by ordered descent.
  *Witness:* `tests/mst_conformance.rs::a_write_repairs_a_tree_a_non_conformant_writer_touched`
- AC-2: (REQ-1) Every key stays readable after every single insert, checked
  after each one rather than at the end.
  *Witness:* `tests/mst_conformance.rs::every_key_readable_after_every_insert`
- AC-3: (REQ-2) The tree kan writes is the tree a conformant implementation
  writes, so an upgraded log is a valid atproto repo rather than a kan-specific
  artifact.
  *Witness:* `tests/mst_conformance.rs::root_cid_matches_the_reference_implementation`
- AC-4: (REQ-4) The old CAR is a byte-exact prefix of the CAR after the
  first conformant write. *INTENT:* verified by hand on a synthetic legacy log
  (235,776 bytes retained unchanged, 9,049 appended); no automated witness yet,
  and it belongs in the migration matrix rather than a unit test.
- AC-5: (REQ-2, REQ-1) A workspace an older kan wrote, then written to by this
  build, keeps every claim it had — compared as CID sets, because a rebuild that
  drops one claim while adding the new one leaves the count plausible.
  *Witness:* `scripts/run-migration-cell.sh`, the upgrade-write step, run for
  every cell of the 64-row matrix that otherwise passes. Note this asserts data
  preservation rather than canonical shape: shape is pinned by AC-3, and
  preservation is the guarantee the matrix exists to give.

## Architecture

`Mst::insert` in `src/mst/tree.rs` rebuilds the tree canonically from a full
walk rather than splicing a path, because an MST's shape is a pure function of
its key *set*. The module contract and the two crate failures behind it are in
`src/mst/mod.rs`; the caller is `Log::append_locked` in `src/store/log.rs`.
Three steps, in order, and the order is the design:

1. **Walk** — `entries()` visits every entry unconditionally, so it returns the
   complete key set even from a tree a non-conformant writer has touched.
2. **Sort** — restores the ascending order `build_canonical` requires. This is
   the repair; without it the disorder is baked into the rebuilt tree.
3. **Build, then verify** — `build_canonical` partitions by index range, and a
   post-condition walks the result and compares it against the input.

The post-condition is deliberately on the *result*. A pre-condition can only
reject shapes someone already imagined, and the failure this design exists for
was found by diffing key sets before and after — no inspection of the input
would have predicted which key ordered descent would lose.

## The headline: there is no migration step

The first write under the conformant code produces a canonical tree by itself,
because `insert` rebuilds from the entry walk. Measured on a synthetic
old-format log (60 claims written by an unpatched binary, then one conformant
write):

| | before | after |
|---|---|---|
| root node | 60 entries, 6,147 B | 4 entries + 4 subtree pointers, 652 B |
| shape | flat | tree |
| prior claim CIDs | 60 | **60 present, 0 missing** |
| CAR | 235,776 B | 244,825 B |

**The old CAR is a byte-exact prefix of the new one.** Nothing is rewritten;
9,049 bytes are appended. That property is what makes this safe, and it is
worth stating as the design's central constraint: *migration is an append.*

Three things fall out of it:

- **No commit is re-signed.** Nothing in kan walks the commit `prev` chain (the
  only match in the tree is an unrelated TID test), so historical commits need
  no rewriting. This matters on provenance grounds, not just convenience:
  re-signing history with the current key would silently re-attribute
  attestations made under a key that had since rotated. A provenance tool must
  not do that.
- **Old flat nodes are retained**, still referenced by the old commits. They are
  raw attested data, and `telos/raw-data-and-projections` says retain it. The
  20× shrink therefore applies to *future* growth, not retroactively — from
  ~11 MB, linear growth at ~3 KB/claim leaves roughly 30,000 claims of headroom,
  so the cliff is gone regardless.
- **The overlay needs nothing.** `src/workspace.rs:101` documents it as
  disposable and rebuilt from `.claims/`; `src/workspace.rs:49` calls
  `rm -rf .kan/overlay .kan/index.sqlite` safe. Scope is `log/repo.car` alone.

## The defect this design exists for

**A claim written by an old flat-MST binary into a canonical tree becomes
invisible to reads** while remaining present in the log and in the MST.
Orphaned, not destroyed, and fully recoverable.

Two earlier explanations of this were published and both were wrong. They are
recorded here because the way they failed is the transferable part: each was a
plausible reading of the code, and each was killed by measuring the key set
rather than reasoning about it.

**Mechanism, each step measured:**

1. The old binary inserts a key into the root's entry list by sort order,
   ignoring layer. The claim is still findable at this point — fold reports 41.
2. `collect_entries` visits every entry **unconditionally**, so `entries()`
   returns the complete key set, 41 of 41. Nothing is invisible to the walk.
   *(This killed explanation one: "the walk can't see it.")*
3. But the misplaced key is emitted at its wrong **tree position**, so the
   returned sequence is not strictly ascending — the break was at index 36.
4. `build_canonical` requires sorted input; it partitions by index range. Handed
   the unsorted list it builds a tree where every block is still reachable by a
   full walk (42/42) but one key sits in a sub-tree whose range does not contain
   it, so **ordered descent** cannot reach it (41/42 findable). That is the
   loss: of findability, not of data.
5. Structural, not cached — deleting `.kan/index.sqlite` and re-folding still
   reports 41, missing exactly the old binary's key.
6. Recoverable — rebuilding from the same key set **sorted first** restores
   42/42 to ordered descent.

*(Explanation two — that `binary_search_by` over an unsorted slice returned a
spurious `Ok` and overwrote a pair — also died: simulated over the actual walk
output across 2,000 trials it lands correctly 95.3% of the time, because only
one element is out of place.)*

**This is not hypothetical.** kan 0.12.0-beta.2 is installed at
`~/.cargo/bin/kan`; `day` shells out to whatever `kan` is on `PATH` (ADR-42);
CI pins versions. Any upgrade window has both binaries writing one log.

## The fix is repair, not refusal (landed)

`insert` sorts the walk output before building. That one step heals a log an old
binary has written into rather than propagating the disorder. Measured end to
end: canonical tree → fold 40; old-binary write → fold 41; conformant write →
**fold 42, with the old binary's claim visible again.**

An earlier version of this design refused the write instead. That was the wrong
remedy for a problem I had mischaracterised: it blocked writes to logs that are
completely repairable. It has been removed.

What replaced it is a **post-condition**: the rebuilt tree is walked and its key
sequence compared against the input, and the write is refused if they differ. A
pre-condition can only reject shapes someone already imagined — and no
inspection of the input would have predicted *which* key ordered descent would
lose. That was found only by diffing the key set before and after. The
post-condition rejects any rebuild that failed to preserve the data, whatever
caused it.

| scenario | result |
|---|---|
| legacy flat log, conformant write | succeeds, 30/30 preserved |
| canonical tree, old binary writes | readable, claim visible |
| corrupted tree, conformant write | **repairs it**, fold 42/42 |

## Open, and deliberately not built yet

1. **Repair on read, or only on write?** Sorting fixes the tree on the next
   *write*. A log that is only ever read stays orphaned — its claim invisible —
   until something writes to it. Whether a read should report the anomaly (it
   can detect it cheaply: walk order not ascending) is undecided. It should
   probably warn, since a silently-invisible claim is exactly what this whole
   subject is about.
2. **Preventing the disorder instead of repairing it.** A format marker that old
   binaries would refuse to write past cannot be retrofitted into binaries
   already shipped. The honest mitigation is release-note guidance plus the
   repair. Worth deciding whether beta.4 should warn when it detects an older
   `kan` earlier on `PATH`.
3. **What the matrix's upgrade write may reveal.** The step is gated on a cell
   otherwise passing, so no healthy row can flip for an environmental reason.
   But it has never run on the keychain axes in CI: a cell there proves the read
   and `identity did` both work, which is not the same as proving this build can
   *sign* in that workspace. If keychain rows come back `write-refused`, that is
   a real finding — read-but-not-write on an upgraded keychain workspace — and
   should be recorded as an outcome, not papered over by dropping the check.
4. **Compaction.** Pruning blocks unreachable from HEAD would reclaim the old
   flat nodes. It is not needed for the cliff and it deletes retained attested
   data, so it is a separate decision under
   `telos/raw-data-and-projections`, not part of this work.

## What must be true before this touches a real log

- [x] Claim CIDs preserved across the shape change
- [x] Old CAR bytes retained unmodified (prefix property)
- [x] Read-invisibility path found, reproduced, mechanism measured, and repaired
- [x] Post-condition rejecting any rebuild that does not preserve the key set
- [x] kan's suite green (416 tests, 67 binaries)
- [ ] Decide whether reads should warn on a disordered tree
- [ ] Migration-matrix rows updated
- [ ] Run against copies of kan's and day's real logs, with the identity those
      logs actually use (both are keychain-backed; the synthetic tests used
      seed-file identities in temp dirs)
