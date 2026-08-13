# ADR 0059: The reader: `Log::ingest`, and a foreign-author overlay beside the log

- Status: Accepted
- Date: 2026-07-30
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-59

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

**Date:** 2026-07-30
**Status:** Accepted

**Decision:** `.design/v0.8-milestone.md` REQ-1/REQ-2, closing #97. `Log::ingest`
inserts a fully-formed `StoredClaim` verbatim — same content, same CID, same
signature — after verifying it against **its own** `content.author.did`.
`Workspace::open` reads the tracked `.claims/` tree through
`GitTree::read_all_with_rev` and ingests every **foreign-authored** record into
a new overlay log at `.kan/overlay/`, which the index rebuilds over alongside
`log/`.

**Why `append` could not be this.** `append_locked` signs with the *local*
identity, so pushing a foreign claim through it reproduces the content CID and
replaces the signature — after which `get_stored`'s own-author verification
rejects the very record it just stored. A round trip that silently invalidates
its input is worse than a missing feature, which is why REQ-1 asked for a
separate primitive rather than a flag on `append`.

**The commit stays signed by the local identity, and that is correct.** A
commit attests to the *repo's state*, which this process genuinely is
asserting; each record keeps its own author's signature. Conflating those two
attestations is exactly what made `append` unusable here.

**Why an overlay rather than one log.** `log/repo.car` stays *claims I
authored*, which is what atproto repo semantics require and what a future
HostedRelay/AppView reads from; mixing another actor's records into it would
make the local log unshippable as a repo, invisibly. `tests/reader.rs` asserts
`repo.car` is **byte-unchanged** across an ingesting read, and inverting the
destination fails exactly that test while every read-level test still passes —
which is the point: the separation is invisible to reads, so only a control
catches it.

**The overlay is disposable, like the index.** Everything in it is
reconstructible from `.claims/`. That is what makes refreshing it during
`Workspace::open` acceptable where mutating `log/` on a read path would not be
— the existing rule ("a read command must not modify the log", `Log`'s own
`needs_repair`/`head_stale` comments) is about the source of truth, and this
is derived data.

**Three constraints the ingest pass is written around.**

1. **No write lock unless something is new.** Membership is checked against the
   already-open overlay first, so the common case — nothing published since
   last time — costs a directory read and no lock. `Workspace::open` runs on
   every invocation, and day#123 measured it as already the dominant per-call
   cost; a lock acquisition per command would be a real regression.
2. **A bad record warns and is skipped, rather than failing the workspace.**
   `.claims/` is *tracked*, so anyone can hand-edit it and a bad merge can
   mangle it. Both halves are asserted: the tampered claim never enters a view,
   *and* one broken record does not take out every `kan` command in the repo.
3. **Ingest is idempotent.** A re-read leaves the overlay byte-identical;
   otherwise it would grow without bound across invocations.

**Records published before v0.7.0-beta.1 carry no `rev`.** They fall back to
the content CID, which keeps ordering *deterministic across clones* — every
reader derives the same value from the same bytes — where a locally generated
TID would not. It orders such claims apart from timed ones rather than
inventing a time nobody recorded.

**The index fingerprint now covers two stores.** With no overlay it is the
log's root unchanged, so an index built by an earlier version stays valid and
upgrading forces no spurious rebuild; once an overlay exists both roots are
hashed together, preserving the original skip's property — not "probably
fresh", provably fresh (issue #26).

**Consequences:** `GitTree::log` becomes `Option<Log>` so `new_reader` can
build the read half without contriving a log for it; `publish` on a reader
panics rather than silently writing to a log that was never supplied. Splitting
the trait in two is the type-level fix and is worth doing when `HostedRelay`
gives a second implementation to design against. Restore (`.design/
durability-log-recovery.md` REQ-2/REQ-3) is **not** here: pulling one's *own*
claims back out of `.claims/` needs the identity check REQ-3 specifies, and
ships in v0.9 on this same primitive (Q1).
