# ADR 91: A historical writer is defined by what it builds, not by its name

- Status: Accepted
- Date: 2026-08-11
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-91

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

**Date:** 2026-08-11
**Status:** Accepted

**Decision:** The migration matrix selects its historical writers by *content*:
a released tag is a writer iff it builds something other than this build,
approximated by the `(src tree, Cargo.lock, Cargo.toml)` triple — the same
triple already hashed into the reader cache key, for the same reason. The rule
lives in `scripts/select-migration-writers.sh`. The older ref-name exclusion is
kept beside it, because it states the intent directly and still holds if a
release is ever cut where the tag and HEAD disagree on content.

**Why, demonstrated rather than argued.** kan#205 recorded that protect-filed
keychain entries were "nondeterministically readable across binaries", measured
five times over two days, and proposed a runner-image correlation three times.
Read per *job* rather than per run, there is no nondeterminism. The macOS image
is identical across all five runs (`macos-26-arm64`, `20260728.0273`) and every
sampled job executed rather than hitting the outcome cache — which had to be
checked first, because a cached cell replays an earlier run's answer and would
have made any correlation meaningless. It is not run-level either: in run
31439573855 alone, `v0.12.0-beta.1 keychain` measured `ok` while
`v0.11.0-beta.1 keychain` measured `keychain-blocked`.

One rule fits every cell: `ok` occurred exactly when the writer tag's triple
equalled the reader HEAD's. The census is complete rather than sampled, because
a cell can measure `ok` without failing its job only if its committed row
expected `ok`, and those rows were enumerated from the expectations table *at
each run's own commit* — expectations changed between runs, so job colour is not
a proxy for outcome. Four `ok` measurements exist in the whole dataset; all four
satisfy the rule, and the ~150 cells that differ from the reader produced none.

**The apparent alternation was the event type.** `ok` needs the matrix to
contain a tag whose triple equals HEAD's, and on a tag push that tag is exactly
the one excluded — so a tag push can never produce it. The five runs were
dispatch, push, dispatch, push, push, which is the recorded
`ok/blocked/ok/blocked/blocked` and nothing more. The theory died because it was
never about time.

**What was broken was the instrument, not the keychain.** When the triples
match, the cell is not testing an upgrade: it is one binary reading a keychain
entry it created itself, scored `ok`, which the table then reads as migration
working. This is the `keychain-unused` lesson one level up — that outcome exists
because a cell which did not exercise the keychain plane must not be scored
`ok`, and the same holds for a cell which did not exercise an *upgrade*. An
instrument must prove it measured what it claims, which is also ADR-90's rule
wearing different clothes.

**Selection, not outcome, and the distinction is load-bearing.** An excluded tag
has no cell, so `tests/fixtures/migration-expectations.tsv` stays a function of
`(tag, mode)`. Scoring the collision as a new *outcome* would have made a row's
expected value depend on whichever commit happened to be HEAD — a table that
cannot be read without knowing what ran it.

**Consequence.** Selection moved out of inline workflow shell so that
`tests/migration_writer_selection.rs` can drive the real rule rather than a Rust
restatement of it; a test agreeing with its own copy of the logic would have
agreed with the bug. With the content check reverted, three of its five tests
fail — including the one pinning the misreading this defect was built on, since
v0.12.0-beta.1 and beta.2 share an identical `src` tree and differ only by the
version bump. A version string is a different binary. The script joins the
harness hash, and exclusions are announced as job notices: a matrix that
silently drops rows reads as "covered everything" while covering less.

**What this does not establish.** The mechanism remains a hypothesis — identical
source and manifests should compile to the same binary, hence the same ad-hoc
signature, hence a keychain ACL the reader matches without a prompt, which is
kan#96 working as designed. The cell builds writer and reader in different
directories and cargo's `-C metadata` takes the package source path, so
byte-identity is not proven. The correlation does not depend on it, and the
causal claim is not recorded as measured until CI tests it. Note also what this
clears: the keychain rows' pin to the blocked side is correct and stable for tag
pushes, which are what gate a release. The gate never carried a coin flip, and
ADR-78's lesson — that a permanently red gate is one nobody reads — is not in
tension with keeping it.
