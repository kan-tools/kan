# ADR 0049: The pre-release review: what it found, and what the record got wrong

- Status: Accepted — corrects claims made in ADR-48 and `docs/SPEC.md` §7.1
- Date: 2026-07-22
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0000 migration.
- Original-number: ADR-49

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

**Date:** 2026-07-22
**Status:** Accepted — corrects claims made in ADR-48 and `docs/SPEC.md` §7.1

**Context:** an independent adversarial review of the v0.7 release candidate,
run before the release PR was cut, returned **BLOCK**: nine defects, three of
them data loss, three acceptance criteria failing, and several claims in the
record that the code did not support.

**The finding that matters most is that ADR-48's own thesis held, against
ADR-48.** That thesis: *kan is correct where the design attention went, and
absent everywhere data is keyed, framed, or rendered.* Two of the three worst
defects were in code **this release added**, in exactly those modules, and one
was in the recovery path written to satisfy REQ-4. Fixing a boundary is not
the same as crossing it.

### The recovery code created a worse defect than the one it fixed

After a tolerant read of a damaged CAR, `persist_new_blocks` still opened the
file `append(true)` and wrote *past* the damaged region, so every subsequent
block was unreachable to the same tolerant read that had recovered the rest.
Six appends after a truncation all returned success and all vanished.

v0.6 bricked reads on a torn tail — loud, and recoverable. v0.7 converted that
into **silent, unbounded, permanent loss at exit 0**. The CAR is now repaired
before the first write past it, under the write lock, never on open.

**And the test could not fail.** It appended after recovery and asserted
against the *same in-memory* `Log`, whose MST is in RAM, so the count was `+1`
by construction. It now drops the `Log` and reopens from disk; disabling the
repair makes it fail.

This is the sharpest available correction to ADR-48's claim that *"every
concurrency and corruption test in this release is now checked by disabling
the fix and confirming the test fails."* The concurrency test was. The
corruption test was not, and its author believed otherwise. **A negative
control asserted in prose is not a negative control.**

### A read command could roll the log back

`open_or_create` read the CAR and then `HEAD`, neither under the lock, so a
concurrent append between them left a reader holding an old CAR and a new
`HEAD` — a torn view of a healthy log — whereupon the recovery path fired and
rewrote `HEAD` backwards with a plain `fs::write`. Reads now re-read both
before concluding damage and **never write**: a recovered root is held in
memory and persisted by the next append under the lock. The doc comment
claiming readers "never see a torn state" was false and is corrected in place.

### `publish`'s fix broke the layer below it

Folding before publishing was right — it filters retracted and untrusted
claims (REQ-12). But the fold's unit is the merge *class*, so taking its
output wholesale put every `SameAs`-merged subject's claims into each of their
files, duplicated every claim, and made publishing one subject rewrite
another's file. **Decision: a `.claims/<subject>.md` file is subject-exact.**
The merge still travels — as the `SameAs` claim, published like any other and
folded on read — which is where kan puts everything else. That decision is
what made REQ-13's second half (authenticate the filename against the records)
implementable at all; it is now implemented, having been silently dropped.

### Claims corrected

- ADR-48 said *"relations visible from both ends."* False for the case REQ-21
  states: `inbound_edges` sat inside the arm for subjects that have a merge
  class, and a subject with no claims of its own has none. Relations are
  precisely the thing that can arrive before a subject does. Fixed.
- ADR-48 said *"descriptions that stop promising what the surface cannot
  deliver."* `schemars` rationale still shipped in seven tools' schemas via
  `SubjectKind` — the identical fix was applied to `StatusValue` twelve lines
  below and missed. Fixed.
- ADR-48's honesty note on deletion detection conceded only that *"an editor
  who rewrites every remaining record's `seq`/`of` defeats it,"* framed as an
  adversary. **kan's own `publish` is that editor**, which makes the accidental
  republish case — the one REQ-10 names in its own text — exactly what the
  mechanism cannot catch. Filed rather than patched: honest detection needs
  the publisher to sign over the record set.
- `docs/SPEC.md` §7.1, amended in this same release, mandates a test
  constructing a *known* kind with an unknown field. The behaviour works; the
  mandated test did not exist. Filed.
- REQ-18 was reinterpreted from "resolve a retraction's target" into "accepts
  CID syntax" — it searched the live view, which by definition excludes the
  retracted claim it exists to show. Fixed by searching the log.
- The `KAN_IDENTITY_FILE` branch lacked the refuse-to-mint-a-second-identity
  guard the keychain branch had, so following `KeychainUnreachable`'s own
  recommended remedy produced a new DID and "no subjects yet" at exit 0 —
  verbatim REQ-5's failure mode via the release's own advice. Fixed.

### Process

**PR #89 shipped without an ADR**: encryption-at-rest reversed ADR-25's
explicit decision, added a top-level `identity` verb outside ADR-32's
vocabulary, and sat outside all 24 REQs — at the tail of a release whose theme
is that provisional patches cause data loss. This ADR supersedes ADR-25's
"leave the plaintext file in place" and records `identity` as setup/tooling
alongside `mcp`, not a fifth phase of the claim-graph vocabulary.

**Two decided items were lost in a re-scope** — the stale-binary error message
and the subject-argument unification — both recorded as decisions in kan's own
log, neither carried into the design doc, which was written from the session
rather than from the log. The error message was recovered only because the
defect it fixes caused a false data-loss alarm hours later. Nothing in `day
design check` compares a design doc against the `decide` claims already on its
subject; that gap is filed against `day`.

**The design doc's own escape condition was met and not fired.** It said the
GitTree reader moves into v0.7 if REQ-9, REQ-10 or REQ-13's criteria could not
be demonstrated without a shipped reader. All three required linking the crate
directly. The condition is now acknowledged: the reader stays in v0.8, and the
release states plainly that those three ACs are demonstrated at the library
level only. Leaving a stated condition silently unfired is how a design doc
stops being evidence.
