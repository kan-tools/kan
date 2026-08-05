# Post-mortem: the v0.11 review loop

Five cold adversarial reviews, five blocking verdicts, seven fix commits, and
the milestone ended no closer to shipping than it was after the first one. The
code is fine — better than v0.10 in every dimension the reviews examined. The
*loop* was the failure, and it was mine.

This is about the loop. The design cause of the defects themselves is
`.design/identity-resolution.md`.

## What happened

The milestone's ten requirements shipped across five PRs, all merged, all
green. Before merging the last one, a cold review (fresh agent, no inherited
context, given the artifacts rather than the author's account) returned
REDIRECT with three blocking findings. Those were fixed. A second review of
the fixes returned BLOCK. Those were fixed. So did the third, fourth, and
fifth.

Every blocking finding from round two onward was in identity resolution, and
every one was introduced by the previous round's fix.

## Four things that went wrong

### 1. Each review was treated as a work queue, not as evidence

A review returns findings, so the obvious response is to fix findings. Doing
that five times in a row never asks the question the *set* of reviews was
answering: **why is it always the same subsystem?**

The signal was available at round three. It was even noticed — the round-three
summary says "given the pattern, I'd run one more cold review rather than
assume this is the one that converged." That is pattern recognition followed
by another iteration of the thing the pattern says will not work.

**Rule:** if two consecutive reviews find defects in the same subsystem, stop
fixing and go specify. The third finding is not a third bug; it is the second
piece of evidence that the area has no specification.

### 2. Patching an unspecified space generates one defect per patch

Identity resolution has ~30 reachable configurations (`KAN_IDENTITY_FILE` ×
key file × seed × `seed-id` × keychain × roles × log state, for reads and
writes). None were written down. Every fix addressed the cell the review had
found and was locally reasonable; each revealed the next cell, because there
was no map.

This is not a hard problem — it is a table. It was never built, in five
rounds, while five patches were.

**Rule:** before the second fix in one area, write the table.

### 3. Claims outran verification, in one specific and repeatable way

Round five's sharpest finding was not a code defect. Three revert probes were
run; each turned exactly one test red; the commit message then said "each
verified by revert the hunk, watch exactly that test go red." The *mapping*
was never checked. Reverting the round-four B1 hunk turned a different test
red — the B1 test's setup never constructed the state it named, so it passed
with its own fix removed.

An aggregate was verified (one failure per probe) and a specific was reported
(each test defends its hunk).

The same shape recurs across the milestone: read performance measured and
reported while write performance silently doubled; `roles` narrowing asserted
while the primary was auto-declared all along; "the two paths agree claim for
claim" written into a comment about two paths that did not.

**Rule:** state exactly what was checked. If the check was "one test failed",
say that — not "the right test failed".

### 4. BLOCK was read as "must fix now" rather than "must triage"

The reviews were deliberately unbounded: *hostile by default, find defects*.
Against a 5,000-line milestone that always succeeds — which is what they are
for. Treating every BLOCK as a gate meant every round produced fixes, and
every round of fixes produced the next round's findings.

Some findings were data-safety (a claim written under an identity the caller
did not ask for). Some were quality (a stale comment, a weak assertion). They
got the same response.

**Rule:** triage before fixing. Data-safety findings block. Quality findings
get filed. And ask the *shippable* question — "is there a path where data is
lost or misattributed?" — separately from the *unbounded* one.

## What went right, and should be kept

- **Cold reviews work.** Five rounds, five real defects, several of which
  would have shipped. Two — a claim written under a fabricated author, and a
  seed-rooted workspace re-minting and permanently shadowing its identity —
  were the kind this project exists to prevent.
- **Giving the reviewer artifacts and not the author's account.** Both rounds
  where the author had "already reasoned about and stopped" were found by a
  reader who had not.
- **The revert-the-hunk discipline**, once adopted, immediately caught two of
  the author's own tests being wrong — including one written *while* writing
  tests to fix untested code.
- **Recording decisions in kan as they were made.** None of the analysis
  depended on any one session's context surviving.

## The rules, collected

1. Two consecutive reviews finding defects in one subsystem ⇒ stop fixing,
   specify.
2. Before the second fix in one area, write the table.
3. State what was checked, not what was intended. Verify mappings, not
   aggregates.
4. Triage: safety blocks, quality gets filed. Ask the shippable question
   separately from the unbounded one.
5. A fix answering a review ships with a test that fails without it —
   already in `CLAUDE.md`, and worth keeping there.

## Cost

Five review cycles and seven fix commits, against a subsystem that needed one
specification pass. The reviews were not the expensive part.
