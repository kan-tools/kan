<!--
Behaviour changes should already have an issue and a design pass
(.design/<slug>.md). Typo/link/comment fixes can ignore most of this.
-->

## What this changes

<!-- One or two sentences. What is different after this lands. -->

Closes #

## Evidence

<!--
Not "tests pass" — what did you run, and what did it show? Paste the output
that would be different if this were wrong.
-->

- [ ] `just test`
- [ ] `just lint` (clippy `-D warnings` + `cargo fmt --check`)

## If this answers a review or fixes a defect

- [ ] A test ships in this commit that **fails without the fix** — verified by
      reverting the fix and watching it go red, not by writing it afterwards.

## Invariants

Confirm none of these is broken, or say which one and why it is right anyway:

- [ ] No operation destroys a subject; the log stays append-only.
- [ ] The fold still reads morphisms and mutates nothing.
- [ ] The fold is still a pure, deterministic function of (claims, enrichment).
- [ ] No `cites` edge is fabricated or dropped.
- [ ] No second UI; the surface is still CLI + MCP.

## Notes

<!--
Anything a reviewer would otherwise have to discover: a decision you made that
could have gone the other way, something you deliberately did not do, an ADR
this needs, or a change touching `.claims/` (those files are verified by CID and
signature, not by review).
-->
