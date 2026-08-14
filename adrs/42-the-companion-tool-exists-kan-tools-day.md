# ADR 42: The companion tool exists: `kan-tools/day`

- Status: Not recorded contemporaneously
- Date: 2026-07-21
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-42

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
**Context:** ADR-18 drew the kan/companion-tool boundary rule and named a
"future, separate companion tool" to receive everything that fails it —
session orchestration, interactive design authoring, code-review
orchestration. It deliberately did not build one (issue #24 tracked the
scaffolding, issue #48 the adversarial-review skill). Both are now closed:
the tool exists, is published, and this ADR records what that settles so
`CLAUDE.md`'s scope section and ADR-18's "if and when it's built" hedge
stop being the only account of it.
**Decision:** the companion tool is **`day`** (`kan-tools/day`, published to
crates.io, v0.1.2-beta.1 at time of writing). Named for Brian Day (Sydney
school): Day convolution is built from Kan extensions/coends and is what
gives profunctor composition its monoidal structure, so the lineage sits
directly next to Kan's — three letters beside `kan`, and `day plan`/`day
review` read as the daily practice of development. It is a Rust CLI
(`init`/`doctor`/`hook`/`mcp`) packaged as a Claude Code plugin, whose
primary dev-flow integration is harness-level hooks.
**What it proves about ADR-18's rule:** the boundary held under a real
implementation, which is the only test that counts. day needed **no new
`ClaimBody`/`ClaimKind`/`Anchor`/`RelationKind` variant**. Its entire
schema is a set of subject-naming conventions over kan's existing verbs:
teloi on `telos/<slug>` subjects, process atoms on `atom/<slug>` subjects
carrying a fenced `day-atom` JSON interface block, assessments as
`observe`/`result` claims citing evidence CIDs. day keeps no store of its
own, and talks to kan by **shelling out to the `kan` binary** rather than
linking it as a library — so the boundary is enforced as the same public
CLI contract any other consumer gets, not as a convention day could quietly
erode. ADR-18's narrow-exception carve-out (kan may describe its own
interface) is unaffected.
**Migrations completed:** `.claude/commands/design.md` — flagged as tech
debt by ADR-18 — is now also shipped by day as its "generative closed-loop
design" atom. Issue #48's adversarial-review skill was built there rather
than here, as that issue anticipated. kan's copy of `design.md` stays for
now, since day's repo is private and therefore not `/plugin install`-able
by anyone else yet; its banner now points at day instead of at a
hypothetical future tool, and a real bug in it was fixed in passing (it
instructed agents to pass file paths to `--cites`, which takes claim CIDs
and errors on a path — found live while recording this very work into kan).
Full retirement in favour of a pointer is deliberately deferred until the
plugin path actually works for a third party.
**What this puts back on kan:** two things surfaced from the other side of
the boundary. (1) `RelationKind` has no edge for "in tension with", so
tension between teloi — the central relation in day's model, and what makes
teloi more than a values list — is unqueryable prose. That needs a new
`RelationKind` variant, which by ADR-18's own rule is **kan's** to own, not
day's to work around; it blocks day's v0.5 frames work. (2) day's v0.2 will
write through kan's public CLI (`kan decide`/`observe`/`result`), making
kan's write-verb ergonomics and error messages a dependency of a *program*,
not only of agents.
**Consequences:** `CLAUDE.md`'s "Scope boundary: kan vs. a future companion
tool" section is updated to name day and drop the future tense — living
documentation, same practice ADR-18 used when it superseded ADR-7's
vocabulary line. ADR-18's own historical text is left as-is.
