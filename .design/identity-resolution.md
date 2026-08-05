# Design: identity resolution — one question at a time

## Why this exists

Five cold adversarial reviews of the v0.11 milestone returned five blocking
verdicts. Every blocking finding from the second round onward was in one
place — identity resolution — and every one was *introduced by the previous
round's fix*:

| round | blocking finding | introduced by |
|---|---|---|
| 1 | `restore` mints before refusing; index incoherence; REQ-6 half-done | the milestone |
| 2 | fixes shipped with no tests; `restore`/`adopt` dead end | round 1's fix |
| 3 | the fix moved the mint one layer down | round 2's fix |
| 4 | substitution fabricated authorship; guard blind to `seed-id` | round 3's fix |
| 5 | refusal depended on evidence; read still substituted | round 4's fix |

Nothing in the milestone's actual deliverables — `TrustBase::Local`, the
read-only workspace, the `--trust` vocabulary, `publish`, the `origin` column
— was blocked after round 1. Five reviews confirmed those sound. The defect
generator was the patching, not the code being patched.

This document is the "stop patching and specify" pass. It is not a fix.

## The pattern, stated once

**kan conflates three different questions into one function, and answers them
with side effects.**

1. **Which identity does this workspace *have*?** A fact about `.kan/`.
2. **Which identity should sign *this write*?** A selection — primary, or a
   declared role.
3. **May kan *create* one?** An authorization question, guarded by ADR-77.

`Identity::load_or_create` answers all three at once. Everything below follows
from that.

### Consequence 1 — the env var means "select", but is implemented as "redefine"

`kan identity role add`'s own help says it plainly (`src/cli/mod.rs:408`):

> Afterwards, run kan with `KAN_IDENTITY_FILE` set to the role's key **to
> write as that role**.

That is question 2: *sign this write as this identity*. It is implemented as
an override of question 1: *this workspace's identity is now this file*.
Every round's defect is that substitution showing through.

- A **selection** whose target is missing is obviously an error — you asked
  to write as a role and the role's key is gone. A **redefinition** whose
  target is missing means "this workspace has no identity", which invites
  creating one. That is round 5's B2: kan minted a fresh key at the missing
  role's path and signed a claim with a DID no `.kan/roles` line mentions, so
  `--trust roles` reported nothing on the subject just written.
- A **selection** is orthogonal to what `adopt` writes, so the two cannot
  shadow each other. A **redefinition** means an adopted `.kan/identity` is
  invisible while the variable is set — rounds 2 and 3's `adopt` → `restore`
  dead end, twice.
- A **selection** is validated against `.kan/roles`, the registry of valid
  selections. A redefinition has no reason to look there, and did not — which
  round 4's commit message named as the cause and round 4's code still did not
  do.

### Consequence 2 — asking question 1 has side effects, so question 3 sees them

`keychain_account` (`src/sign.rs:561`) **writes** `.kan/identity-id` while
resolving. So the guard for question 3 can observe state created by asking
question 1. Widening the guard's evidence to include `identity-id` made it
fire on evidence its own invocation had just written, turning every first-run
keychain workspace into a refusal — caught only because five pre-existing
tests went red.

A pure "what does this workspace have" cannot do that.

### Consequence 3 — question 1 has two implementations, and they drift

Because `load_or_create` cannot answer question 1 without also answering 3
(it may create), v0.11 needed a read-only variant and grew a second
implementation: `existing_identity`. Two implementations of one fact, with no
shared definition, drifted immediately and repeatedly:

| | read (`existing_identity`) | write (`load_or_create*`) |
|---|---|---|
| round 2 | learned `.kan/identity` | did not |
| round 3 | — | substituted `.kan/identity` |
| round 4 | key file → seed | seed → key file |
| round 5 (now) | override → seed → key file | override → seed → **keychain** → key file |

The last row is still open (#170): on the default macOS layout — `identity-id`
present, no key file, no seed, which is *this repository's own* — `kan
identity did` resolves and `--trust me` reports no identity.

### Consequence 4 — the guard's evidence set is a proxy for question 1

`refuse_second_identity` asks "does this workspace already have an identity"
by enumerating files: a non-empty log, `.kan/identity`, `.kan/seed`,
`.kan/seed-id`. That enumeration is a hand-maintained approximation of
question 1, and it has been wrong in both directions — blind to `seed-id`
(round 5's B3: a seed-rooted workspace with a cleared log was re-minted and
its identity permanently shadowed), and self-triggering on `identity-id`.

If question 1 had one answer, the guard would be
`workspace_identity(kan_dir)?.is_some()` and would have no evidence set to get
wrong.

## The shape this asks for

Three functions, each answering exactly one question, none with side effects
except the one whose job is to write.

```
workspace_identity(kan_dir) -> Result<Option<Identity>>
    // Question 1. Pure. Never creates, never writes, never migrates.
    // ONE precedence order, used by reads and writes alike.
    // The keychain is part of this or it is not -- but it is the same
    // answer for both sides either way (#170 is the choice of which).

signing_identity(kan_dir, selection) -> Result<Identity>
    // Question 2. `selection` is Primary | Role(name) | KeyFile(path),
    // parsed from KAN_IDENTITY_FILE and `.kan/roles`.
    // A selection naming something absent is an ERROR, always -- never a
    // reason to create, never a reason to fall back to something else.

create_workspace_identity(kan_dir) -> Result<Identity>
    // Question 3. The ONLY function that writes. Refuses when
    // `workspace_identity` already returns Some -- which is the whole of
    // ADR-77's guard, with no evidence set to maintain.
```

The properties that fall out, rather than being patched in:

- Reads and writes cannot diverge — one implementation of question 1.
- A missing role key is an error — selections do not fall back.
- `adopt` and `KAN_IDENTITY_FILE` are orthogonal — one changes the workspace's
  identity, the other selects among identities.
- The guard cannot be blind or self-triggering — it has no evidence set.
- Resolution has no side effects, so nothing observes state that asking
  created.

## What this is not

Not a rewrite of `sign.rs`'s crypto, keychain handling, seed derivation, or
recovery phrases — all of which the reviews left alone. This is about the
*resolution* layer sitting on top of them.

Not ADR-75's author→claim trust generalisation, and not #164's medium work.

## Sequencing

**v0.12**, alongside #164 and B1 (the origin-aware fold), because it wants
the same thing they do: a specification before code.

Two things it must ship with, learned the expensive way:

1. **The full cell table, tested.** Inputs are `KAN_IDENTITY_FILE`
   (unset / present / naming a missing path) × `.kan/identity` × `.kan/seed` ×
   `.kan/seed-id` × keychain reachable × `.kan/roles` entry × log empty or not,
   for reads and writes. Roughly thirty cells, most collapsing. Every defect
   in this milestone lived in a cell nobody had enumerated.
2. **Every cell asserted, and each assertion verified by reverting its own
   hunk** — per `CLAUDE.md`'s "Workflow: answering a review". Round 5 found a
   test that did not test its own fix because the mapping was assumed rather
   than checked.

Do it in a fresh session with this document as the input, not with the
accumulated context of the five rounds — for the same reason the reviews were
run cold.

## Interim state, v0.11

Identity resolution is left exactly as it is. It is strictly better than
v0.10 — #149, #90, #153 and #136 are closed and reviewed — with one known,
filed gap (#170). The next change to this area should be the specification
above, not another patch.
