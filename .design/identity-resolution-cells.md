# Identity resolution: the cell table

`.design/v0.12-milestone.md` REQ-6, and `docs/POSTMORTEM-v0.11-review-loop.md`'s
second rule — *before the second fix in one area, write the table.* Five
review rounds patched this space; none enumerated it.

**This describes kan as it is at `a14b585`, not as REQ-1 will make it.** It is
the before-picture. Every cell REQ-1/REQ-2/REQ-3 changes should be visible as
a diff against this document and against `tests/identity_cells.rs`.

## The two procedures, derived from source

Question 1 — *which identity does this workspace have* — has two
implementations today, which is the defect `.design/identity-resolution.md`
names. Here they are side by side.

### Read: `sign::existing_identity` (`src/sign.rs:839`)

```
R1  KAN_IDENTITY_FILE set?
      exists   -> that key                         [never consults the keychain]
      missing  -> None                             [silently; not an error]
R2  Seed::load:
      .kan/seed present                 -> seed-derived key
      KAN_NO_KEYCHAIN                   -> None, fall through
      .kan/seed-id + keychain reachable -> seed from keychain -> derived key
      .kan/seed-id + keychain error     -> Err(KeychainUnreachable)
R3  .kan/identity present -> that key                (`load_existing`, cannot mint)
R4  otherwise -> None
```

**The read never consults the keychain for the signing key.** Only for a
*seed*, and only when `.kan/seed-id` exists. That single fact is #170.

### Write: `Identity::load_or_create_for_workspace` (`src/sign.rs:488`)

```
W1  KAN_IDENTITY_FILE set -> load_or_create:
      missing + named in .kan/roles -> Err(DeclaredRoleKeyMissing)
      missing                       -> guard, then MINT at the override path
      exists                        -> that key
W2  Seed::load (identical sub-cases to R2) -> seed-derived key
W3  fresh = !.kan/identity && !.kan/identity-id
      not fresh -> load_or_create (env unset):
          KAN_NO_KEYCHAIN:
              no key file -> guard, then mint
              key file    -> that key
          keychain:
              keychain_account() WRITES .kan/identity-id   <- side effect
              entry found          -> that key; deletes a matching plaintext copy
              no entry + file      -> import file, store to keychain
              no entry + no file   -> guard, then generate + store
              backend unavailable  -> warn, fall back to plaintext file
      fresh     -> guard, then Seed::create (keychain-preferred)
```

The guard is `refuse_second_identity` (`src/sign.rs:622`): refuse if the log
is non-empty **or** `existing_identity_evidence` finds `.kan/identity`,
`.kan/seed`, or `.kan/seed-id`. `.kan/identity-id` is deliberately *not*
evidence, because `keychain_account` writes it before the guard runs
(`src/sign.rs:675`).

## What collapses

The space looks like 3 × 2 × 2 × 2 × 3 × 2 × 2 = 288. It is not, because
every dimension after the first decided one stops mattering:

- **`KAN_IDENTITY_FILE` set and present short-circuits everything.** Layout,
  keychain, seed and log are all irrelevant on both paths. 96 raw
  combinations, 1 cell.
- **`.kan/seed` present short-circuits the keychain and the key file** on both
  paths.
- **The log only matters where something is about to mint**, so it is a
  dimension of the guard, not of resolution.
- **`.kan/roles` only matters when the override path is missing.**

What remains is 23 reachable cells, of which **15 are exercisable in CI** —
see "What CI cannot reach" below.

## The table

`identity` = `.kan/identity`, `id` = `.kan/identity-id`, `seed` = `.kan/seed`,
`seed-id` = `.kan/seed-id`. Keychain column: `off` = `KAN_NO_KEYCHAIN`,
`on` = reachable. Log: whether `log/repo.car` is non-empty.

The **agree** column has exactly three values, and the distinction is the
whole point of the table: `✓` both resolve the *same* identity; `✗` the read
resolves nothing while the write resolves a definite one — the #170 shape;
`—` neither resolves an identity, because the write mints or refuses instead.

| # | env | layout | keych | log | READ resolves | WRITE resolves | agree |
|---|---|---|---|---|---|---|---|
| 1 | unset | *empty* | off | empty | None | mints a seed at `.kan/seed` | — |
| 2 | unset | *empty* | off | claims | None | **refuses** (guard: log) | — |
| 3 | unset | `identity` | off | empty | the key file | the key file | ✓ |
| 4 | unset | `identity` | off | claims | the key file | the key file | ✓ |
| 5 | unset | `id` | off | empty | None | mints `.kan/identity` | — |
| 6 | unset | `id` | off | claims | None | **refuses** (guard: log) | — |
| 7 | unset | `seed` | off | either | seed-derived | seed-derived | ✓ |
| 8 | unset | `seed-id` | off | empty | None | **refuses** (guard: seed-id) | — |
| 9 | unset | `seed-id` | off | claims | None | **refuses** | — |
| 10 | unset | `seed`+`identity` | off | either | seed-derived | seed-derived | ✓ |
| 11 | unset | `seed-id`+`identity` | off | either | the key file | the key file | ✓ |
| 12 | unset | `id`+`identity` | off | either | the key file | the key file | ✓ |
| 13 | exists | *any* | either | either | the override key | the override key | ✓ |
| 14 | missing | *empty* | off | empty | None | **mints at the override path** | — |
| 15 | missing | *empty* | off | claims | None | **refuses** (guard: log) | — |
| 16 | missing | `identity` | off | empty | None | **refuses** (guard: key file) | — |
| 17 | missing | `seed` | off | empty | None | **refuses** (guard: seed) | — |
| 18 | missing, in `roles` | *any* | either | either | None | `DeclaredRoleKeyMissing` | — |
| 19 | unset | `id` | on | either | **None** | the keychain key | ✗ **#170** |
| 20 | unset | *empty* | on | empty | None | mints a seed into the keychain | — |
| 21 | unset | `seed-id` | on | either | seed from keychain | seed from keychain | ✓ |
| 22 | unset | `identity` | on, no entry | either | the key file | key file, **migrated in** | ~ |
| 23 | unset | `id` | on, no entry | claims | None | **refuses** | — |

**Row 5 corrected while writing the test.** The first draft of this table said
the write seed-roots there. It does not: `fresh` is
`!.kan/identity && !.kan/identity-id` (`src/sign.rs:508`), so `identity-id`
alone makes the workspace *not* fresh, the write falls through to
`load_or_create`'s plaintext branch, and it mints `.kan/identity` instead. A
derivation from reading code is a hypothesis; `tests/identity_cells.rs` is
what makes it a measurement.

## Where the two disagree, and what each costs

**Row 19 is #170**, and it is this repository's own layout: `identity-id`
present, no key file, no seed, no `seed-id`. `kan identity did` — which is a
**write**-path command (`src/cli/mod.rs:846` calls `ws.identity()` after
`commit_identity`) — resolves the keychain key. `--trust me` calls
`existing_identity`, which has no keychain branch, and reports no identity.
One workspace, two answers, depending on which verb you asked.

**Row 19 is the only `✗` in the table, and that is the finding.** With the
keychain disabled, the two resolvers never disagree about *which* identity a
workspace has — they only ever both fail to find one. Every divergence
`.design/identity-resolution.md` catalogues needs a reachable keychain, which
is why the suite could not have caught #170 and why five adversarial review
rounds did not either. `tests/identity_cells.rs` asserts that set is empty on
the testable plane, so a *new* divergence introduced there fails loudly.

**Rows 5, 6, 8 and 9 are the softer version of the same shape.** The read
reports nothing; the write either refuses on evidence the read never
consulted (`seed-id` in rows 8–9) or mints. Not a misattribution, but
`--trust me` still answers "no identity" in a workspace the write path treats
as having one.

**Row 14 is the surviving mint hazard.** `KAN_IDENTITY_FILE` naming a path
that does not exist, in a workspace with nothing else and an empty log, still
creates a key there. That is REQ-2's target: a selection naming something
absent is *always* an error. Today it is an error only when the guard finds
evidence — so the guard's evidence set is doing work that the *selection*
semantics should make unnecessary.

**Row 22 is a write with a side effect a read would never have**: resolution
migrates the plaintext key into the keychain and deletes the redundant copy.
Correct behaviour, but it means "ask who I am" and "ask who I am, in a way
that might write" are different questions — REQ-1's whole point, and AC-8's
byte-identical-`.kan/` assertion.

## What CI cannot reach, and why that matters

**Rows 19–23 require a reachable OS keychain and cannot run in CI or in this
suite.** `KAN_NO_KEYCHAIN=1` is set by every test that touches identity,
because a rebuilt binary blocks forever on a macOS authorization prompt (#96)
— a suite that hangs locally and passes on CI is worse than one that fails.

So the plane containing #170 is exactly the plane the suite cannot exercise.
That is not a coincidence and it is worth stating plainly: **#170 survived
five adversarial review rounds because no test could have caught it.** The
rows above are the substitute — an enumeration a reader can check by hand
where a machine cannot.

It is also the strongest practical argument for REQ-3. Retiring the keychain
from the default path does not merely simplify the table; it moves rows 19–23
into the testable plane, where rows 1–18 already live.

## Sequencing note

Rows 1–18 are pinned by `tests/identity_cells.rs`, one assertion per cell,
against both probes:

- **read probe** — `kan show <subject> --trust me --json`, which calls
  `existing_identity` and cannot mint.
- **write probe** — `kan observe`, which calls `commit_identity` →
  `load_or_create_for_workspace`.

Probing both matters. Nine v0.11 tests had to change probe rather than
expectation because they used a read to detect a minting path, and a read can
no longer mint — asserting the guard held while exercising nothing.
