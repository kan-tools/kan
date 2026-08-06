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
              Entry::new failed    -> warn, fall back to plaintext file
              get_secret errored:                          (src/sign.rs:413)
                  key file present -> warn, fall back to plaintext file
                  no key file      -> Err(KeychainUnreachable)
      fresh     -> guard, then Seed::create (keychain-preferred, src/sign.rs:1290)
```

The `get_secret` error branch is distinct from `NoEntry` and is the one #96
actually produces — a keychain that answers with neither the key nor "no such
entry", because it is waiting on an authorization prompt nobody can answer.
The first draft of this document omitted it while documenting its mirror on
the read side, which is the same asymmetry the whole table exists to expose.

The guard is `refuse_second_identity` (`src/sign.rs:622`): refuse if the log
is non-empty **or** `existing_identity_evidence` finds `.kan/identity`,
`.kan/seed`, or `.kan/seed-id`. `.kan/identity-id` is deliberately *not*
evidence, because `keychain_account` writes it before the guard runs
(`src/sign.rs:675`).

## What collapses

There are **eight** input dimensions: `KAN_IDENTITY_FILE` (3) × `.kan/identity`
× `.kan/identity-id` × `.kan/seed` × `.kan/seed-id` × keychain (4: off,
reachable-with-entry, reachable-no-entry, errored) × log × a `.kan/roles`
entry — 3 × 2 × 2 × 2 × 2 × 4 × 2 × 2 = **768**.

*(The first draft wrote "3 × 2 × 2 × 2 × 3 × 2 × 2 = 288" — seven factors for
eight dimensions. The omitted one was `.kan/identity-id`, which is the single
artifact row 5's correction and #170 both turn on, and the one the guard
deliberately ignores. Dropping precisely that dimension from the count is how
rows 19 and 26 came to be missing.)*

It collapses, because every dimension after the first decided one stops
mattering:

- **`KAN_IDENTITY_FILE` set and present short-circuits everything.** Layout,
  keychain, seed and log are all irrelevant on both paths. 96 raw
  combinations, 1 cell.
- **`.kan/seed` present short-circuits the keychain and the key file** on both
  paths.
- **The log only matters where something is about to mint**, so it is a
  dimension of the guard, not of resolution.
- **`.kan/roles` only matters when the override path is missing.**

What remains is **27 reachable cells, of which 20 are exercisable in CI** —
see "What CI cannot reach" below. Rows 1–20 each have their own `#[test]` in
`tests/identity_cells.rs`; rows 21–27 have none and cannot.

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
| 13 | exists | *any* | either | either | the override key †| the override key | ✓ |
| 14 | missing | *empty* | off | empty | None | **mints at the override path** | — |
| 15 | missing | *empty* | off | claims | None | **refuses** (guard: log) | — |
| 16 | missing | `identity` | off | empty | None | **refuses** (guard: key file) | — |
| 17 | missing | `seed` | off | empty | None | **refuses** (guard: seed) | — |
| 18 | missing | `seed-id` | off | empty | None | **refuses** (guard: seed-id) | — |
| 19 | missing | `id` | off | empty | None | **mints at the override path** | — |
| 20 | missing, in `roles` | *any* | either | either | None | `DeclaredRoleKeyMissing` | — |
| 21 | unset | `id` | on, entry | either | **None** | the keychain key | ✗ **#170** |
| 22 | unset | *empty* | on | empty | None | mints a seed into the keychain | — |
| 23 | unset | `seed-id` | on | either | seed from keychain | seed from keychain | ✓ |
| 24 | unset | `identity` | on, no entry | either | the key file | key file, **migrated in** | ~ |
| 25 | unset | `id` | on, no entry | claims | None | **refuses** | — |
| 26 | unset | `id` | on, no entry | empty | None | **mints a new DID into the keychain** | — |
| 27 | unset | `identity` | errored | either | the key file | key file, with a warning | ✓ |

† Row 13's read is **not side-effect free** — see below.

**Rows 18, 19, 26 and 27 were missing from the first draft**, all found by a
cold adversarial review. The pattern in the omissions is worth more than the
rows: every one of them is a cell where `.kan/identity-id` or a keychain
*error* is the deciding input, which are exactly the two things dropped from
the dimension count above. An enumeration is only as complete as its list of
dimensions, and mine was short by one.

**Row 5 corrected while writing the test.** The first draft of this table said
the write seed-roots there. It does not: `fresh` is
`!.kan/identity && !.kan/identity-id` (`src/sign.rs:508`), so `identity-id`
alone makes the workspace *not* fresh, the write falls through to
`load_or_create`'s plaintext branch, and it mints `.kan/identity` instead. A
derivation from reading code is a hypothesis; `tests/identity_cells.rs` is
what makes it a measurement.

## Where the two disagree, and what each costs

**Row 21 is #170**, and it is this repository's own layout: `identity-id`
present, no key file, no seed, no `seed-id`. `kan identity did` — which is a
**write**-path command (`src/cli/mod.rs:846` calls `ws.identity()` after
`commit_identity`) — resolves the keychain key. `--trust me` calls
`existing_identity`, which has no keychain branch, and reports no identity.
One workspace, two answers, depending on which verb you asked.

**Row 21 is the only `✗` in the table, and that is the finding.** With the
keychain disabled, the two resolvers never disagree about *which* identity a
workspace has — they only ever both fail to find one, or the write creates the
one it signs with. Every divergence `.design/identity-resolution.md`
catalogues needs a reachable keychain, which is why the suite could not have
caught #170 and why five adversarial review rounds did not either.
`the_two_resolvers_disagree_in_exactly_these_cells` **measures** both
resolvers per cell and pins the set to the four minting rows, so a new
divergence on the testable plane fails loudly.

**Rows 5, 6, 8 and 9 are the softer version of the same shape.** The read
reports nothing; the write either refuses on evidence the read never
consulted (`seed-id` in rows 8–9) or mints. Not a misattribution, but
`--trust me` still answers "no identity" in a workspace the write path treats
as having one.

**Rows 14, 19 and 26 are mint hazards, not one.** The first draft called row
14 "the surviving mint hazard", singular, and that was wrong twice over:

- **Row 19** is the same shape with `.kan/identity-id` present — a workspace
  that demonstrably *has had* an identity. It mints at the override path and
  signs at exit 0, because `identity-id` is the one artifact
  `existing_identity_evidence` deliberately ignores (`src/sign.rs:675`). The
  guard is blind here by design, for a reason that is correct on its own terms
  (`keychain_account` writes that file before the guard runs), and the cost is
  this cell.
- **Row 26** is the quietest of the three and cannot be tested: an empty log
  plus a keychain that answers `NoEntry` sends `load_or_create` to
  `Self::generate()` and then `set_secret` (`src/sign.rs:304–331`), filing a
  **brand-new DID into the keychain** for a workspace that had one.

All three are REQ-2's target: a selection naming something absent is *always*
an error, and an identity is never created as a side effect of failing to find
one. Today they are errors only when the guard finds evidence — so the guard's
evidence set is doing work that *selection* semantics should make unnecessary,
and it is doing it with a known blind spot.

**Row 13's read is not side-effect free**, which the first draft asserted only
writes could be. `existing_identity`'s env branch calls
`Identity::load_or_create` (`src/sign.rs:849`), not `load_existing`, so
`kan show <subject> --trust me` with `KAN_IDENTITY_FILE` set to an existing
key **creates `.kan/`** and **tightens that key's permissions** to `0600`.
Measured, with the control that isolates the cause:

```
KAN_IDENTITY_FILE=…/key  kan show nothing --trust me --json
  before: .kan/ absent, key mode 644
  after:  .kan/ PRESENT, key mode 600
same read WITHOUT --trust me:  .kan/ absent, key 644
```

`src/sign.rs:833-838` says the key-file branch "uses `load_existing` … so it
cannot reach the keychain, write `identity-id`, or migrate" — true of the
branch it sits above (R3), false of the env branch three lines earlier (R1a).
`tests/write_guards.rs::a_read_creates_no_workspace` misses it because it
points the variable at a path that does not exist, so the resolving branch is
never entered. Pinned by
`a_read_that_resolves_an_identity_still_has_side_effects`, which REQ-1 must
**invert** in the commit that makes `workspace_identity` pure.

**Row 24 is a write with a side effect the *seed* path never has**: resolution
migrates the plaintext key into the keychain and deletes the redundant copy.
Correct behaviour, but together with row 13 it means "ask who I am" and "ask
who I am, in a way that might write" are the same question today — REQ-1's
whole point, and what AC-8's byte-identical-`.kan/` assertion has to cover on
both paths rather than only on the write.

## What CI cannot reach, and why that matters

**Rows 21–27 require a reachable OS keychain and cannot run in CI or in this
suite.** `KAN_NO_KEYCHAIN=1` is set by every test that touches identity,
because a rebuilt binary blocks forever on a macOS authorization prompt (#96)
— a suite that hangs locally and passes on CI is worse than one that fails.

So the plane containing #170 is exactly the plane the suite cannot exercise.
That is not a coincidence and it is worth stating plainly: **#170 survived
five adversarial review rounds because no test could have caught it.** Rows
21–27 are the substitute — an enumeration a reader can check by hand where a
machine cannot, which also means they carry no guarantee beyond one reader's
care. Row 26 is derived from source and has never been executed by anyone.

It is also the strongest practical argument for REQ-3. Retiring the keychain
from the default path does not merely simplify the table; it moves rows 21–27
into the testable plane, where rows 1–20 already live — turning an
unfalsifiable defect class into a falsifiable one.

## Sequencing note

Rows 1–20 are pinned by `tests/identity_cells.rs` with **one `#[test]` per
cell per path**, so each fails alone and AC-3's revert-the-hunk method is
implementable. A `for` loop over cells cannot deliver that: the first failing
cell aborts the rest, so eight moved cells report one failure. Both probes:

- **read probe** — `kan show <subject> --trust me --json`, which calls
  `existing_identity`.
- **write probe** — `kan observe`, which calls `commit_identity` →
  `load_or_create_for_workspace`.

Probing both matters. Nine v0.11 tests had to change probe rather than
expectation because they used a read to detect a minting path, and a read can
no longer mint — asserting the guard held while exercising nothing.

The three minting outcomes assert **who signed**, not merely that a file
appeared: a write that creates a key and then signs as somebody else is the
misattribution this project exists to prevent, and the first draft's
file-exists assertion would have passed it.
