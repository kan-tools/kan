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

There are **eight** input dimensions: `KAN_IDENTITY_FILE` (3 meaningful
states, 4 as tested) × `.kan/identity` × `.kan/identity-id` × `.kan/seed` ×
`.kan/seed-id` × keychain (off / reachable-with-entry / reachable-no-entry /
`Entry::new` fails / `get_secret` errors) × log × a `.kan/roles` entry.

*(The first draft wrote "3 x 2 x 2 x 2 x 3 x 2 x 2 = 288" — seven factors for
eight dimensions. The omitted one was `.kan/identity-id`, which is the single
artifact row 5's correction and #170 both turn on, and the one the guard
deliberately ignores. Dropping precisely that dimension is how four cells came
to be missing. A later draft then said "27 reachable cells" and that number
was not derived from anything either. **No cell count appears in this document
any more** — the testable plane is generated and counted by the generator, and
the untestable plane is a list a reader can check.)*

Short-circuits worth knowing when reading the generated tables:

- **`KAN_IDENTITY_FILE` naming a file that exists short-circuits everything**
  on both paths. That is a claim the generator now *tests* across all 32
  combinations rather than asserting over one.
- **`.kan/seed` short-circuits the keychain and the key file** on both paths.
- **The log only matters where something is about to mint**, so it is a
  dimension of the guard rather than of resolution.
- **`.kan/roles` only matters when the override path is missing.**

## The table is derived, not curated

**The testable plane is generated, not listed here.** `tests/derived_cells.rs`
enumerates the full product it can construct — `KAN_IDENTITY_FILE` (4 states)
× `.kan/identity` × `.kan/identity-id` × `.kan/seed` × `.kan/seed-id` × log
empty-or-not, 128 configurations — runs both resolvers against each, and
writes the outcomes to `tests/fixtures/golden/derived-cells-*.txt`. Read those
files for the table; they are the table.

Outcomes are symbolic rather than DIDs: `resolved:identity`, `signed:override`
and so on name **which artifact** the key traces back to, computed after the
probe so a key the write just minted is matched the same way a pre-existing
one is. That is what makes a read and a write naming *different* artifacts
visible as a diff.

### Why this replaced a hand-written table

The first version of this document listed rows by hand. Two consecutive cold
reviews each found rows missing — four, then four more, including a mint the
prose explicitly denied existed and a case where a curated "1 cell, 96
combinations collapse" claim was backed by exactly one tested combination.

The second review's recommendation, adopted: *where an enumeration keeps
missing cells, derive it rather than curate it harder.* A hand-maintained list
that has already missed cells twice will miss them again; the third round of
patching it is the same bet as the first two.

Demonstrated rather than asserted. Mutating `existing_identity` so a workspace
key outranks the override when both exist — a read/write split on *definite*
identities, worse than #170 — leaves all 43 curated cell tests green and fails
the derived table on the first `env=exists` row that has a key file.

## The plane that cannot be derived

Everything above pins the keychain to **disabled**, because every identity
test must set `KAN_NO_KEYCHAIN` or a rebuilt binary blocks forever on a macOS
authorization prompt (#96). The keychain-reachable plane is unreachable from
any test in this suite, and derivation does not change that — these rows are
prose because prose is the only instrument available. They carry no guarantee
beyond one reader's care, and two of them have never been executed by anyone.

| env | layout | keychain | log | READ | WRITE | agree |
|---|---|---|---|---|---|---|
| unset | `id` | reachable, entry present | either | **None** | the keychain key | ✗ **#170** |
| unset | `identity`+`id` | reachable, entry present | either | **the key file** | **the keychain key** | ✗✗ |
| unset | *empty* | reachable | empty | None | mints a seed into the keychain | — |
| unset | `seed-id` | reachable | either | seed from keychain | seed from keychain | ✓ |
| unset | `identity` | reachable, no entry | either | the key file | key file, migrated in | ~ |
| unset | `id` | reachable, no entry | claims | None | **refuses** | — |
| unset | `id` | reachable, no entry | empty | None | **mints a new DID into the keychain** | — |
| unset | `identity` | `Entry::new` fails | either | the key file | the key file, warned | ✓ |
| unset | `id` | `Entry::new` fails | claims | None | **mints, unguarded** (#180) | — |
| unset | `id` | `get_secret` errors | either | None | `Err(KeychainUnreachable)` | — |
| unset | `seed-id` | `get_secret` errors | either | `Err` | `Err` | — |

`~` marks a definite answer reached with a side effect (the plaintext key is
migrated into the keychain and the redundant copy deleted).

**The second `✗` is worse than #170 and was missed by both the first draft and
its first correction.** With `.kan/identity` *and* `.kan/identity-id` present
and a keychain entry, the read returns the key file and the write returns the
keychain key — both definite, and different. It is reachable through
`kan identity adopt`, which writes `.kan/identity` but leaves `identity-id`
untouched (`src/actions.rs:820`), so adopt reports success while the next
write signs as something else. `src/sign.rs:290-299` exists solely to warn
about that state, which is evidence the author already knew it was reachable.

**#180 is the unguarded one.** When `keyring::Entry::new` fails,
`load_or_create` falls through to `load_or_create_plaintext`
(`src/sign.rs:254`), which contains no `refuse_second_identity` call — the
only minting path in the function that never consults the guard. On a machine
with no Secret Service that is the ordinary path, not an exotic one.

## Where the two disagree, and what each costs

**#170** is this repository's own layout: `identity-id` present, no key file,
no seed, no `seed-id`. `kan identity did` — a **write**-path command
(`src/cli/mod.rs:846` calls `ws.identity()` after `commit_identity`) —
resolves the keychain key. `--trust me` calls `existing_identity`, which has
no keychain branch, and reports no identity. One workspace, two answers,
depending on which verb you asked.

**Both `✗` rows are on the untestable plane, and that is the finding.** With
the keychain disabled, the two resolvers never disagree about *which*
artifact a workspace's identity comes from — the generated tables contain no
row where `resolved:` and `signed:` name different artifacts. Every divergence
`.design/identity-resolution.md` catalogues needs a reachable keychain, which
is why the suite could not have caught #170 and why five adversarial review
rounds did not either.

**The softer version shows up throughout the generated tables**: the read
reports `none` while the write either refuses on evidence the read never
consulted — `.kan/seed-id`, which `Seed::load` skips under `KAN_NO_KEYCHAIN`
but `existing_identity_evidence` sees — or mints. Not a misattribution, but
`--trust me` still answers "no identity" in a workspace the write path treats
as having one.

**There are four mint hazards, not one.** An early draft called the
`KAN_IDENTITY_FILE`-names-a-missing-path case "the surviving mint hazard",
singular. It is not:

- the same shape **with `.kan/identity-id` present** — a workspace that
  demonstrably *has had* an identity — still mints at the override path and
  signs at exit 0, because `identity-id` is the one artifact
  `existing_identity_evidence` deliberately ignores (`src/sign.rs:675`). The
  guard is blind there by design, for a reason correct on its own terms
  (`keychain_account` writes that file before the guard runs), and this is the
  cost.
- an empty log plus a keychain answering `NoEntry` sends `load_or_create` to
  `Self::generate()` and `set_secret` (`src/sign.rs:304–331`), filing a
  **brand-new DID into the keychain** for a workspace that had one.
- **`Entry::new` failing falls through to `load_or_create_plaintext`, which
  has no guard at all** (`src/sign.rs:254`, #180) — the only minting path in
  the function that never consults `refuse_second_identity`.

All four are REQ-2's target: a selection naming something absent is *always*
an error, and an identity is never created as a side effect of failing to find
one. Today they are errors only when the guard finds evidence — so the guard's
evidence set is doing work that *selection* semantics should make unnecessary,
and it is doing it with a known blind spot and one path that skips it.

**A read that resolves an identity is not side-effect free**, which the first draft asserted only
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

**The keychain-migration write has a side effect the seed path never has**: resolution
migrates the plaintext key into the keychain and deletes the redundant copy.
Correct behaviour, but together with the read above it means "ask who I am" and "ask
who I am, in a way that might write" are the same question today — REQ-1's
whole point, and what AC-8's byte-identical-`.kan/` assertion has to cover on
both paths rather than only on the write.

## Sequencing note

Two test files, doing different jobs:

- **`tests/derived_cells.rs`** generates the testable plane by enumerating the
  product and probing both resolvers. Completeness is mechanical here.
- **`tests/identity_cells.rs`** keeps one named `#[test]` per hand-chosen cell,
  so a specific expectation fails alone and can be reverted-and-checked
  individually. It is the readable set, not the complete one, and the derived
  tables are what guard against it being short.

Both probe both paths, deliberately:

- **read** — `kan show <subject> --trust me --json`, which calls
  `existing_identity`.
- **write** — `kan observe`, which calls `commit_identity` →
  `load_or_create_for_workspace`.

`kan identity did` is a **write**-path command, which is exactly why #170
presents as "`identity did` resolves fine but `--trust me` does not". Nine
v0.11 tests had to change probe rather than expectation because they used a
read to detect a minting path — asserting the guard held while exercising
nothing.

The three minting outcomes assert **who signed**, not merely that a file
appeared: a write that creates a key and then signs as somebody else is the
misattribution this project exists to prevent, and a file-exists assertion
would pass it.
