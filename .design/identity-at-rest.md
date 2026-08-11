# Feature: identity at rest — the default flips, the keychain becomes opt-in

*v0.12 REQ-3. Executes `.design/v0.12-milestone.md` Resolved Q1 and Q3; sits
on top of REQ-1's three functions (ADR-88). Answers #183.*

## Summary

A fresh workspace roots in a passphraseless `0600` seed file. The OS keychain
stops being the default and becomes an opt-in, reached by `kan identity
protect`; `kan identity unprotect` is its inverse and the way a grandfathered
keychain-rooted workspace gets out. Neither command may change the workspace's
DID, on any of the four at-rest states.

This is ADR-87's layer 3 becoming the default and layer 1 becoming a command.
It is not the agent (layer 2) and not passphrase encryption — both are
downstream of this and out of scope.

## Why, in the order the arguments actually weigh

**1. It converts an unfalsifiable defect class into a falsifiable one.** This
is the argument `.design/v0.12-milestone.md` understated, and it is the
largest. Every identity test in the suite must set `KAN_NO_KEYCHAIN` or a
locally-rebuilt binary hangs (#96) — so today the keychain-reachable plane is
*unreachable from the suite by construction*. #170, #180 and ADR-88's `adopt`
defect all lived on that plane, and **not one of them could have been caught by
a test**, however careful. `tests/derived_cells.rs` says so in its own header:
*"the reachable-keychain plane is unreachable from this suite (#96) and lives
in prose instead."*

Moving the default off the keychain does not make that plane testable. It makes
it **rare** — the path a new workspace takes, the path CI takes, the path `day`
and the MCP server and every agent take, is the one the suite can reach. The
untestable plane stops being the default and becomes an opt-in that a human
chose.

**2. #96's practical close** (milestone AC-4): a workspace created by this
build raises no interactive prompt on any platform, in CI, in a container, or
under `day` shelling out, with `KAN_IDENTITY_FILE` unset.

**3. Cell-table collapse**: most of REQ-6's keychain dimension stops being
reachable by accident.

## The reversal this makes, and the counter-argument answered

REQ-3 reverses a decision recorded twice — ADR-63 (`docs/DECISIONS.md:3020`,
*"Where the root lives: the OS keychain when available, a `0600` file when
not"*) and `Seed::create`'s own doc comment (`src/sign.rs:996`):

> Taking the file-always reading would have reopened issue #6 for every new
> workspace — the root secret in plaintext where the key it replaces was
> encrypted — which is a strictly worse at-rest posture than the version it
> upgrades from.

That argument is not wrong, and it is not being ignored. It is being
**outweighed, and paid for by a command**. The honest accounting:

**What is given up, stated plainly.** On a fresh workspace, `.kan/seed` is
32 bytes readable by anything running as you, without a prompt. #6's property —
a brand-new identity leaves no plaintext secret on disk — no longer holds by
default. That is a real regression in at-rest posture and this document does
not soften it.

**Why it is the right trade anyway.** Three reasons:

- **It is the ssh trade, deliberately.** ADR-87's layer 3 is a passphraseless
  `0600` file, and a GitHub Actions deploy key is exactly that. A very large
  fraction of developer machines carry a passphraseless `~/.ssh/id_ed25519`,
  and that is an accepted posture rather than a known defect.
- **On macOS the protection and the defect are the same mechanism.** The login
  keychain is unlocked for the whole session, so a process running as you can
  read an entry once the prompt is answered. What actually gates access is the
  trusted-application ACL — and the ACL keying on the calling binary's code
  identity *is* #96. The at-rest protection ADR-63 bought is delivered by the
  precise mechanism that hangs a rebuilt binary. It cannot be kept without
  keeping the other.
- **The property is restored in one command**, by anyone who wants it, on any
  of the four states — which is more than ADR-63 offered, since ADR-63's
  keychain-by-default had no way *out* except `adopt`.

**What is not given up.** `.kan/` is gitignored (ADR-3), so the secret does not
travel with the repo. The derived signing key is still never written, so a
seed-rooted workspace still holds *fewer* secrets at rest than a v0.8 one. The
recovery phrase is unchanged.

This is the milestone's third specification reversal and, like ADR-88's two, it
is recorded with its argument rather than applied quietly.

## #183 — decided

> **The implicit plaintext→keychain migration is retired. `kan identity
> protect` is the deliberate way in.**

AC-8 required removing the migrate-and-delete *side effect* from the resolution
path, and that is what shipped. #183 correctly observes that AC-8 did not
sanction removing the *feature*, and that the feature went anyway. The decision
is that it should have:

- **A capability that only ever fired as a side effect of resolution was never
  something an operator could ask for, see, or undo.** It moved a secret
  because you ran `kan show`. Under REQ-1 that is not a feature with an awkward
  trigger; it is the exact class AC-8 exists to kill, and retaining it in any
  implicit form contradicts REQ-1.
- **`protect` covers strictly more than it did.** The implicit migration
  handled one direction of one state (`.kan/identity` → keychain). `protect`
  covers all four states, in both directions.

So this is a **move, not a drop** — which is only true because `protect`
handles the grandfathered key-rooted case. If it handled seeds only, #183's
honest answer would be "dropped," and a pre-v0.9 workspace that wanted ADR-25's
posture would have no on-ramp at all.

## Requirements

- **REQ-3.1 — `Seed::create` stops preferring the keychain.**
  `Seed::create` (`src/sign.rs:1002`) writes `.kan/seed` at `0600`
  unconditionally and never calls `keyring::Entry`. Its "OS keychain
  unavailable" `eprintln!` is not an unavailability warning any more and must
  not read as one: it becomes a single line stating where the root secret is,
  that the recovery phrase (`kan identity phrase`) is the off-disk backup, and
  that `kan identity protect` moves it into the keychain.

- **REQ-3.2 — `kan identity protect`.** Moves this workspace's at-rest secret
  into the OS keychain, over all four states, leaving `kan identity did`
  unchanged:
  `.kan/seed` → `.kan/seed-id`, `.kan/identity` → `.kan/identity-id`. A
  workspace already in the keychain is told so and nothing is written.

  **A stale reference is retired, not silently replaced.** Where a pointer
  already exists for the secret being protected, `protect` mints a fresh
  account and removes the old pointer with an explanation, exactly as
  `retire_seed` does (`src/actions.rs:3076` — the reference goes, *"the keychain
  entry itself is left alone"*). Orphaning an entry is already this codebase's
  accepted behaviour and the entry stays reachable through Keychain Access;
  doing it **silently** is the only part that was ever wrong.

  **And `protect` reports every at-rest secret it did not move.** Protecting
  the signing secret while `.kan/identity` still sits beside it leaves a
  plaintext key on disk under a command whose whole promise is that none
  remains. It need not move them — precedence says they are not signing — but
  it must not claim a property the workspace does not have.

  **#112's negative control comes back with this requirement.** REQ-3.5 deletes
  `a_different_key_plaintext_file_survives_a_keychain_hit`, which is correct
  *today* — after REQ-1 nothing in `src/` deletes a secret at all. `protect`
  step 6 reintroduces exactly that operation, so the property returns with it:
  **the plaintext copy is deleted only on a byte match**, asserted by a control
  that puts a *different* key at the path and requires it to survive. #112's
  actual history is that the guard was a tautology
  (`bytes == import(bytes).export()`) which never read the file and therefore
  could not discriminate — so steps 3 and 4 must be verified by a test that
  fails when the comparison is inverted, not merely by their own existence.

- **REQ-3.3 — `kan identity unprotect`.** *Measured limit, added after the
  migration matrix ran it (run 31287243890): this is the exit for a
  grandfathered workspace **only where a human can answer a keychain prompt**.
  Headless it reports `fix-route-blocked` for every v0.7.0+ writer, because
  unprotect must READ the keychain to move the secret out of it and reading is
  what #96 prevents. That is the design working — unprotect is interactive by
  design — but this document previously called it "the exit for grandfathered
  ones" with no qualifier, and for CI, `day`, MCP and agents there is no exit.
  And for v0.2.0–v0.6.0 there is none at all: those writers left no pointer
  file, so unprotect has nothing to look up (`fix-route-failed`).*

  The inverse:
  `.kan/seed-id` → `.kan/seed`, `.kan/identity-id` → `.kan/identity`. This is
  the grandfathered workspace's deliberate way out, and it is an interactive
  command by design — a keychain prompt here is one a human is present to
  answer, which is the same argument Resolved Q3 used against prompting at
  creation time.

- **REQ-3.4 — a pure planner, so the commands are testable at all.** The
  decision of *what* protect/unprotect would do is a pure function of files
  (`at_rest`, `plan_protect`, `plan_unprotect`); only the executor touches the
  keychain. The planner joins `tests/derived_cells.rs` as a third symbolic
  column over the same enumeration, so protect's behaviour is covered because
  the loop reached it — the milestone's own "derive it rather than curate it
  harder."

  **`at_rest` must mirror `workspace_identity`'s precedence exactly**, or
  `protect` moves a secret that is not the one signing. That is #170's
  disagreement class in a new command, and it is the single most likely way
  this requirement goes wrong.

- **REQ-3.5 — #183's cleanup.** Delete `Identity::load_or_create`,
  `Identity::load_or_create_for_workspace`, `keychain_account`,
  `refuse_second_identity` and `existing_identity_evidence`. Rewrite the ~46
  test call sites that reach them to `Identity::generate().save(path)`, which
  is what they mean. Delete or rewrite the tests whose subject is the retired
  behaviour — `tests/keychain_identity.rs`'s **three** retired tests, and
  `tests/identity_retrievability.rs`'s `0644`→`0600` repair-on-load assertion,
  which #183 confirmed by execution no longer happens.

- **REQ-3.6 — `KAN_NO_KEYCHAIN` re-documented, and demoted.** Its doc comment
  (`src/sign.rs::NO_KEYCHAIN_ENV`) describes it as "the missing middle" — the only way to
  avoid a keychain prompt without naming a key file. After REQ-3 that is the
  default, and its remaining job is narrower: suppress keychain lookups for a
  *grandfathered* workspace's pointer files, and let the suite run. It is also
  **no longer a *minting* hazard**: #146's hazard was that it walked past the
  mint guard into `load_or_create_plaintext`, and REQ-1 closed that by
  construction.

  *Narrowed by a cold review, and it was wrong in two ways. "No longer
  data-affecting" is too strong: the flag still changes **which DID signs** in
  a workspace holding both a keychain root and a plaintext `.kan/identity`,
  because `Seed::load` returns `None` under it (`src/sign.rs:953`) and
  resolution falls through to the key file. That is misattributed authorship
  rather than minting, and this project's own operating notes treat the flag
  as data-affecting for exactly that reason. The same sentence cited the
  derived goldens as showing `write=refused:guard` for **every**
  `id=id`/`seed-id=seed-id` row with `log=claims`; of the 12 such rows in
  `derived-cells-unset.txt`, **3** do. The conclusion survives — the other 9
  sign with an identity that already exists, so nothing mints — but the
  evidence as stated was false, which is the failure this milestone keeps
  naming in other people's work.*

## Acceptance Criteria

- **AC-3.1 — the canary, and the whole point.** A test that does **not** set
  `KAN_NO_KEYCHAIN` creates a workspace, writes a claim, and asserts: `.kan/seed`
  exists at `0600`, `.kan/seed-id` does not exist, no keychain entry was
  created, and the command completed inside a short deadline. This test is
  *impossible today* — it is the first one that can exercise kan's actual
  default path without risking #96's hang — and it must run on macOS CI, not
  only Linux. It is milestone AC-4 made mechanical.

  *Which means REQ-3 must also add a macOS job.* `.github/workflows/ci.yml` is
  a single `runs-on: ubuntu-latest`, so "must run on macOS CI" currently names
  a runner that does not exist. Flagged by a cold review: an acceptance
  criterion whose infrastructure is not in any requirement is one that gets
  quietly satisfied on Linux and called done. The migration matrix gained a
  `macos-latest` cell for the keychain axis; `ci.yml` has not.

- **AC-3.2 — the derived-cells goldens come out byte-identical.** Every row of
  `tests/fixtures/golden/derived-cells-*.txt` runs under `KAN_NO_KEYCHAIN`,
  where `Seed::create` *already* writes `.kan/seed`. So REQ-3.1 must not move
  them at all. A diff is not a fixture to regenerate — it means REQ-3 changed
  something outside its remit. This is a falsifiable prediction, stated before
  the change.

- **AC-3.3 — the planner is derived, with two invariants asserted per row.**
  `at_rest` is emitted as a third column over all 128 configurations, and in
  every row: (a) `at_rest` is `None` exactly when `identity_evidence` is
  `None`; (b) when `workspace_identity` returns `Some` **and every source
  `at_rest` outranks is reachable**, `at_rest` names the source it resolved
  from.

  *The reachability condition is not a hedge — (b) was written without it and
  was already false against a checked-in fixture. `tests/derived_cells.rs`
  runs every row under `KAN_NO_KEYCHAIN`, where `Seed::load` skips `seed-id`
  (`src/sign.rs:953`) and `keychain_identity` skips `identity-id`, so a
  workspace holding `identity` plus a pointer resolves to the key file while a
  pure file-existence ranking names the pointer.
  `tests/fixtures/golden/derived-cells-unset.txt` holds **6 such rows**.
  Unconditional, (b) would have been "fixed" later either by weakening it or
  by making `at_rest` consult the keychain — and that second repair makes
  `protect` prompt, which is #96 reopened by the requirement that exists to
  close it.* `src/sign.rs` currently holds three different
  orderings over these four files — `workspace_identity`'s, `identity_evidence`'s
  and `Seed::load`'s — and (b) is what stops `at_rest` becoming a fourth.

- **AC-3.4 — DID stability, and its stated limit.** `kan identity did` is
  unchanged across `protect` and across `unprotect`, for each of the four
  states. The *planner* half is asserted everywhere; the round trip through a
  live keychain is hand-checked, because the reachable-keychain plane is
  unreachable from the suite (#96). That is the same stated limit AC-3 of the
  milestone records, not a gap to be closed by care.

- **AC-3.5 — #183 verified negatively.** `grep -rn` for the five retired
  function names returns nothing in `src/`, and nothing in `tests/` except
  where the subject is the retired behaviour being gone. The suite's count does
  not drop silently: every deleted test is either replaced or its deletion is
  named in the commit with the behaviour that no longer exists.

- **AC-3.6 — the refusals.** `kan identity protect` under `KAN_NO_KEYCHAIN`
  refuses and says why. `kan identity protect` with `KAN_IDENTITY_FILE` set
  refuses, naming the selection and stating that kan does not manage a key file
  it was merely pointed at (REQ-2: a selection is not a redefinition). Neither
  refusal writes anything.

- **AC-3.7 — each new assertion is verified by reverting its own hunk**, per
  the milestone's AC-3 and the house rule that a fix answering a review ships
  with a test that fails without it. The mapping is checked, not the aggregate:
  "the suite went red" is not "this test defends this hunk." And per the
  instrument register, the revert probe must mutate the **code under test**,
  not the fixture the test reads.
- **AC-3.8 — the migration matrix carries a row for REQ-3, and it is
  dispatched by hand before merge.** REQ-3 changes what a fresh workspace
  *writes* at rest, so `.github/workflows/migration-matrix.yml` must answer
  what this build does with a v0.11-and-earlier workspace: a v0.11 writer
  leaves `.kan/seed-id` on macOS and `.kan/seed` on Linux CI, and a REQ-3
  reader must still read both — `Seed::load` is untouched, so the expected
  outcome is `ok` in both modes and a move off `ok` stops the merge. REQ-9
  already carries this obligation explicitly; REQ-3 has it too and the
  milestone doc does not say so.

  **Dispatch it by hand** — `gh workflow run migration-matrix.yml --ref
  <branch>`. `src/sign.rs` is in the workflow's `paths` filter, but the filter
  did not re-fire on #182's final commit, so path membership is not sufficient
  evidence that the check ran.

- **AC-3.9 — `unprotect` never writes over a differing secret.** The negative
  control: a workspace with `.kan/identity-id` naming key B and `.kan/identity`
  holding key A — the state ADR-53 deliberately produces — and `unprotect` must
  **refuse**, name both DIDs, and leave A byte-identical on disk. Verified by
  reverting the comparison and watching *that* test go red, because the passing
  case (same bytes, proceeds) cannot distinguish a working guard from an absent
  one. This is #112's lesson restated: its predecessor was a tautology that
  never read the file, and it passed for exactly that reason.

  A second control: the same layout with the keychain **unreachable**, which
  must also refuse. "I cannot tell" and "they match" must not collapse into one
  answer — that collapse is the whole of the degradation to option 1.

- **AC-3.10 — `protect` retires a stale reference audibly, and accounts for
  what it left.** *Corrected: this said the pointer's "removal" is named in the
  output. Since the pointer-deletion defect was fixed, `protect` OVERWRITES the
  pointer and never removes it — writing it is the retirement. An AC that
  described the behaviour the fix removed had merged and gone unnoticed for two
  review rounds.* Where a pointer already existed, the account it previously
  named is reported as orphaned, so the operator can find the entry in
  Keychain Access. And where other at-rest secrets remain, they are listed — a
  `protect` that leaves `.kan/identity` in place while reporting success is
  claiming #6's property without delivering it.


## Architecture

**Where the flip lands.** `Seed::create` (`src/sign.rs:1002`) is the entire
default-side change: drop the `keyring::Entry` branch and the
`fresh_account()` call, always `seed.save(&kan_dir.join(SEED_FILE))`. Nothing
in `workspace_identity` / `signing_identity` / `create_workspace_identity`
moves — REQ-1's three functions already read `.kan/seed` first
(`Seed::load`, `src/sign.rs:953`, decides from files before any keychain
call). REQ-3 is a change to what gets *written*, not to how anything is
resolved, which is why AC-3.2 predicts an unchanged golden.

**The precedence trap, and it is the load-bearing detail.**
`workspace_identity` (`src/sign.rs:385`) resolves in the order: `Seed::load`
(`.kan/seed`, then `.kan/seed-id`) → `keychain_identity` (`.kan/identity-id`)
→ `.kan/identity`. Note that **`.kan/identity-id` outranks `.kan/identity`**,
which is not the order anyone writes from memory. `at_rest` must reproduce
exactly that, or `protect` picks up a secret the signer is not using — one
actor's write mutating what another reads, which CLAUDE.md's invariant forbids
and which is #170 wearing a new hat. `identity_evidence` (`src/sign.rs:524`)
uses a *third* order; that is fine, because it only selects a message and
answers a yes/no question, but it is exactly why AC-3.3(b) exists.

```
at_rest(kan_dir)                    // pure; file existence only
  .kan/seed        -> SeedFile
  .kan/seed-id     -> SeedKeychain
  .kan/identity-id -> KeyKeychain
  .kan/identity    -> KeyFile
  otherwise        -> None
```

**Planner and executor.** `plan_protect(kan_dir)` / `plan_unprotect(kan_dir)`
return a `Plan` — the move to perform, `AlreadyProtected` / `AlreadyUnprotected`,
`NothingToDo` for `AtRest::None`, or a `Refuse(reason)`. Everything above is
pure and enumerable. The executor is the only thing that calls
`keyring::Entry`, and it is the only thing the suite cannot reach.

**Executor ordering is crash-safety, not style.**

*protect* (file → keychain):
1. read the secret from the file;
2. write it to a fresh account (`fresh_account()`, `src/sign.rs:649`) under
   the right service — `SEED_KEYCHAIN_SERVICE` for a seed, `KEYCHAIN_SERVICE`
   for a grandfathered key;
3. **read it back and compare bytes** — a store that silently truncates would
   otherwise destroy the only copy;
4. **derive and compare the DID** against what `workspace_identity` returned
   before the move;
5. write the pointer file;
6. only then dispose of the plaintext file — see below.

**Deleting the superseded plaintext copy.** Decided with Maxine: deleting is
the right pattern, but **not without asking**. So step 6 is a confirmation, not
an unconditional `remove_file`:

- **Confirmed (or `--yes`)** → delete. This is ADR-53's case exactly — a
  plaintext copy that *matches* a verified keychain entry, which ADR-53 removes
  and keeps only when it differs. Steps 3 and 4 are what earn that: the bytes
  were read back and compared, and the DID was re-derived. The output names
  `kan identity phrase` as the off-disk backup, which is strictly better than a
  copy sitting beside the secret it protects.
- **Declined** → move aside as `.kan/seed.protected-<stamp>` (or
  `identity.protected-<stamp>`), following `retire_seed`'s precedent
  (`src/actions.rs:872`), and say plainly that the plaintext copy still exists,
  still reproduces this identity, and that #6's property is not restored until
  it is gone. **It may not simply be left where it is**: `.kan/seed` outranks
  `.kan/seed-id` in `workspace_identity`'s precedence, so leaving it under that
  name means the workspace still resolves from the plaintext file and `protect`
  has reported success while changing nothing — ADR-88's `adopt` defect,
  reproduced in a new command.
- **Not a TTY, and no `--yes`** → **refuse before step 1**, writing nothing at
  all. `kan identity phrase` (`src/cli/mod.rs:857`) already establishes
  terminal-sensing as this repo's gate on an unattended secret decision, and
  refusing *before* the keychain write is what guarantees there is no
  half-state to reason about. The gate belongs at the top of the executor, not
  at step 6.

*Flag spelling:* the decision said `--force`; this specifies **`--yes`**,
because `kan identity phrase --yes` is the existing idiom on the one sibling
command that gates a sensitive irreversible act, and two words for one concept
is the duplication this project keeps paying for. Cheap to overrule.

*unprotect* (keychain → file):
1. read the secret from the keychain — this may prompt, and that is fine here;
2. **if the destination file already exists, compare before writing.** Same
   bytes → proceed (it is a redundant copy). Different bytes → **refuse**,
   naming both DIDs. Cannot tell → **refuse**. This step is the invariant, not
   a nicety: see "the overlap" below;
3. write `.kan/seed` or `.kan/identity` at `0600` via the existing
   `restrict_permissions` path;
4. compare the DID;
5. remove the pointer file — **after** the write, never before, or a failed
   write leaves the workspace with no identity at all;
6. leave the keychain entry alone, following `retire_seed`'s precedent
   (`src/actions.rs:3076`: *"the keychain entry itself is left alone"*), and
   print the account name **before** deleting the pointer file that holds it,
   so the operator can find it in Keychain Access.

**The overlap, and why step 2 is the whole of it.** `.kan/identity` holding
key A beside `.kan/identity-id` naming key B is not a hypothetical: **kan
produces it deliberately.** ADR-53 deletes a plaintext copy only when it
*matches* the keychain and keeps it when it **differs** — which is exactly
what #112's negative control existed to protect. `identity-id` outranks
`identity`, so B signs and A sits there as the only copy of another identity.

Without step 2, `unprotect` writes B over A and reports success. That is the
sole path in this design that **destroys a secret**, it is reachable from a
state kan itself created, and it is the #90/#107 shape that CLAUDE.md's
invariant exists to forbid. Refusing when the comparison cannot be made is
part of the rule rather than a fallback: "I cannot tell whether this file
holds a different identity" and "this file holds the same identity" are
different answers, and only one of them permits a write.

*Note the asymmetry, which is the reason `protect` and `unprotect` do not get
the same rule.* `protect` cannot destroy anything once its read-back and DID
checks pass — the worst it can do is orphan a keychain entry, and an orphaned
entry is still reachable through Keychain Access. `unprotect` writes over a
file. Symmetry would have been tidier and would have got this wrong in one
direction or the other.

**These commands must not route through `commit_identity()`.**
`Command::Identity` currently calls `ws.commit_identity()` before dispatch
(`src/cli/mod.rs:844`), which resolves-or-creates. For `protect` that would
mean minting an identity in order to protect it — a creation as a side effect
of a command that is not about creating one, which is AC-8's class. Both
commands resolve via `workspace_identity` directly and refuse on `None`.
`Adopt` and `Authors` already take a bypass through `is_read_only`
(`src/cli/mod.rs::is_read_only`); these need the same shape for a different reason, and
the reason should be in the comment, since the existing bypass's rationale
("read-only") does not apply.

**Surface.** Two new `IdentityAction` variants (`src/cli/mod.rs:338`).
No new flags: `protect` has exactly one backend today, and a flag with one
legal value is noise. Passphrase-encrypted-at-rest is the second backend and
arrives with the agent (ADR-87 layer 2) — at which point `protect --passphrase`
is a compatible addition, which is the argument for not inventing the flag now.

**The recovery hole this is adjacent to but does not fill.** `kan identity
restore` (`src/cli/mod.rs:882`) only *checks* a phrase — it prints which DID
the words belong to and never installs it. Worse, it routes through
`commit_identity()`, so in the lost-key workspace where it would matter it hits
`create_workspace_identity`'s refusal and cannot run at all. An operator
holding 24 words and no key has no supported way to make them this workspace's
identity. That is a real gap, it is the same destination `unprotect` writes to,
and it is **out of scope** by the milestone's fence — to be filed, not built
here.

## Open Questions

*(Q1 — what becomes of the superseded plaintext file — is resolved; see
"Deleting the superseded plaintext copy" above.)*

*(Q2 — a workspace holding both a plaintext secret and a pointer — is
resolved; see "The overlap" under the executor, and REQ-3.2's stale-reference
rule.)*

None remain.

## Out of Scope

- **Passphrase-encrypted at rest** (ADR-87 layer 1's other half) and **the
  signing agent** (layer 2). An agent's entire job is caching one unlock, so it
  is worth having only once the key is encrypted at rest — the ordering ADR-87
  established. Neither is v0.12.
- **`kan init`** (#173) and **`kan config`** (#174). Resolved Q3 already ruled
  out prompting at creation time, which is what would have pulled `init` in.
- **#96's `protected`-backend spike.** Code signing, and one timeboxed spike is
  permitted by the milestone but is not this requirement.
- **Installing a recovery phrase** (the `restore` gap above). File it.
- **REQ-5** (role declarations become claims) and all of Cluster B.
