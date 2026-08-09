# Feature: role declarations become claims (v0.12 REQ-5)

## Summary

`.kan/roles` is workspace state that is not a claim: a line binding a DID to a
name, in a file the fold is forbidden to read. REQ-5 replaces it with
`ClaimBody::RoleDeclaration { did, name }` — so a role declaration carries an
author, is revoked by retraction rather than by a file edit, and lands where
the resolver already looks. `--trust roles` stops reading a file and starts
reading the log.

`.design/identity-resolution.md` (lines 198–207) calls this "probably the
single highest-value change adjacent to this spec".

## What was already decided before this document

Recorded on `v0.12-milestone`
(`bafyreigxqe6yrsgbc63th3txv24my563lvlzoqans2r6pwxi5alsosyk2u`), not reopened
here:

- **The encoding is forced, so it is not a fork.** No existing `ClaimBody`
  variant carries a DID in its body — `ClaimContent::author` is the *signer*,
  not a subject — so binding a DID to a name needs a new variant, which under
  ADR-18's boundary rule is kan's to own rather than `day`'s.
- **Only the workspace's own identity may declare a role.** A declaration
  authored by anyone else folds as an ordinary claim and grants nothing. The
  reason arrives with REQ-8: once the fold is origin-aware and `.claims/`-borne
  records count as authors, "any author in the log" would let a foreign file
  declare a role for itself. A role declaration is privilege-granting, so the
  rule must be fixed before the sharing channel opens.
- **Depth 0.** A declared role may not declare further roles. That is
  delegation — UCAN's problem, out of v1. Cheap to widen later, expensive to
  narrow once someone depends on it.

## The migration population, measured

Not reasoned about. Every `.kan/roles` file under `~/code`, on 2026-08-09:

| workspace | rows | log authors | at-rest root |
|---|---|---|---|
| `kan` itself | **none** | 1 | `.kan/identity-id` |
| `day` | **none** | 1 | `.kan/identity-id` |
| `maxinelevesque/sheaf-games` | 4 | 4, all four declared | `.kan/identity-id` |

`sheaf-games` is a live multi-role log: `primary` 807 claims, `director` 86,
`prover` 7, `referee` 6 (`sqlite3 .kan/index.sqlite 'select author_did,
count(*) from claims group by 1'`). Its four rows are the entire known
migration population.

**Two corrections this measurement forces on documents already written:**

1. `.design/v0.12-milestone.md` line 254 says "this repo currently holds the
   failure it prevents, a role key whose declaration does not exist." **It no
   longer does** — AC-9 closed that, and `.kan/` here holds no `roles` file at
   all. The sentence is stale and should be corrected when REQ-5 lands, not
   carried as live evidence.
2. The third column of `.kan/roles` — the key path — is **already fiction for
   one row in four**. `sheaf-games`'s `primary` row records
   `…/sheaf-games/.kan/identity`, a file that does not exist there; that
   workspace is keychain-rooted. `src/sign.rs::register_active` writes that
   path unconditionally, whether or not anything is at it. The registry has
   been recording an unchecked path since roles existed.

## Requirements

- REQ-1: **`ClaimBody::RoleDeclaration { did: Did, name: String }`** — a new
  variant added under `docs/SPEC.md` §7.1's additive rule, mirrored in
  `KnownBody` (which carries `deny_unknown_fields`, per ADR-48), with a
  matching `ClaimKind::RoleDeclaration`. **Fold-inert**, exactly as
  `ClaimBody::Publication` is: `src/fold/` contains no reference to either, so
  a declaration carries no status or relational meaning into the fold and
  cannot influence a classification.
- REQ-2: **Declarations live on subject `role/<name>`**, one subject per role.
  `kan show role/director` is that role's whole history — declared, retracted,
  re-declared — which is how AC-10's retraction is aimed without hunting a CID
  out of a shared registry. Matches `day`'s established `telos/<slug>` and
  `atom/<slug>` convention rather than inventing one. `role/*` is an ordinary
  subject namespace: `kan publish role/director` works, and is a deliberate act
  the operator has to name (see *Sharing*, below).
- REQ-3: **Role resolution reads the log, not the file.** The declared set is:
  claims whose body is `RoleDeclaration`, whose author DID equals
  `sign::workspace_identity(kan_dir)`, minus those in
  `fold::identity::excluded_by_retraction`. That function is
  **trust-independent** — self-retraction only — so resolving roles is not
  circular with the trust base it feeds. `sign::list_roles` stops being the
  source for `Workspace::role_trust_entries`, `Workspace::undeclared_log_authors`,
  `--trust role:<name>`, and `kan identity authors`.
- REQ-4: **The registry drops the key path.** The claim carries `{did, name}`
  only. A local absolute path is machine-specific, is already unchecked (see
  above), and under REQ-2 would be publishable. `kan identity role add` keeps
  minting at `.kan/roles.d/<name>`, so the path stays derivable by convention
  where kan created it; `KAN_IDENTITY_FILE` continues to name a path directly.
- REQ-5: **`kan identity role import`** — one-shot, explicit. Reads
  `.kan/roles`, writes one `RoleDeclaration` per row, and is idempotent
  (a row whose DID and name already have a live declaration is skipped, not
  duplicated). It **never rewrites and never deletes** the file. It closes by
  telling the operator the file is no longer read by this kan and is safe to
  remove, naming the one reason to keep it: a kan older than v0.12 reads the
  file and cannot interpret declarations.
- REQ-6: **Latest declaration wins per name**, in log order. An append-only log
  cannot refuse a duplicate the way `add_role` does, so the fold needs a rule,
  and log order is the convention already used for intra-author supersession
  (`src/fold/state.rs::classify`: "`class_claims` is already chronological").
  A DID declared under two names resolves under both; a name declared for two
  DIDs resolves to the later. The write-time refusals (`RoleNameTaken`,
  `RoleAlreadyRegistered`) stay as **affordance** — they warn before the log
  grows a shape that needs a tiebreak, they do not enforce.
- REQ-7: **Declaring refuses when the signer is not the workspace identity.**
  Running `kan identity role add|import` with `KAN_IDENTITY_FILE` pointing at a
  role would write a claim that folds as inert — a complete-looking write that
  grants nothing. It errors instead, naming both DIDs.
- REQ-8: **`--trust roles` distinguishes "nothing declared" from "no identity to
  ask about".** Nothing declared stays what it is today — an empty frame that
  discloses what it excluded. A workspace whose own identity cannot be resolved
  errors, because "who did this workspace vouch for" has no answer without
  knowing who this workspace is. This distinction is **new**: the file version
  could not make it, since a file read needs no identity.

## Acceptance Criteria

Every criterion names its witness, per `atom/design`. Where there is no
mechanical witness the criterion says so and is marked **intent**.

- [ ] AC-1: For REQ-1, a `RoleDeclaration` claim round-trips byte-identically
      and an older reader preserves it as `Unknown` rather than dropping or
      rejecting it. *Witness*: `tests/schema_evolution.rs` —
      `body_kinds_all_round_trip` (already fails if `KnownBody` drifts from
      `ClaimBody`), plus a new case constructing a `RoleDeclaration` with an
      unknown field, per ADR-48's rule that the test must use a *known* kind.
- [ ] AC-2: For REQ-1, every claim CID written before this variant existed is
      unchanged. *Witness*: `tests/golden_reads.rs`'s AC-1 invariant golden,
      which must pass untouched.
- [ ] AC-3: For REQ-3 + REQ-2 — **this is AC-10 of the milestone** — a role
      declaration carries an author, and retracting it removes the role from
      `--trust roles` **with no file edited**. *Witness*: a new
      `tests/role_declarations.rs` (new), test `retracting_a_declaration_removes_the_role`,
      asserting the `.kan/` directory listing is byte-identical before and
      after the retraction.
- [ ] AC-4: For REQ-3, a role whose declaring claim is retracted cannot sign as
      a declared role: `--trust role:<name>` errors with `NoSuchRole` and
      `kan identity authors` reports that DID as UNDECLARED. *Witness*:
      `tests/role_declarations.rs` (new), test `a_retracted_role_is_undeclared`.
- [ ] AC-5: For REQ-3, a `RoleDeclaration` authored by **anyone other than** the
      workspace identity grants nothing — it appears in `kan show` as an
      ordinary claim and does not appear in `--trust roles`. *Witness*:
      `tests/role_declarations.rs` (new), test `a_foreign_declaration_grants_nothing`. This
      is the REQ-8 pre-condition and must exist before the sharing channel opens.
- [ ] AC-6: For REQ-5, importing `sheaf-games`'s four rows produces four
      declarations, `--trust roles` returns the same author set the file
      produced, and running import twice adds nothing. *Witness*:
      `tests/role_declarations.rs` (new), test `import_is_idempotent_and_preserves_the_set`,
      seeded from a fixture copy of that file — **not** from the live workspace.
- [ ] AC-7: For REQ-5, import leaves `.kan/roles` byte-identical. *Witness*:
      same test, hashing the file before and after.
- [ ] AC-8: For REQ-6, a name declared twice for different DIDs resolves to the
      later declaration, deterministically, across an index rebuild. *Witness*:
      `tests/role_declarations.rs` (new), test `latest_declaration_wins_per_name`, asserted
      after `Index::rebuild` so the answer cannot depend on insertion order in a
      live connection.
- [ ] AC-9: For REQ-7, `KAN_IDENTITY_FILE` pointing at a declared role makes
      `kan identity role add` refuse, and **no claim is appended**. *Witness*:
      `tests/role_declarations.rs` (new), test `a_role_cannot_declare_a_role`, asserting the
      log length is unchanged — depth 0's negative control.
- [ ] AC-10: For REQ-8, a workspace with no resolvable identity errors on
      `--trust roles` rather than returning an empty frame. *Witness*:
      `tests/role_declarations.rs` (new), test `roles_without_an_identity_is_an_error`.
- [ ] AC-11: For REQ-4 + the surfaces that move, the change-ledger golden
      records exactly what changed in `kan identity role list` and
      `kan identity authors` output, human and `--json`. *Witness*:
      `tests/golden_trust_and_identity.rs` and
      `tests/fixtures/golden/trust-and-identity.txt`; AC-2 of the milestone
      says this fixture is expected to change and that a diff is accepted only
      in a commit naming its requirement.
- [ ] AC-12: **Intent, no mechanical witness.** A kan older than v0.12 reading
      a v0.12 log sees declarations as `Unknown` and reports only whatever the
      leftover `.kan/roles` still says. Stated precisely rather than measured;
      see *The downgrade asymmetry*.

## Architecture

- `src/claim.rs` — `ClaimBody::RoleDeclaration`, the `KnownBody` mirror
  (`src/claim.rs:301`, `deny_unknown_fields`), `ClaimKind::RoleDeclaration`
  (`src/claim.rs:181`), and the two `From` arms at `src/claim.rs:342` and
  `src/claim.rs:370`. `Publication` (`src/claim.rs:260`) is the worked example
  of an additive variant and should be followed line for line.
- `src/context.rs` — a one-line summary at `src/context.rs:78` and a budget
  rank at `src/context.rs:103`, both of which currently enumerate `Publication`
  and will fail to compile without the new arm. That non-exhaustive match is
  the compiler doing the enumeration work, which is why no checklist is needed
  here.
- `src/sign.rs` — `list_roles` (`src/sign.rs:1022`) survives only as the
  importer's reader. `add_role` (`src/sign.rs:301`) stops appending a line and
  appends a claim; `register_active` (`src/sign.rs:363`) becomes a
  self-declaration by the workspace identity, which depth 0 permits because it
  is the primary declaring itself. `ROLES_FILE` (`src/sign.rs:274`) keeps its
  constant for the importer, and its docstring is the reversal recorded below.
- `src/workspace.rs` — `role_trust_entries` (`src/workspace.rs:670`),
  `undeclared_log_authors` (`src/workspace.rs:686`) and `trust_from`'s
  `role:<name>` branch (`src/workspace.rs:752`) all move from
  `sign::list_roles` to the log-backed resolver.

  *A drift found while reading it, in the exact function REQ-3 rewrites.*
  `Workspace::role_trust_entries`'s docstring says `--trust roles` expands to
  the declared identities **"plus the active one"**, and spends a paragraph
  justifying that choice. Its body maps the declared set only, and
  `tests/trust_vocabulary.rs:203` pins the opposite in words — "the v0.11
  change is that it is now ONLY that, with no active identity injected on
  top". The docstring describes pre-v0.11 behaviour and has been wrong since.
  Two implementations of one fact, drifted, in the function this requirement
  replaces — so REQ-3 must rewrite the prose, not port it.
- `src/store/index.rs` — no schema change: the `claims` table already carries a
  `kind` column (`src/store/index.rs:169`) populated from
  `body.kind()` (`src/store/index.rs:202`), and `all_stored_claims`
  (`src/store/index.rs:259`) is the read path. The `CREATE TABLE IF NOT EXISTS`
  note at `src/store/index.rs:25` applies unchanged.
- `src/cli/mod.rs` — `RoleAction` (`src/cli/mod.rs:446`) gains `Import`;
  `Add`'s dispatch (`src/cli/mod.rs:993`) and `List`'s
  (`src/cli/mod.rs:1022`) move to the log-backed resolver.
- `src/json.rs` — `RoleJson` (`src/json.rs:315`) loses `key_path`, which is
  AC-11's diff.
- `tests/role_declarations.rs` — new, and the home of AC-3 through AC-10.
  `tests/multi_role.rs`, `tests/trust_surface.rs` and
  `tests/trust_vocabulary.rs` hold the existing role behaviour and are where a
  silent change would show.
- `tests/review_fixes.rs` — where fixes answering review findings land, per
  CLAUDE.md's rule that such a fix ships with a test in the same commit.

### The invariant

The fold reads morphisms and never mutates objects, and no operation destroys a
subject. REQ-5 strengthens both: a role's existence stops being a mutable file
line and becomes an append-only, attributable claim. Retraction removes it from
a *view*, retaining it in history — §8's palimpsest, unchanged.

### Sharing, and what E2EE does and does not care about

Checked against the sharing designs rather than assumed. None of
`.design/e2ee-hosted-relay.md`, `.design/hosted-relay.md`,
`.design/sync-layer-architecture-and-staging.md` or
`.design/git-tree-transport.md` mentions roles at all, so this is new ground.

- **L1 E2EE is unaffected.** It encrypts the log as one object;
  `.design/e2ee-hosted-relay.md`'s "what the server learns" puts *"Author DIDs
  within an object"* under **does not see**, beside claim text and subject
  names. A `RoleDeclaration` inside the log is protected identically to every
  other claim, and needs no new key handling.
- **`.claims/` is the plaintext rung, and the DIDs are already there.** Every
  claim a role signs carries that role's DID in its plaintext `author` field
  today. What REQ-5 newly puts on that channel is the **name and the vouching
  fact** — that this workspace calls `zDnaeY4c…` "director" — and only if
  someone publishes a `role/*` subject, which is per-subject and deliberate
  under ADR-43.
- **"Revocation by retraction" is a view change, not capability revocation.**
  Retracting a declaration removes the role from `--trust roles`; it un-signs
  nothing the role already wrote. This matches the file (deleting a line
  un-signed nothing either) and matches `.design/e2ee-hosted-relay.md`'s own
  *"Retroactive revocation — removing a member stops future access only…
  claims are immutable, so this is by construction."* For a
  privilege-granting claim the word "revocation" reads stronger than it is
  unless the doc says this plainly, which is why it is said here.

### The downgrade asymmetry

`docs/SPEC.md` §7.1 preserves unknown kinds rather than rejecting them, so an
older kan reading a v0.12 log decodes each `RoleDeclaration` as an opaque
`ClaimBody::Unknown` and reports roles from `.kan/roles` alone. Because import
never deletes that file, an old kan sees **exactly the set it saw before the
migration** — full fidelity for pre-migration roles, and blindness to any role
declared after. The operator is told this at the one moment it is actionable:
the end of `role import`, where removing the file is offered with its one
consequence named.

*One thing measured, which sharpens how this should be described.* The hazard
is often stated as "`--trust roles` would silently show no roles." It is not
silent. `tests/trust_vocabulary.rs:291` pins the existing behaviour: an empty
roles frame returns zero claims **and** reports `excluded_by_trust: 2`. An
empty frame discloses what it excluded. The downgrade produces a wrong-but-
disclosed answer, not a silent one — which is why this is a documented
asymmetry rather than a blocker.

### The specification argues back: what REQ-5 reverses

`src/sign.rs:269` states a position REQ-5 overturns, and it was argued rather
than assumed:

> Lives inside `.kan/` (gitignored, repo-local per ADR-3) because a role is a
> local process arrangement, not something to share — the *claims* roles write
> are the shareable part, and they already carry their own author.

That reasoning holds for a *path*, which is why REQ-4 keeps the path out of the
claim. It does not hold for the **binding** — the fact that this workspace
vouched for a DID under a name is exactly the kind of attributable, revocable
assertion kan exists to record, and keeping it in a file is what cost it
provenance, an author, and revocation-by-retraction. The docstring must be
rewritten when `ROLES_FILE` becomes the importer's input, not left standing as
a contradicted comment.

### What REQ-5 makes worse, stated rather than discovered later

`src/sign.rs:905` produces `DeclaredRoleKeyMissing` — "you asked to write as
declared role `prover` and that role's key is gone" — by matching the missing
path against the registry's third column. REQ-4 removes that column, and the
DID cannot substitute for it, because computing a DID requires loading the key
that is missing.

The replacement is convention: a missing path of the form
`.kan/roles.d/<name>` where `<name>` is a declared role still produces the
specific error; any other path falls back to the generic `SelectionMissing`.
That covers what `role add` creates — measured, three of `sheaf-games`'s four
rows are at the default path, and the fourth is `primary`, which has no role
key by construction. A role minted with `--key` elsewhere loses the specific
message. This is the one place REQ-5 degrades an existing error, and the
degradation is a less specific message, not a wrong one.

## Open Questions

None. The two the milestone left open — migration off `.kan/roles`, and the
SPEC §7.1 downgrade hazard — are resolved above (REQ-5 and *The downgrade
asymmetry*), decided with Maxine on 2026-08-09.

## Out of Scope

- **Delegation of any depth.** Depth 0 is decided; a role that needs to declare
  roles is a second workspace identity and should be one. UCAN is the thing to
  reach for if this ever crosses actors, and it is beyond v1.
- **Roles as capabilities.** A declaration widens a *view*; it authorises
  nothing, gates nothing, and blocks no write. Affordance, not enforcement.
- **Cross-workspace or foreign-authored roles.** AC-5 pins that they grant
  nothing. Whether they should ever mean anything is REQ-8's question and
  ADR-75's, not this one.
- **A `.kan/roles` writer.** Nothing after import writes that file again. Kan
  does not maintain a downgrade shim; two implementations of one fact is the
  defect class this milestone exists to fix.
- **Deleting `.kan/roles` on the operator's behalf.** Import says it is safe to
  remove and why; the removal is the operator's, made once, with the tradeoff
  in front of them.
- **Changing `.kan/roles.d/` key storage, permissions, or the at-rest posture
  of role keys.** REQ-3's flip covered the workspace root secret; role keys are
  plaintext `0600` files and stay that way here.
- **Publishing policy for `role/*` subjects.** They publish like any other
  subject, deliberately. A reserved namespace `publish` refuses was considered
  and not taken.
