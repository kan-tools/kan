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
   workspace is keychain-rooted. `register_active` (deleted by this requirement;
   see Architecture) wrote that
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
  circular with the trust base it feeds. Role resolution consults
  `excluded_by_retraction` and **deliberately not**
  `src/fold/identity.rs::excluded_by_rejection`: a rejection is another author's
  suppression of a claim, honoured only by folds that trust the rejecter, and
  letting one suppress a declaration would hand a third party a revocation
  power the declaring workspace never granted. `sign::list_roles` stops being
  the source for `Workspace::role_trust_entries`,
  `Workspace::undeclared_log_authors`, `--trust role:<name>`, and
  `kan identity authors`.
- REQ-4: **The registry drops the key path, and `SelectionMissing` absorbs the
  case it served.** The claim carries `{did, name}` only — a local absolute
  path is machine-specific, is already unchecked (see above), and under REQ-2
  would be publishable. `kan identity role add` keeps minting at
  `.kan/roles.d/<name>`; `KAN_IDENTITY_FILE` continues to name a path directly.
  `Error::DeclaredRoleKeyMissing` is **deleted rather than reconstructed**: it
  matched a missing path against the registry's third column, and a DID cannot
  substitute, because computing one requires loading the key that is missing.
  Instead `Error::SelectionMissing` — which today says only "no key at
  `<path>`" — carries the path, the role names this workspace declares, and
  where kan mints role keys. That answers the operator's actual question
  (*which key did I mean, and where should it be*) in **every** case, including
  a role minted with `--key` elsewhere, which the deleted error never could.
  Strictly more information than the status quo, and one fewer variant.
- REQ-5: **`kan identity role import`** — one-shot, explicit. Reads
  `.kan/roles`, writes one `RoleDeclaration` per row, and is idempotent
  (a row whose DID and name already have a live declaration is skipped, not
  duplicated). It **never rewrites and never deletes** the file. It closes by
  telling the operator the file is no longer read by this kan and is safe to
  remove, naming the one reason to keep it: a kan older than v0.12 reads the
  file and cannot interpret declarations.

  **A workspace holding an unimported `.kan/roles` is told so**, on
  `kan identity role list` and `kan identity authors` — the two surfaces an
  operator asks on — naming the command that brings it across. Decided with
  Maxine, and it closes the one cost the one-shot choice carried: without it,
  upgrading makes `--trust roles` go empty and every author report
  `UNDECLARED`, with nothing pointing at the file in `.kan/`. kan still never
  *reads* the file for resolution; the notice checks only that it exists, and
  disappears on its own once anything is declared.
- REQ-6: **Latest declaration wins per name**, in log order. An append-only log
  cannot refuse a duplicate the way `add_role` does, so the fold needs a rule,
  and log order is the convention already used for intra-author supersession
  (`src/fold/state.rs::classify`: "`class_claims` is already chronological").
  A DID declared under two names resolves under both; a name declared for two
  DIDs resolves to the later. The write-time refusals (`RoleNameTaken`,
  `RoleAlreadyRegistered`) stay as **affordance** — they warn before the log
  grows a shape that needs a tiebreak, they do not enforce.
- REQ-7: **Declaring refuses when the signer is not the workspace identity, and
  when there is no workspace identity at all.** Running
  `kan identity role add|import` with `KAN_IDENTITY_FILE` pointing at a role
  would write a claim that folds as inert — a complete-looking write that
  grants nothing. It errors instead, naming both DIDs.

  *Both arms refuse, and the second is not a formality.* Written first as
  "compare the signer against the workspace identity **if there is one**",
  which skipped the check entirely for a workspace that has none — so
  `role add` reported success, printed `declared role`, and nothing could ever
  honour the result. A guard with a hole in exactly the shape it guards
  against. Found by the change-ledger golden when it was extended to cover a
  populated role listing.

  **This removes a capability from identity-file-only workspaces**, which is
  the CI/`day`/agent configuration `.design/v0.12-milestone.md`'s REQ-2
  amendment describes — under `.kan/roles` they could declare, because a file
  read needs no identity. Decided with Maxine to accept: roles require a
  workspace identity, and the refusal names `kan identity adopt --key <path>`
  as the way to get one. **Four call sites across three existing test files** asserted the old
  behaviour — `tests/guard_every_minting_path.rs`, `tests/review_fixes.rs` and
  `tests/trust_vocabulary.rs` (twice) — each now adopting its key first. *This
  paragraph said "exactly one existing test … so the blast radius is measured
  rather than estimated". It was estimated from a truncated `grep`, and the
  correction is the more useful fact: the identity-file-only workspace is the
  shape most of this suite is written in, which is the same population REQ-2's
  amendment calls the configuration `KAN_IDENTITY_FILE` exists for.* The lost-key hazard this raises is answered in REQ-9.
- REQ-8: **`--trust roles` reports three states rather than one empty frame.**
  It stays an empty frame — never an error — and the disclosure says *which*
  empty: (a) nothing declared; (b) no workspace identity is resolvable, so no
  declaration can be honoured; (c) declarations exist but none were authored by
  this workspace. State (c) is information the file version could not produce
  at all.

  *Specified as an error first, and reversed.* The argument for erroring was
  consistency with `--trust me`, which raises `NoIdentityToName`. It is weaker
  than it looks: `me` **is** the identity, so the question is meaningless
  without one, whereas "the set this workspace vouched for" is a legitimate
  question whose answer is legitimately empty. What actually decided it is
  **composition** — `--trust roles --trust did:key:abc…` is valid today, and an
  erroring alias means one member of a set failing to expand kills the whole
  read, so an alias that composes stops composing. It also sits badly with
  REQ-1's ethos: a read that *errors* because it could not resolve an identity
  is one step from a read that *needs* one.

  **The reason reaches `--json` as `trust.empty_reason`**, decided with
  Maxine, because the consumer that most needs to tell these apart is an agent
  reading JSON and it cannot ask a follow-up question. Additive and omitted
  when absent, so every view that named an author serializes byte-identically —
  `docs/SPEC.md` §7.1's rule for claim fields, applied to the read contract.
  Human output carries the same sentence beside the exclusion note, which is
  also what the MCP surface renders.

  *One ordering decision falls out, and it is not arbitrary*: **"nothing
  declared" wins over "no workspace identity"**. With no declarations anywhere,
  that is the true and more useful answer whoever is asking, and reporting the
  identity problem would send an operator to recover a key that would reveal
  nothing. `NoWorkspaceIdentity` therefore means exactly *declarations exist
  here and none can be honoured* — the lost-key state, which is the one worth
  naming. Found by writing AC-10's witness, where states (a) and (b) came back
  identical.
- REQ-9: **`kan identity adopt` re-declares the live role set under the new
  identity, and prints what it re-declared.** Adopt changes the workspace DID,
  so every declaration authored by the previous identity would stop being
  honoured — and could not be retracted either, retraction being self-only.
  Under `.kan/roles` this did not arise, because adopt never touched the file.
  At adopt time kan holds both DIDs and can resolve the current set, so it
  appends one fresh declaration per role. `src/sign.rs::primary_role_name` (the
  surviving half of `register_active`) is the
  precedent and the same argument: it fires at the one moment the identity is
  loaded and its DID is known.

  *This is a write side effect of another command, which is the shape #183
  retired, so the distinction has to be earned rather than assumed.* #183's
  migration moved a **secret**, fired during *resolution* (so `kan show` could
  trigger it), and could be neither seen nor undone. This one fires during an
  explicit write command, prints every claim it appends, is undone by
  `kan retract`, and is independently askable as `kan identity role import`.
  Visible, deliberate, reversible — the three properties #183 found absent.

  **It resolves the set from the declaration authors, not from the workspace
  identity, and that is what makes it work when it is needed.** Asking
  `declared_roles()` would ask `workspace_identity` — which is *precisely what
  is missing* in the case adopt exists for. Lose the key and the chain is:
  resolution returns `NoWorkspaceIdentity`, the set is empty, and adopt
  re-declares nothing, silently. Writing the new key first makes it worse, as
  the identity then resolves to a DID that has authored no declarations, so the
  set is empty for a second reason. So adopt captures the set **before**
  switching keys and resolves it by asking *who has authored `RoleDeclaration`
  claims here* — answerable with no identity at all, since every claim carries
  its author. One such author: carry its live set across and say so. Several:
  report them and re-declare none, rather than guess which was the workspace.

  *Raised by Maxine asking whether requiring a workspace identity breaks when
  identity files get lost.* It does, and this is the same shape as the
  succession-claim problem recorded above — the case that needs the mitigation
  is the case that cannot satisfy its precondition. `role import` does not cover
  it either: only a *migrated* workspace has a `.kan/roles` to re-read, and one
  created after v0.12 never had one. With this, role declarations survive
  exactly as well as the claims themselves, which is what the whole
  make-it-a-claim argument was buying.

  **It refuses to carry rather than carrying wrong.** The writable open used to
  append resolves a *selection* from `KAN_IDENTITY_FILE`, not the key just
  adopted, so with that variable pointing elsewhere the declarations would be
  authored by a third identity and grant nothing. Adopt compares the resolved
  signer against the adopted DID and, on a mismatch, carries nothing, says so,
  and names the remedy (re-run with the variable unset). Nothing is lost either
  way: the previous declarations stay in the log. *Added answering a cold
  review, which measured the alternative — `--trust roles` going from three
  authors to zero while stdout reported a successful carry.*

  *Narrower than it first appears*: `src/actions.rs::adopt_identity` **refuses a key
  that authored none of the log's claims**, so the adopted identity is always
  an existing co-author rather than a stranger.

## Acceptance Criteria

Every criterion names its witness, per `atom/design`. Where there is no
mechanical witness the criterion says so and is marked **intent**.

**A witness for shipped code is written as a resolvable citation — the
`<file>::<symbol>` form — not as prose**, so `scripts/check-citations.sh` resolves it like any other. The prose
form — "`tests/foo.rs` (new), test `bar`" — exists only for a test that has not
been written yet, and it must be converted the moment it is.

*That escape hatch was invented here, and it is where three unwitnessed
criteria hid.* AC-1, AC-8 and AC-10b each named a test that did not exist;
three cold review rounds passed before a fourth said so. The gate could have
caught all three for free, since it already resolves a `fn` in a test file —
they were simply written in the one form it does not check. Borrowed from
`day`'s teloi, which declare **witness types** the bridge check can compute
over rather than describe them in prose.

- [ ] AC-1: For REQ-1, a `RoleDeclaration` claim round-trips byte-identically
      and an older reader preserves it as `Unknown` rather than dropping or
      rejecting it. *Witness*: `tests/schema_evolution.rs` —
      `body_kinds_all_round_trip` (already fails if `KnownBody` drifts from
      `ClaimBody`), plus a new case constructing a `RoleDeclaration` with an
      unknown field, per ADR-48's rule that the test must use a *known* kind —
      `tests/schema_evolution.rs::a_role_declaration_with_an_unknown_field_is_preserved_verbatim`. *Named
      here for three rounds before it existed; written when a fourth said so.*
- [ ] AC-2: For REQ-1, every claim CID written before this variant existed is
      unchanged. *Witness*: `tests/golden_reads.rs`'s AC-1 invariant golden,
      which must pass untouched.
- [ ] AC-3: For REQ-3 + REQ-2 — **this is AC-10 of the milestone** — a role
      declaration carries an author, and retracting it removes the role from
      `--trust roles` **with no file edited**. *Witness*: a new
      `tests/role_declaration_lifecycle.rs::retracting_a_declaration_removes_the_role`,
      asserting the `.kan/` directory listing is byte-identical before and
      after the retraction.
- [ ] AC-4: For REQ-3, a role whose declaring claim is retracted cannot sign as
      a declared role: `--trust role:<name>` errors with `NoSuchRole` and
      `kan identity authors` reports that DID as UNDECLARED. *Witness*:
      `tests/role_declaration_lifecycle.rs::a_retracted_role_is_undeclared`.
- [ ] AC-5: For REQ-3, a `RoleDeclaration` authored by **anyone other than** the
      workspace identity grants nothing — it appears in `kan show` as an
      ordinary claim and does not appear in `--trust roles`. *Witness*:
      `tests/role_declaration_lifecycle.rs::a_foreign_declaration_grants_nothing`. This
      is the REQ-8 pre-condition and must exist before the sharing channel opens.
- [ ] AC-6: For REQ-5, importing `sheaf-games`'s four rows declares all four,
      **also ensures this workspace's own identity is declared**, and running
      import twice adds nothing. The author set is a superset of the file's
      rows, never a subset: a registry that omits the importing workspace drops
      every claim it ever wrote out of `--trust roles`, which a third cold
      review graded blocking. On the real file the extra step is a no-op, since
      its `primary` row already names that workspace. *Witness*:
      `tests/role_declarations.rs::import_is_idempotent_and_preserves_the_set`,
      seeded from a fixture copy of that file — **not** from the live workspace.
- [ ] AC-7: For REQ-5, import leaves `.kan/roles` byte-identical. *Witness*:
      same test, hashing the file before and after.
- [ ] AC-8: For REQ-6, a name declared twice for different DIDs resolves to the
      later declaration, deterministically, across an index rebuild. *Witness*:
      `tests/role_resolution_rules.rs::latest_declaration_wins_per_name`,
      which states the rule against the pure resolver and asserts that REVERSING
      the log order reverses the answer — so it tests the ordering rule rather
      than something incidental to the DIDs. `tests/role_declaration_lifecycle.rs::the_declared_set_survives_an_index_rebuild`
      covers the rebuild half.
- [ ] AC-9: For REQ-7, `KAN_IDENTITY_FILE` pointing at a declared role makes
      `kan identity role add` refuse, and **no claim is appended**. *Witness*:
      `tests/role_declarations.rs::a_role_cannot_declare_a_role`, asserting the
      log length is unchanged — depth 0's negative control.
- [ ] AC-10: For REQ-8, all three empty states are reachable and each reports a
      *different* disclosure, and none of them errors. The composition case is
      the point: `--trust roles --trust did:key:…` returns the named author's claims
      even when `roles` expands to nothing. *Witness*:
      `tests/role_declarations.rs::three_empty_roles_frames_read_differently`,
      asserting the three messages differ pairwise rather than merely that each
      is non-empty — an assertion that every state says *something* is one a
      single hardcoded string would pass.
- [ ] AC-10b: For REQ-3's rejection rule, a `Rejects` claim naming a live role
      declaration — authored by a trusted author, so the fold would honour it
      anywhere else — leaves `--trust roles` unchanged. *Witness*:
      `tests/role_resolution_rules.rs::a_rejection_cannot_revoke_a_role`. The
      negative control for the hole a later symmetry-minded reader would open. It
      also asserts that a self-RETRACTION does remove the role, without which the
      rejection assertion would pass against a resolver honouring nothing at all.
- [ ] AC-10c: For REQ-9, `kan identity adopt` either leaves `--trust roles`
      returning the **same author set** it returned before the adopt and names
      each re-declared role on stdout, **or** carries nothing and says plainly
      that it did not. What it must never do is report a carry it did not
      perform — the two outcomes are asserted as mutually exclusive, because a
      bare "did it mention carrying?" check matches the refusal text too.
      *Witnesses*, and it takes two because the branches live apart:
      `tests/role_declarations.rs::adopt_carries_the_role_registry_across`
      for the carry — comparing the set before and after rather than counting
      it, so a set that changed membership while keeping its size cannot pass —
      and `tests/role_review_fixes.rs::adopt_does_not_carry_roles_under_a_stray_selection`
      for the refusal,
      which is where the mutual exclusion is asserted. *This criterion named
      only the first for one round, describing an assertion the named test does
      not make.*
- [ ] AC-11: For REQ-4, `kan identity role list` reports name and DID and **no
      key path**, human and `--json`. *Witness*:
      `tests/role_declarations.rs::role_list_reports_two_columns_and_no_key_path`.

      *This criterion originally named the change-ledger golden as its witness,
      and the golden structurally cannot be one.* Its fixture workspace is
      driven entirely by `KAN_IDENTITY_FILE` and has no identity of its own, so
      under REQ-7 it can never hold a declared role — it can only ever freeze
      the **empty** listing, which is what it had been doing since roles
      existed. Corrected during implementation, when extending the fixture to
      cover the populated case is what surfaced that it could not.
- [ ] AC-11b: For REQ-7, the change-ledger golden freezes the **refusal** —
      `kan identity role add` in a workspace with no identity of its own fails,
      naming why the declaration could never be honoured. *Witness*:
      `tests/golden_trust_and_identity.rs` and
      `tests/fixtures/golden/trust-and-identity.txt`; AC-2 of the milestone
      says this fixture is expected to change and that a diff is accepted only
      in a commit naming its requirement. This is the surface the golden
      **can** hold, and adding it is what found the hole in REQ-7's guard.
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
- `src/roles.rs` — **new, and deliberately not under `src/fold/`.** Role
  resolution is not part of the fold; it produces an *input* to it. The rule
  itself is a pure function (`src/roles.rs::declared`) taking the claims and
  the workspace DID as arguments, so it is testable without a workspace, a key
  or a filesystem — the seam drawn one layer deeper than REQ-3's review found
  it drawn last time. `src/roles.rs::Declared` is total, so an empty answer
  always carries its reason (REQ-8).
- `src/sign.rs` — `src/sign.rs::list_roles` survives only as the importer's
  reader. `add_role` and `register_active` are **gone**: the first becomes
  `src/sign.rs::mint_role_key` (a key, no registration — registration is a
  claim now, and the clash checks moved to where the declared set is
  resolvable), the second becomes `src/sign.rs::primary_role_name`, with the
  append itself in `src/actions.rs::declare_role`. `src/sign.rs::ROLES_FILE`
  keeps its constant for the importer, and its docstring is the reversal
  recorded below.
- `src/workspace.rs` — `src/workspace.rs::role_trust_entries`,
  `src/workspace.rs::undeclared_log_authors` and `trust_from`'s `role:<name>`
  branch all move to `src/workspace.rs::declared_roles`, which supplies the two
  inputs the pure resolver needs and does nothing else.

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

### Who can change a role, and what the trust root actually is

Asked by Maxine, and worth answering as a closed set rather than a reassurance,
because a privilege-granting claim invites the question. **Change is closed to
the workspace identity, by four independent mechanisms:**

- **Declare** — only the workspace identity; anyone else's declaration folds as
  an ordinary claim and grants nothing (AC-5).
- **Retract** — `excluded_by_retraction` is *self-retraction only*, so a
  `Retraction` takes effect only against a claim by the same author. Nobody
  else can revoke a declaration.
- **Reject** — cannot suppress a declaration at all, per REQ-3. This falls out
  of the resolver as specified, which is exactly why it is written down: a
  later reader adding rejection handling *for symmetry* would open the hole
  without noticing, and symmetry is a persuasive reason to do the wrong thing.
- **`KAN_IDENTITY_FILE`** — cannot shift the set. Resolution asks
  `workspace_identity` (question 1); the selection is question 2. REQ-1's
  separation paying a dividend it was not designed for.

**And the honest framing, which the word "privilege" would otherwise obscure:
the trust root is the local `.kan/` secret, not the log.** Whoever can write
`.kan/` decides which DID counts as this workspace, and therefore which
declarations are honoured — wholesale, without appending anything. Role
declarations are **a local view configuration with provenance**, not a
distributed authorization system. Everything above constrains what *claims* can
do; none of it constrains what filesystem access can do, and it should not be
read as if it did.

*Transitive succession claims — "this identity succeeds that one", followed
across hops — were proposed and deferred rather than dismissed.* They would fix
this class properly and generalise past roles: after **any** adopt, `--trust
me` shows only the adopted identity's claims, which is true today and has
nothing to do with REQ-5. Three reasons they are not here: they reintroduce
precisely what depth 0 fenced out (a depth bound, cycles where `A` succeeds `B`
succeeds `A`, and a retracted intermediate); they **are** ADR-75's vouching,
which `.design/v0.12-milestone.md`'s Out of Scope names explicitly; and the
case that needs one is the case that cannot prove it — a succession claim can
only be signed by the *new* key, since holding the old one means retracting and
re-declaring instead. An unbacked assertion whose only safe scope is local and
unverifiable is a footgun pointed at REQ-8's sharing channel. Wants its own
issue, covering roles, `--trust me`, and "what happened to my old claims".

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

### The error this was going to degrade, and why it improves instead

`src/sign.rs:905` produces `DeclaredRoleKeyMissing` — "you asked to write as
declared role `prover` and that role's key is gone" — by matching the missing
path against the registry's third column. REQ-4 removes that column, and the
DID cannot substitute for it, because computing a DID requires loading the key
that is missing.

*This section originally proposed preserving the error by convention*: a
missing `.kan/roles.d/<name>` for a declared name keeps the specific message,
any other path degrades to the generic `SelectionMissing`. It was measured as
adequate — three of `sheaf-games`'s four rows sit at the default path, and the
fourth is `primary`, which has no role key by construction — and recorded as
the one place REQ-5 made something worse.

**REQ-4 now deletes the variant instead, and that is strictly better.** The
convention preserved a special case that only works where *kan* chose the path,
which is the case least likely to have gone missing; the operator who typed
`--key /somewhere/else` got nothing. Folding the facts into `SelectionMissing`
— the path, the declared role names, where kan mints role keys — answers the
question in every case, including the one convention could not reach, and
removes code rather than adding a fallback.

Worth keeping as a pattern, not just an outcome: the fix that *reduced* surface
beat the one that preserved it, which is the same finding REQ-3's review loop
ended on — the round whose fixes reduced the number of assertions was the round
that terminated it.

## Open Questions

None. The two the milestone left open — migration off `.kan/roles`, and the
SPEC §7.1 downgrade hazard — are resolved above (REQ-5 and *The downgrade
asymmetry*). Six further decisions taken with Maxine on 2026-08-09 are recorded
on `v0.12-milestone` (`bafyreigolvvpx7oqv5jexq4jztr52evigdagfsz7b7govjpozw3xsu6gvq`):
Q4's release boundary, the migration matrix keeping a keychain writer, REQ-8's
three states, REQ-4's deleted variant, REQ-9's adopt behaviour, and the authz
answer above.

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
