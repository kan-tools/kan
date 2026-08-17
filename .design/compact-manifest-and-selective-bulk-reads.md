# Feature: Compact manifest and selective bulk reads

## Summary

Turn kan's whole-workspace read into a two-stage protocol: a body-free manifest
from `kan status --json`, followed by one structured `kan show` invocation that
hydrates only selected exact subjects or visible subject prefixes. Preserve
`kan show --all --json` as the complete graph-transfer contract, and close
kan#202 in the same stacked PR so the newly recommended manifest path performs
no eager Git-ancestry work on uncontested subjects.

This design serves `telos/performance-at-scale` by removing both unnecessary
claim-body transfer and quadratic ancestry subprocesses from orientation. It
also serves `telos/raw-data-and-projections`: counts, heads, revisions, status,
and selected views remain deterministic projections over the visible trusted
claim set, never stored state. The PR is stacked on
`design/read-write-surface`, whose implementation of kan#216 supplies the
authority and projection boundary this read contract must obey.

## Requirements

- REQ-1: `StatusEntryJson` in `src/json.rs` must add `claim_count`,
  `kind_counts`, `head`, and `revision`. These fields describe all trusted,
  visible, live claims in the entry's folded `SameAs` merge class, including
  retractions and unknown claim kinds; they must never contain narrative claim
  bodies.
- REQ-2: `head` must describe the final claim in the merge class's existing
  deterministic folded order with exactly `cid`, `kind`, and optional
  `recorded_at`. It is not selected by maximum wall-clock time. `kind_counts`
  must use stable claim-kind names and deterministic key ordering.
- REQ-3: Every status entry must emit a lowercase
  `sha256:<64 hexadecimal digits>` revision over the ordered visible CID bytes
  in its merge class. `StatusJson` must add a whole-view revision over the
  trust frame and ordered visible subject classes. Both digests must use
  distinct versioned domain prefixes and length-prefix every variable-width
  value.
- REQ-4: The whole-view revision must cover the trust-base name, admitted
  authors (including optional legacy agent keys) and weights in deterministic
  `(DID, agent)` order, every visible class's
  primary and alias names, and its subject revision. Excluded claim CIDs and
  wholly excluded subject names must never enter either digest. Existing
  `excluded_by_trust` fields remain the only disclosure that a trust-narrowed
  view is partial.
- REQ-5: `src/cli/mod.rs` must preserve `kan show <subject> --json` and add
  repeatable `--subject <name>` and `--prefix <prefix>` selectors. Selectors
  require `--json`, conflict with the positional subject and `--all`, and may
  be combined with each other. `show` with no positional subject, selector, or
  `--all` remains a usage error.
- REQ-6: Selected hydration must read and fold the complete trusted workspace
  once, then select merge classes immediately before serialization. An exact
  selector matches any visible name in a trusted `SameAs` class; a prefix
  matches visible folded names only; several selectors that reach the same
  class return it once under the canonical primary label.
- REQ-7: Every selected entry must be field-for-field the same `ShowJson` value
  that client-side filtering of `show --all --json` would retain. Inbound edges
  from unselected source classes must remain present because selection narrows
  serialization, not the graph used to compute a selected view.
- REQ-8: Selected hydration must use a new top-level JSON envelope containing
  schema version, trust, log-wide `excluded_by_trust`, published-read
  diagnostics, `visible_subjects`, `matched_subjects`, and selected
  `subjects`. Both subject counts count folded merge classes, not alias names.
  Zero matches is a successful, explicit result. Prefix metadata must never
  disclose a wholly trust-excluded subject name or selector-specific hidden
  count.
- REQ-9: Selected hydration is all-or-nothing. It must perform one
  `all_stored_claims` read and one fold, with no fallible per-subject reads;
  any read or serialization failure fails the invocation rather than silently
  omitting a selected class. Log-wide published-read diagnostics remain
  attached once to the outer envelope.
- REQ-10: `show_all_json` and `ShowAllJson` must remain unchanged as the
  complete graph-transfer path established by ADR-71 and ADR-81. Existing
  status and show fields retain their meanings, all new JSON fields are
  additive, and `SCHEMA_VERSION` remains `1` under ADR-50 and ADR-60.
- REQ-11: kan#202 must be closed structurally, not by adding another narrowed
  eager call. Status classification must request Git ancestry only after the
  fold has found two or more live status positions with different values, and
  only among those disagreeing positions. An uncontested subject, a subject
  with no Status claims, or several agreeing live statuses must execute zero
  Git-ancestry subprocesses.
- REQ-12: Production callers must name the computed relation provider they
  consume. The catch-all `relations::compute_default` path must have no
  production caller and should be removed; status classification requests
  `GitAncestry`, while the related-subject view requests `GitSameFile`. The
  implementation and tests must enumerate every remaining production
  `RelationProvider`, `compute_all`, and direct `.relations` call site and
  state which edge kinds its consumer reads.
- REQ-13: The performance grid and focused regression tests must turn #202's
  repair into a scaling contract. `status-all`'s claims-axis bound in
  `tests/fixtures/perf-bounds.tsv` must move from the measured defective bound
  of 400 to a near-linear predicted bound, and binary-level tests must count
  `git merge-base` invocations for uncontested, agreeing, and contested status
  fixtures instead of using elapsed time as the only oracle.
- REQ-14: Documentation must teach manifest -> select -> hydrate, retain
  `show --all --json` for consumers that require the complete graph, explain
  revision privacy and trust-frame scope, and keep `context` described as a
  ranked token-budgeted projection rather than an inventory.

## Acceptance Criteria

- [ ] AC-1: A fixture containing narrative, Status, Relation, Retraction,
      Rejection, Subject, and unknown-kind claims asserts that every
      `status --json` row's `claim_count`, `kind_counts`, and `head.cid` agree
      CID-for-CID with the corresponding `show --all --json` entry, and that
      no manifest field contains narrative text. (REQ-1, REQ-2)
- [ ] AC-2: Repeating `status --json` over an unchanged claim set and trust
      frame produces byte-identical subject and whole-view revisions. A
      narrative-only append changes both relevant revisions without requiring
      a status change. (REQ-3)
- [ ] AC-3: Revision-vector tests pin the exact domain strings, length-prefix
      encoding, trust-base encoding, `(DID, agent)` ordering, weight encoding,
      alias encoding, CID byte encoding, and lowercase `sha256:` output for at
      least one committed fixture. Subject and whole-view digests over
      identical payload bytes differ because their domains differ. (REQ-3,
      REQ-4)
- [ ] AC-4: Narrowing a multi-author fixture's trust changes the visible
      counts and revisions without placing an excluded CID or wholly excluded
      subject name into any returned digest input or selector metadata. Two
      differently named trust frames over the same visible claims produce
      different whole-view revisions. (REQ-4)
- [ ] AC-5: Clap tests accept repeated `--subject`, repeated `--prefix`, and a
      mixture of both with `--json`; retain the positional single-subject
      form; and reject selectors without JSON, selectors with `--all`,
      selectors with a positional subject, and an unqualified bare `show`.
      (REQ-5)
- [ ] AC-6: Exact selection by either alias of a trusted `SameAs` class returns
      that class once under the same primary label as `show --all`; overlapping
      exact and prefix selectors still return one entry. A prefix matches only
      visible folded names. (REQ-6)
- [ ] AC-7: Over a varied fixture containing `SameAs`, retraction, rejection,
      unknown kinds, multi-author trust, superseded statuses, and relations,
      selected entries equal client-side filtering of `show --all --json` as
      complete JSON values. (REQ-7)
- [ ] AC-8: A relation from an unselected class into a selected class remains
      in the selected entry's `inbound` array with identical CID, kind,
      relation, source, and author fields. (REQ-7)
- [ ] AC-9: Selected-envelope tests distinguish a clean zero-match response
      (`matched_subjects == 0`), a matched class with per-class trust
      exclusions, a view with wholly excluded content through log-wide
      `excluded_by_trust`, and a degraded published read through nonempty
      diagnostics. No prefix response names a wholly excluded subject.
      (REQ-8)
- [ ] AC-10: A structural test proves selected hydration invokes one
      `all_stored_claims` path and contains no per-subject read loop; an
      injected whole-read failure fails the command without returning a
      partial `subjects` array. (REQ-9)
- [ ] AC-11: Existing `tests/bulk_read.rs` and `tests/json_contract.rs` pins for
      `ShowAllJson`, nested `ShowJson`, all-or-nothing behavior, additive
      fields, and `SCHEMA_VERSION == 1` continue to pass without weakening.
      (REQ-10)
- [ ] AC-12: With `git` shimmed to count `merge-base` calls, `status`, `issues`,
      `show`, and `context` execute zero ancestry queries for subjects with no
      statuses, one status, or several agreeing live statuses. (REQ-11,
      REQ-13)
- [ ] AC-13: A fixture with three live disagreeing status positions on
      distinct commits executes ancestry queries only for pairs among those
      three positions and produces the same `StateView` as the existing eager
      edge implementation. Retraction and citation dominance retain their
      current results. (REQ-11)
- [ ] AC-14: A source-level inventory test fails if production code introduces
      `compute_default`, invokes more than the declared provider call sites, or
      computes an edge kind its immediate consumer does not read. The
      committed inventory names status classification -> `GitAncestry` and
      related-subject lookup -> `GitSameFile`. (REQ-12)
- [ ] AC-15: `tests/fixtures/perf-bounds.tsv` changes `status-all`'s
      claims-axis row from the measured defective bound of 400 to a PREDICTED
      bound no greater than 32, with #202 cited; the first CI measurement is
      retained for later conversion to MEASURED. (REQ-13)
- [ ] AC-16: README documentation includes working manifest, exact-selection,
      prefix-selection, and complete-graph examples and explains which of
      `status`, selected `show`, `show --all`, and `context` answers each read
      question. (REQ-14)

## Architecture

### Manifest projection

`src/json.rs` owns the public shapes. Add a small `HeadJson` containing `cid`,
`kind`, and optional `recorded_at`, then extend `StatusEntryJson` with the four
REQ-1 fields and `StatusJson` with `revision`. `json::status_entry` already
receives the complete folded `SubjectView`, so it can derive counts and head
without another store read or fold. A `BTreeMap<String, usize>` makes
`kind_counts` byte-stable. Claim-kind strings must come from the same helper
used by `ClaimJson`, preventing an unknown kind or future kind from being
named differently by manifest and hydration.

Put revision encoding in a private helper module near the JSON projection,
not in `src/store/` or the SQLite index. The subject preimage is:

1. ASCII domain `kan.status.subject-revision.v1`;
2. the number of live CIDs as an unsigned fixed-width integer;
3. each CID's binary bytes, preceded by its unsigned fixed-width byte length.

The whole-view preimage is:

1. ASCII domain `kan.status.view-revision.v1`;
2. the trust-base name;
3. admitted `(DID, optional agent key, weight)` tuples sorted the same way as
   `TrustBase::authors`, with an explicit option tag and weights encoded by
   canonical IEEE-754 bits rather than formatted decimal prose;
4. each folded class in the fold's stable order, including its primary name,
   sorted alias names, and decoded 32-byte subject digest.

Every variable-width item is length-prefixed. The public representation is
`sha256:` plus 64 lowercase hexadecimal digits, using the existing `sha2`
dependency. Versioned domains permit a future encoding change without making
old and new revisions collide. Including trust metadata ensures two frames
over the same visible CIDs do not collide accidentally; excluding filtered
CIDs and names prevents the revision from becoming an equality oracle for
hidden evidence.

### Selected hydration

In `src/cli/mod.rs`, retain the existing positional `subject: Option<String>`
and add separately named vectors with `#[arg(long = "subject")]` and
`#[arg(long = "prefix")]`. Clap constraints reject ambiguous mixtures before
opening a workspace. Positional selection keeps returning one `ShowJson` for
backward compatibility. Flag selectors route to a new
`actions::show_selected_json` and always return the selected envelope, even
when only one exact flag is supplied.

Factor the construction of a nested `ShowJson` in `src/actions.rs` out of
`show_all_json` so complete and selected bulk paths call the same function.
The helper receives the complete `FoldedView`; therefore
`inbound_edges_json` continues to see relations from unselected classes.
`show_all_json` retains its present envelope and behavior. The selected path
performs the same single `all_stored_claims` read and fold, filters
`view.classes` afterward, deduplicates by class identity, and serializes in
the fold's stable order rather than selector argument order.

Exact selectors compare against every visible name in `class.subjects`.
Prefix selectors do the same but never inspect pre-trust raw subject names.
`visible_subjects` is `view.classes.len()` and `matched_subjects` is the
deduplicated selected-class count. Log-wide exclusion and publication-error
metadata remain honest about partial inputs without claiming which hidden
subject a prefix might have matched.

### Demand-driven relations

Today `actions::status_classification_edges` narrows
`relations::compute_default` to Status claims, which fixed the worst accidental
fan-out but still computes every ancestry pair before `fold::state::classify`
knows whether it will read one. Split classification into a pure first phase
that establishes the live per-author status positions and handles the
unclassified, single-position, and all-agree cases. Only the disagreement
branch invokes a supplied ancestry computation over those live positions,
then applies the existing `dominated_cids` rules.

The action layer supplies `GitAncestry` for that lazy branch because Git access
belongs outside the pure fold. `GitAncestry::relations` may retain its internal
pair cache, but its input is now the minimal disagreeing live set. The existing
eager-edge classification entry point can remain as a test/reference oracle
until equivalence is pinned; production callers use only the demand-driven
entry point.

Remove `compute_default`, the API that makes asking for unused providers easy.
The only production provider sites after the change are:

| consumer | provider | input | consumed edge |
|---|---|---|---|
| status classification used by `status`, `issues`, `show`, and `context` | `GitAncestry` | live disagreeing Status positions in one class | `Ancestry` |
| `related_subjects_by_file` | `GitSameFile` | live claims across the folded view | `SameFile` |

`tests/state_fold.rs` may invoke providers directly to establish reference
behavior, but no production catch-all remains. A source-inventory test pins
the table's production side so the third instance of compute-more-than-used
cannot arrive as an unreviewed call.

### Performance contract

Replace elapsed-time-only coverage in `tests/show_status_edges_perf.rs` with a
Git shim that counts `merge-base --is-ancestor`. The negative controls are
uncontested and agreeing status sets, which must count zero. The positive
control uses disagreeing positions on distinct commits and proves both that
queries occur and that their count is bounded by pairs among the supplied
positions.

`tests/fixtures/perf-bounds.tsv` lowers `status-all`'s 16x-claims bound from
400 to at most 32 as PREDICTED. The full perf workflow remains the measured
shape oracle; this PR must not manufacture a MEASURED label before CI runs.
The subjects-axis and unrelated operations retain their existing rows unless
the implementation changes their measured generator.

## Open Questions

None remaining.

## Resolved Questions

- RQ-1: The focused PR is stacked on `design/read-write-surface`, so kan#216 remains
  the base and the review diff contains only kan#232 plus the required kan#202
  closure.
- RQ-2: kan#202 is closed fully in this PR: demand-driven ancestry, production
  call-site inventory, subprocess-counting regression controls, and the
  tightened perf-grid prediction all ship together.
- RQ-3: The existing positional `show` form remains intact. Repeatable `--subject`
  and `--prefix` flags select the new bulk envelope and cannot be mixed with
  the positional form or `--all`.
- RQ-4: Revisions use public versioned `sha256:<hex>` values with domain-separated,
  length-prefixed preimages. Subject revisions cover ordered visible CIDs;
  whole-view revisions additionally cover the visible trust frame and class
  naming without hashing excluded evidence.
- RQ-5: Selection occurs after the complete trusted fold. Exact aliases and visible
  prefixes select a class once; inbound edges are computed from the unfiltered
  folded graph; all-or-nothing failure is retained.

## Out of Scope

- Human rendering changes from kan#199, including shortening CIDs, reversing
  claim order, or making rendered `status` one physical line.
- Any change to `context` ranking, token budgeting, or omission accounting.
- Persisting revisions, counts, heads, relation edges, or any other derived
  projection in the log or SQLite index.
- A title-resolution fold or a synthetic current title in the manifest.
- Changing claim, CAR, MST, publication, or SQLite wire/storage formats.
- Updating `day` skills or downstream fingerprinting before the kan JSON
  contract ships; downstream adoption is a separate repository change.
- Closing or merging the stacked kan#216 branch as part of this implementation
  branch.
