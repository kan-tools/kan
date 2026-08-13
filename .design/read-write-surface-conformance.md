# Feature: Read/write surface specification and conformance

## Summary

Make kan's authority boundary mechanically legible. `docs/SPEC.md` will name
every class of value that can enter a view, a committed catalog will classify
every kan-managed stored field and every external input boundary, and
`tests/surface_conformance.rs` will fail when implementation storage exists
without a declaration or when a disposable projection disagrees with
recomputation from authoritative inputs. This is the `spec-conformance`
witness for `telos/raw-data-and-projections-attained` and the continuing CI
guard for `telos/raw-data-and-projections`.

## Requirements

- REQ-1: `docs/SPEC.md` must specify the read/write surface using three
  authority classes: `authoritative-kan`, `authoritative-other`, and `derived`.
  Authority describes who defines a value's semantics, not which storage
  medium happens to carry it.
- REQ-2: The specification must separate authority from source and medium.
  Kan-authored claims may arrive from the local log, `.claims/`, a future
  replica, or a future atproto repository without changing authority class;
  repository configuration and system configuration are authoritative kan
  inputs with different scopes; Git and other auxiliary inputs are
  authoritative-other.
- REQ-3: A committed `tests/fixtures/read-write-surface.tsv` must declare every
  implemented kan-managed durable artifact. Structured stores must be declared
  at field or column granularity; opaque containers may be declared at artifact
  granularity. Every row must name its authority class, source kind, scope,
  storage artifact, value, writer, reader, derivation or validation rule, and
  rebuild/deletion contract.
- REQ-4: The catalog vocabulary must be extensible to unimplemented claim
  substrates and auxiliary sources without declaring them implemented. It must
  distinguish `implemented` from `planned`, and planned rows must name an
  existing design or SPEC section rather than an invented code path.
- REQ-5: `tests/surface_conformance.rs` must enumerate the implementation side
  independently of the catalog and fail when an implemented stored artifact,
  structured field, or SQLite column has no exact committed row. A test that
  only iterates catalog rows is insufficient.
- REQ-6: The implementation inventory must cover the current `.kan/log` CAR,
  log `HEAD` and `LOCK`, `.kan/overlay`, versioned SQLite schema and metadata,
  `.claims/`, workspace identity roots and pointers, role key files, legacy
  role configuration, and keychain entries named by kan-managed pointers.
- REQ-7: Every `derived` row must name a deterministic derivation from declared
  inputs. Currently persisted disposable projections—`.kan/index.sqlite` and
  `.kan/overlay`—must have executable conformance checks that delete or bypass
  them, recompute from authoritative inputs, and compare semantic outputs.
- REQ-8: `authoritative-kan` rows must be checked by their governing invariant,
  not by pretending all authority is reconstructible: signed claims verify by
  CID and signature; identity roots obey at-rest precedence and ownership;
  configuration parses under its declared scope. Replicated claim media must
  preserve the signed object even when their framing differs.
- REQ-9: `authoritative-other` inputs must be cataloged at their boundary into
  kan and remain attributable to their provider. Git anchors and ancestry may
  influence a projection, but their derived edges must not be stored as kan
  claims or silently reclassified as authoritative-kan.
- REQ-10: Conformance must run in the ordinary Rust test suite and remain
  hermetic: no network, hosted backend, live keychain, or developer-global
  configuration may be required. Planned media are schema-checked; only
  implemented media are behavior-checked.
- REQ-11: The catalog and SPEC must state the known limit of the recomputation
  oracle: if reference recomputation becomes too costly for CI, replacing it
  requires a new explicit oracle decision rather than weakening or skipping
  the check.

## Acceptance Criteria

- [ ] AC-1: `docs/SPEC.md` contains a read/write-surface section defining all
      three authority classes and explicitly states that authority, source,
      medium, and projection are independent axes. (REQ-1, REQ-2)
- [ ] AC-2: `tests/fixtures/read-write-surface.tsv` parses as a fixed-column TSV
      and contains no duplicate `(artifact, value)` keys, unknown enum values,
      empty writer/reader/rule fields, or `planned` row without an existing
      design/SPEC citation. (REQ-3, REQ-4)
- [ ] AC-3: A catalog fixture demonstrates the same signed claim authority
      across the local log, `.claims/`, replica, and atproto source kinds while
      marking the latter two planned; it separately represents repository
      config, system config, and an external Git input. (REQ-2, REQ-4, REQ-9)
- [ ] AC-4: Adding a SQLite column in `src/store/index.rs` without adding its
      exact catalog row makes `surface_conformance` fail with the missing table
      and column named. (REQ-3, REQ-5)
- [ ] AC-5: Adding a new kan-managed path constant or literal under `.kan/` or
      `.claims/` in the registered persistence modules without cataloging it
      makes `surface_conformance` fail with the source path and storage artifact
      named. (REQ-5, REQ-6)
- [ ] AC-6: The implementation inventory accounts for every current artifact
      listed by REQ-6, and the test fails if either the inventory or catalog has
      an unmatched implemented entry. (REQ-5, REQ-6)
- [ ] AC-7: A fixture workspace produces the same claim CIDs and folded JSON
      after deleting `.kan/index.sqlite` and reopening it; corrupting a
      projected SQLite claim row cannot change the recomputed result. (REQ-7)
- [ ] AC-8: A fixture with foreign signed records in `.claims/` produces the
      same semantic view before and after rebuilding `.kan/overlay`, proving
      the overlay is disposable while the authenticated published claims are
      retained. (REQ-7, REQ-8)
- [ ] AC-9: Existing CID/signature, GitTree round-trip, identity-at-rest, role
      registry, and Git-anchor tests are cited from catalog rules, and the
      conformance test verifies that every implemented non-derived row names a
      real rule identifier. (REQ-8, REQ-9)
- [ ] AC-10: `cargo test --test surface_conformance` passes without network or
      keychain access, and the test is discovered by the repository's normal
      `cargo test --workspace` CI path. (REQ-10)
- [ ] AC-11: The SPEC and fixture header state that reference recomputation is
      the current oracle and name excessive CI cost as the event requiring an
      explicit replacement decision. (REQ-11)

## Architecture

### The model: authority is not location

The current `docs/SPEC.md` §10 sentence “one source of truth” is directionally
right about rejecting SQLite as authority, but too singular for the medium
model already established in `.design/medium-architecture.md`. Each signed
claim is authoritative kan data wherever it is validly carried. The local
`.kan/log`, tracked `.claims/`, a replica, and an atproto repository are
distinct claim substrates with different availability and ownership; none
becomes a derived summary merely because another copy exists.

The catalog therefore uses these authority classes:

- `authoritative-kan`: inputs whose semantics and validation rules kan owns.
  This includes signed claims on any claim substrate, repository-scoped kan
  configuration, machine-scoped kan configuration, identity roots, and the
  pointers which select them.
- `authoritative-other`: inputs kan may consult but does not own, such as Git
  commits, ancestry, blobs, and filesystem facts. The provider remains named
  so a computed edge cannot masquerade as an attested claim.
- `derived`: values deterministically computed from declared authoritative
  inputs, including SQLite rows, overlay contents, folds, caches, and rendered
  JSON. A derived value may be persisted for performance but is never evidence
  for itself.

`source_kind` is separate. Its initial vocabulary is `local-log`, `git-tree`,
`replica`, `atproto`, `repo-config`, `system-config`, `identity-store`,
`external-git`, `overlay`, and `sqlite-index`. `scope` distinguishes `claim`,
`repository`, `system`, and `invocation`. Future additions extend these enums
in the parser and fixture together.

### Catalog shape

`tests/fixtures/read-write-surface.tsv` follows the committed-decision style of
`tests/fixtures/migration-expectations.tsv`, but its rows are declarations
rather than measurements. Ignoring comment lines, its columns are:

```text
status  authority_class  source_kind  scope  artifact  value  writer  reader  rule  lifecycle  design
```

`artifact` is a stable logical name such as `local-log:repo.car` or
`sqlite/claims_v1`; it is not an absolute path. `value` is `*` only for an
opaque container whose format already has an independent conformance oracle;
structured formats use one row per persisted field or column. `writer` and
`reader` name Rust module paths or `external` for an outside provider. `rule`
is either `derive:<function>`, `validate:<rule-id>`, or `select:<rule-id>`.
`lifecycle` states whether deletion is forbidden, reconstructible, or merely
loses an optional connection. `design` points to an existing file and section
for planned rows and may point to `docs/SPEC.md` for implemented ones.

The fixture includes planned `replica` and `atproto` rows so the schema proves
it can represent them, but `status=planned` excludes them from behavioral
coverage. A planned row cannot satisfy an implemented inventory entry.

### Independent implementation inventory

Exhaustiveness cannot come from asking the catalog what exists. The test will
build a second set from implementation-owned declarations and compare the two
sets in both directions.

For SQLite, `tests/surface_conformance.rs` opens an index and uses SQLite
schema introspection to enumerate tables, metadata keys, and columns created by
`src/store/index.rs`. This is field-level and catches an added computed column
without a row.

For filesystem/keychain artifacts, persistence-owning modules expose small
declarative inventories alongside their existing path constants:

- `src/store/log.rs`: `repo.car`, `HEAD`, and `LOCK`;
- `src/store/index.rs`: `index.sqlite` and its versioned schema;
- `src/transport/git_tree.rs`: `.claims/` framing and paths;
- `src/sign.rs`: seed/key files, pointer files, legacy role configuration,
  role keys, and the keychain services those pointers name;
- `src/workspace.rs`: `.kan/overlay` and assembly of the repository surface.

The inventory records only stable identifiers and storage shape, not the
catalog's authority judgment. This separation is deliberate: adding a path to
the implementation and copying an authority label from the same declaration
would let code approve its own classification. The catalog supplies the
judgment; the code supplies the facts that something is persisted.

Literal scanning alone is not the oracle—aliases and constructed paths make it
unsound, as GitHub issue #194 already records. A lightweight source scan may
guard that every persistence module participates, but exact coverage comes
from module-owned inventories plus runtime schema inspection.

### Behavioral conformance

Derived stores get executable recomputation oracles:

- `Index`: build a view, delete `.kan/index.sqlite`, reopen the workspace, and
  compare semantic claim CIDs and folded JSON. The test also poisons a derived
  row and proves authoritative recomputation wins.
- `Overlay`: ingest foreign signed `.claims/`, record the semantic view, remove
  `.kan/overlay`, invoke the existing rebuild path in `src/workspace.rs`, and
  compare the view and provenance.

The comparison is semantic, not byte-for-byte: SQLite layout and CAR block
order are implementation details, while claim CIDs, authorship, citations,
medium provenance, and fold output are the contract.

Authoritative values use the invariant appropriate to their kind. Claim
substrates cite existing CID/signature and GitTree conformance tests; identity
and configuration rows cite selection/precedence and ownership rules from
`src/sign.rs` and `src/roles.rs`; authoritative-other Git rows cite anchor and
ancestry tests. `surface_conformance` validates that every rule identifier used
by an implemented row exists in a committed registry, while the focused tests
continue to execute the behavior.

### Specification and CI

`docs/SPEC.md` gains the conceptual model, the catalog schema, and a table of
current source kinds. `tests/surface_conformance.rs` is an ordinary integration
test, so `.github/workflows/ci.yml` needs no special gate: omission from the
normal workspace suite would itself be visible as the test target disappearing.

The recomputation oracle is correctness-first and intentionally pays the full
reference cost on a small fixture. If that becomes too expensive even there,
the check must not be marked slow, ignored, or changed to trust the cache. That
event requires a recorded decision defining a new independent oracle, preserving
the tension documented on
`tension/performance-at-scale--raw-data-and-projections`.

## Resolved Questions

- RQ-1: The surface includes all kan-managed durable state, not only claim-bearing
  stores. Claim substrates, repository configuration, system configuration,
  identity material and selectors, and projections all belong in the model;
  auxiliary external inputs are declared at their boundary into kan.
- RQ-2: Authority uses three semantic classes: `authoritative-kan`,
  `authoritative-other`, and `derived`. Storage media and connection types are
  separate axes, so multiple authoritative claim substrates do not become one
  physical “source of truth.”
- RQ-3: Structured storage is cataloged at field or column granularity; opaque
  containers are cataloged at artifact granularity when an independent format
  oracle already exists.
- RQ-4: Executable recomputation is required for disposable persisted projections.
  Authoritative and external rows instead carry the validation, selection, or
  attribution invariant appropriate to their kind.

## Open Questions

None.

## Out of Scope

- Implementing repository or system configuration commands and file formats;
  this design specifies their place in the model before those sources exist.
- Implementing replica, archive, HostedRelay, atproto, PDS, firehose, or
  appview connections.
- Retiring `.kan/overlay` under GitHub issue #164.
- Adding incremental folds or persisted fold caches under GitHub issues #25,
  #151, #165, or #202.
- Changing claim encoding, CIDs, signatures, GitTree framing, or identity
  at-rest behavior.
- Replacing focused behavioral tests with one monolithic conformance test; the
  new test binds declarations to those executable rules rather than absorbing
  every invariant into one file.
- Solving day's maintenance-telos limitation tracked as day#171.
