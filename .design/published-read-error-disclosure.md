# Feature: Disclose published-record read errors in structured output

## Summary

Make every JSON read envelope say when the tracked `.claims/` projection was
only partially readable. A degraded read remains nonfatal and continues to
return every verified claim, while structured repository-relative diagnostics
let a machine consumer distinguish that partial view from a complete one.

Serves `telos/raw-data-and-projections`: the rendered view must disclose when
its raw published inputs were refused, rather than presenting the projection
as complete. This closes kan#211, the publication-layer analogue of ADR-57's
trust-exclusion disclosure.

## Requirements

- REQ-1: `Workspace::open_read_only` in `src/workspace.rs` retains every
  `git_tree::Error` returned while reading `.claims/`, instead of preserving it
  only as a stderr line before discarding it.
- REQ-2: The errors retained by REQ-1 are read metadata, not claims: they do
  not enter the append-only log, overlay, SQLite index, or fold, and therefore
  cannot alter the verified claims in the returned view.
- REQ-3: `ShowJson`, `ShowAllJson`, `StatusJson`, `IssuesJson`, and
  `ContextJson` in `src/json.rs` always emit `published_read_error_count` and
  `published_read_errors`. A clean read emits `0` and `[]`; neither field is
  omitted.
- REQ-4: Each `published_read_errors` entry has the stable fields `path`,
  `kind`, and `message`. `kind` is a kan-owned machine-readable string derived
  from the concrete `transport::git_tree::Error` variant, while `message`
  retains the diagnostic detail intended for a person.
- REQ-5: Diagnostic paths are relative to the repository root and begin with
  `.claims/`. JSON never exposes an absolute checkout path, and two clones
  containing the same malformed tree produce the same path value.
- REQ-6: A malformed or unverifiable published record remains nonfatal: the
  command exits successfully, returns every verified claim, and reports the
  refused input through REQ-3 and REQ-4. Existing human-readable stderr
  warnings remain.
- REQ-7: The disclosure is attached to the top-level envelope for the entire
  `Workspace::open_read_only` operation. `show --all` does not duplicate the
  same workspace diagnostics inside each nested `ShowJson` entry.
- REQ-8: The structured-output schema remains version 1 because both fields
  are additive. `tests/json_contract.rs` pins their presence and the exact
  diagnostic-entry shape.
- REQ-9: Error ordering is deterministic, following `GitTree::read_records`'
  sorted file traversal and record order, so consumers and golden tests do not
  see clone-local or filesystem-order noise.

## Acceptance Criteria

- [ ] AC-1: A binary-level test corrupts one published record, runs `kan show
  <subject> --json`, and asserts exit status 0, all remaining verified claims
  present, `published_read_error_count == 1`, and one structured diagnostic.
  (REQ-1, REQ-2, REQ-6)
- [ ] AC-2: The AC-1 diagnostic has exactly `path`, `kind`, and `message`; its
  path begins `.claims/`, is not absolute, and its kind identifies a malformed
  record without parsing `message`. (REQ-4, REQ-5)
- [ ] AC-3: Clean `show`, `show --all`, `status`, `issues`, and `context` JSON
  payloads each contain `published_read_error_count: 0` and
  `published_read_errors: []`. (REQ-3)
- [ ] AC-4: A test invokes each JSON read surface against the same malformed
  published tree and asserts each top-level envelope reports the same
  diagnostic. (REQ-3, REQ-7)
- [ ] AC-5: `show --all --json` contains the diagnostic fields once at the
  outer envelope and does not repeat them inside entries under `subjects`.
  (REQ-7)
- [ ] AC-6: Two temporary repositories containing byte-identical malformed
  `.claims/` trees produce identical `path`, `kind`, and `message` values.
  (REQ-5, REQ-9)
- [ ] AC-7: A human read of the AC-1 fixture still prints the existing
  `warning: skipping a published record` line to stderr. (REQ-6)
- [ ] AC-8: `tests/json_contract.rs` pins both new top-level fields on all five
  read envelopes, pins diagnostic entries to `path`, `kind`, and `message`,
  and continues to pin `SCHEMA_VERSION == 1`. (REQ-4, REQ-8)
- [ ] AC-9: A test with two malformed records in distinct files asserts the
  count is 2 and the diagnostic array is ordered by repository-relative path.
  (REQ-9)

## Architecture

The information is currently lost in `read_published` at
`src/workspace.rs:1006`: `GitTree::read_all_with_rev()` yields a
`Result` for each record, the `Err` arm writes it to stderr, and the function
returns only `(PublishedIndex, arrived claims)`. By the time `actions::show_json`
or another JSON renderer runs, no structured representation of the rejected
input remains.

Add a workspace-level collection such as `published_read_errors` beside
`Workspace::published`. `read_published` returns that collection with its
existing products, and `Workspace::open_read_only` carries it without writing
it anywhere. This is invocation metadata about the source material used to
build a projection; storing it as a claim or index row would turn a derived
diagnostic into authoritative data and violate `telos/raw-data-and-projections`.

The structured diagnostic should be a small kan-owned type rather than a
serialized `git_tree::Error`. The latter contains `std::io::Error`, CIDs, and
variant-specific fields whose Rust representation is not the JSON contract.
The conversion matches every current error variant to a stable snake-case
`kind`, renders the existing error as `message`, and strips `Workspace::root`
from its path before serialization. Keeping the exhaustive conversion close
to `src/transport/git_tree.rs::Error` makes a new error variant a compile-time
prompt to define its public diagnostic category.

The top-level envelope owns the disclosure because the degradation happens
once while opening the workspace, before any fold or subject selection. The
constructors in `src/actions.rs` copy the same count and slice into `ShowJson`,
`ShowAllJson`, `StatusJson`, `IssuesJson`, and `ContextJson`. For bulk show, the
outer `ShowAllJson` carries it once; nested `ShowJson` entries represent subject
views and do not each pretend the workspace was opened again.

`published_read_error_count` counts diagnostic events returned by GitTree, not
an inferred number of lost claims. That distinction matters: an I/O error may
make a whole file unreadable, while `RecordsMissing` can report several absent
records in one event. The array length and count agree exactly; neither claims
knowledge kan does not have.

The human warning remains in the same error arm. JSON stdout gains disclosure
without redirecting or embedding stderr, and successful partial reads retain
exit status 0. This preserves the availability decision already documented in
`src/workspace.rs`: one bad tracked record must not deny access to every valid
claim.

No fold code changes. No claim is accepted without CID and signature
verification. No operation destroys a subject, and the private log remains
append-only.

## Open Questions

None remaining.

## Resolved Questions

- **Every JSON read envelope discloses degradation.** Publication errors arise
  during workspace opening, so limiting disclosure to `show` would make the
  same workspace appear complete under `status`, `issues`, or `context`.
- **Diagnostics are structured and counted.** A count establishes completeness
  cheaply; `path`, `kind`, and `message` let consumers classify and operators
  diagnose without scraping one prose field for both jobs.
- **Paths are repository-relative.** Absolute checkout paths are unstable
  across clones and unnecessarily expose local filesystem structure.
- **Partial reads remain successful.** Verified claims remain available, while
  mandatory nonempty diagnostics make the partial result unmistakable.
- **The count measures error events.** kan cannot honestly infer how many
  records an unreadable file contained, so the public field does not claim to.

## Out of Scope

- Repairing, rewriting, or deleting malformed `.claims/` records.
- Making a degraded read fatal or introducing a strict-read mode.
- Changing v3 framing or the nested per-author publication layout.
- Trust selection and the everyone-in-tree selector tracked by kan#212.
- Citation graph queries tracked by kan#210.
- Adding diagnostics to non-JSON prose beyond the warning already emitted.
- Changing MCP response schemas; this slice pins kan's versioned JSON read
  contract used by subprocess consumers.
