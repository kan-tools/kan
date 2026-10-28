# Design schema validation, 2026-10-19

Actual `day design check` results are preserved unchanged with exit status.
Worktree-local invocation refuses shared-workspace discovery (day#168/kan#197),
so these read-only checks run from the primary checkout against absolute worktree
document paths. That lets the live schema validate the documents but resolves
relative references against the older primary checkout: v2 path warnings are
expected and are not evidence that those files are absent in this branch.
All referenced v2 source/test/parent-design files were separately checked here.
`docs/SPEC.md` is the common provenance grounding that exists in both checkouts.

Inventory: 6 requirements / 6 criteria; recovery bundles: 8 / 6;
conversation reconstruction: 8 / 8. All three schema checks exit 0 with the
preserved path warnings and the existing two-withheld-claim warning. This is
schema validation, not implementation or independent-review acceptance.

Git-first recording continues. Phases 5–7 that require reliable worktree log
context are not performed; no semantic log is modified, missing claims are not
recreated, and no maintenance witnesses or bridge success are invented.
The existing target remains telos/raw-data-and-projections.
