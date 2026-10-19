# Unicode SQLite-family correction: author evidence

Fresh Opus correction review 423054a was APPROVE WITH FOLLOW-UPS; its complete
report, including demonstrated F-A, is preserved unchanged under
`../kan-v2-copy-followups-opus/`. F2-F7 are independently closed. F-A remains a
required custody correction despite that nonblocking verdict.

Production change: compare every source/destination SQLite family path using
actual filesystem identity in addition to conservative Unicode case expansions;
recognize reserved sidecar suffixes with the same rule. Existing aliases cannot
hide behind unrelated hard-link names. Currently absent long-s sidecars are
refused before a plan is created. This does not emulate every filesystem's
collation or fence hostile path races. No new durable surface is introduced.
The path-expression inventory changes from a byte-slice expression to `base`.

Executed evidence: 112 functions pass across destination (32), source (10), legacy
store (34), lifecycle (11), recovery CLI (6), surface (19), including existing
subprocess-helper functions. Strict v2-crypto all-target Clippy and fmt pass.
Full production reversion via the day reversion engine and scripts/revert_v2.py
reverts all 4 src/evidence_store.rs hunks: all four new named tests fail under
reversion and pass on baseline/restoration. Exact raw logs and patch are retained.
Tests cover destination CLI resume with preserved recipe, fresh source read,
creation before a sidecar exists, and a sidecar hard-linked to an unrelated name.

The first test run passed storage/lifecycle tests but failed the independent
path-expression inventory because the new `base` expression was not registered.
That failed run is retained; the inventory was updated explicitly and the entire
qualification rerun passed. No failed compile/runner is counted as a regression.

F-C cost disclosure now distinguishes CLI source re-audit from reuse of a pinned
source in the API, and names the repeated whole-prefix comparisons and their
O(n² / batch-size) total-copy cost. Prior reports remain unmodified.

Synthetic fixtures only; reused shared target, four Cargo jobs, no production
keys/archive use, activation, installation, server or merge. The new correction
requires a fresh independent review and closes no full-roadmap acceptance.
