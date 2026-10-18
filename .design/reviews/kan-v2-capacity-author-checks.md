# Capacity / retained-generation author checks

Production slice is based on a04f288 (reliability correction plus independent
review record). The production source is permanent in kan-v2-journal-capacity.

Passed: 9 health units; 19 existing operations integrations; 8 collection tests;
19 surface conformance tests; strict v2 all-target Clippy; format; 16 Node tests;
5 Python reversion-runner tests. An additional integration test then passed for
session-exhaustion disclosure without refusal of reporter startup (20th target
case). Initial sandbox networking refusals were rerun with loopback permitted;
the interrupted test left no orphan. The initial empty-string Clippy error was
fixed and the lint rerun passed. Private per-worktree COW targets avoid stale
cross-worktree Cargo package reuse; no Mathlib or global build cache was created.

The retained bundled-day whole-production reversion failed the named session-
exhaustion assertion and passed after restoration. It demonstrates that boundary,
not the entire new collection protocol. Collection fault tests cover all five
publication boundaries, source hash preservation, active writer refusal, malformed
manifests, corruption, symlinks, permissions, hardlinks and malformed lock files.
The logical attempt-count guard uses compact white-box seeded rows so that the
physical page ceiling does not mask the separate row-count condition.

Actual client browser checks used production assets with a synthetic fixture API;
see capacity-browser/README.md and screenshots. They are separate from the Rust
HTTP/security integration test. The temporary server and tab were stopped.

Full collection-wide deduplicated overview, real reader/Library, annotation/view,
analysis and admin workflows remain open. Reader planning does not count as API
implementation. No main merge, live migration, deployment, production key use or
provider calls occurred. Fresh independent Opus review is the next checkpoint.
