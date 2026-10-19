# Session assembly author qualification

Thirty integration tests (13 assembly, 15 decoder, two decoder review regressions)
and one deterministic mid-decode cancellation unit pass. Strict all-target v2
Clippy and formatting pass. Initial formatting failure is retained.

Eight selected compiled controls demonstrate scope/writer/observer/attempt
isolation, ordinal conflict handling, gap refusal, assembled-byte budget and
complete duplicate lineage. Restored 13-test assembly suite passes. The first
control run incorrectly required the literal word assertion: the budget mutant
correctly failed unwrap_err on an unexpected successful Assembly. That complete
failed run is retained; the harness now recognizes this exact semantic failure
for that control. No production code changed to satisfy the harness.

Initial PR CI had 20 successful checks and one context scaling failure (ratio
8.4 against bound 8). The default-feature measured binary excludes the new
v2-crypto module; Cargo manifests/lock and performance paths are unchanged.
The raw failure and successful attempt-2 rerun are both retained. The same source
passed with context/claims ratio 6.8 against unchanged bound 8 (job118211863917).
This resolves the requested rerun; it does not erase or explain the first result.

Day validation refuses the worktree with exit 2 under day#168/kan#197, not a
passing check. No main-workspace log write occurred. Fresh actual Opus review
remains required. No session API, provider adapter or frontend integration is
claimed, and no parent frontend acceptance criterion closes here.
