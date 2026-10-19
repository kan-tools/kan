# Historical Content author evidence

Current interpretation of this directory: `attempt-3` records the initial provider-v1 integration (72 integrations, seven units, 34 UI checks); `provider-v2-integration` records the subsequent provider-v2 consumer (74 integrations, seven units, 35 UI checks). `browser-observations.md` records the later real-browser work and its limits. The old narrative below describes earlier points in that sequence and is not the current acceptance state.

The six backend control logs include provider-v2 consumer tests, but their driver did not retain an immutable source manifest. They therefore cannot establish an exact frozen-commit qualification solely from line numbers or commit placement. They precede the test-only browser-control insertion that shifted test lines. The baseline's independent review re-executes controls against frozen bb1e0ab bytes; its complete record will be retained separately. Neither those historical logs nor this explanatory correction are independent acceptance of the new follow-up implementation.

## Original checkpoint narrative (retained)

# Content draft author evidence

This draft consumes the provider candidate 0d04848, whose independent review is in progress. The Content integration is not yet accepted.

34 Library UI tests pass, including exact-coordinate and opaque signed-pin handling, source-return navigation, hostile text, unknown data, revoked access, lock and late responses. Five selected UI mutations fail assertions, with restored tests passing. Raw intermediate test/formatting results are retained. The latest subsequent UI change adds occurrence-lineage navigation; its 34 tests pass in ui-content-attempt-3.

Rust qualification, backend semantic controls, actual browser validation, fresh integration review and CI remain pending. day design check returns exit 2 for the known worktree lookup refusal, not a passing check; no main log mutation. No deployed service, live key or live archive was used.

Initial Rust build succeeded; attempt 1 could not bind synthetic loopback listeners in the sandbox. Attempt 2 reached the assertions and exposed the old expected capability list. After adding the new Content capability to that expectation, attempt 3 passes 72 integrations, four Content units, three Library admission units, strict all-target v2 Clippy/fmt, and 34 UI checks. This qualifies the draft against provider 0d04848, not the provider's forthcoming version 2 follow-through. Browser and independent integration review remain pending.
