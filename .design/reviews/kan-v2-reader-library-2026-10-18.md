# Library review disposition

Fresh actual Claude Code `claude-opus-5-5`, session
fed454df-1783-4b5c-a35e-fa1a1080f139. Verdict **APPROVE WITH FOLLOW-UPS**.
Reviewed production df74506 against baseline 9d300b4. Exact report is retained
verbatim alongside this file. All 82 src/web file hashes match both the
frozen export and `git show df74506:<path>` after review; the hash manifest is
retained in `kan-v2-reader-library-probes/production-hashes.json`.
The export had a synthetic baseline commit, so the reviewer correctly qualified
commit identity; the post-review Git-object comparison supplies that missing link.

The first session 465f5b1b-1d57-4f9b-b08f-80bb4b3d4978 was interrupted before a
verdict and is not counted as review. Its transcript remains in local-state.
The restarted reviewer exited 0, restored production hashes, and reported no
remaining probe processes. Its owned build cache is removed after exit.

Independent checks: reader8 plus one ignored manual fixture, CLI1, surface19,
Node29, strict v2 all-target Clippy and formatting. Whole-production reversion
compiled and failed the named CLI assertion, then passed after restoration.
This proves the feature is exercised, not every validation branch. Mutation
survivors and the compile-failing M06 are retained exactly as reported.

Corrections are proceeding in separate commits: stale scope rows/continuation
(61e2487), recoverable source failures and directional-control display (22facfa),
then signature-failure catalog classification, principal separation, stronger
validation tests, connection queuing and the visible capability list. These
corrections require a new fresh review and are not covered by this verdict.

AC-3 remains unmet for per-occurrence missing/corrupt evidence. The service Page
contract can fail a whole page containing a damaged object, and physical absence
is reported as corruption. Runbook/design wording now names this limitation.
Browser download delivery, full browser-state qualification, external request
tracing, and the complete frontend remain open. No deployment or main merge.
