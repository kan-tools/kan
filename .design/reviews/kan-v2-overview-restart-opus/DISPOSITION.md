# Author disposition

Fresh actual Claude Code Opus 5.5 approved the restart production correction at
7126848 with follow-ups. The unmodified report and command/mutation evidence are
under `evidence/`. No new production UI change follows that reviewed commit.

F1-F3: the review's12 probes are incorporated as an exact prefix of
`tests/operations_restart_review.test.cjs`, covering partial-key mutations,
lock/relogin same-sample rendering, null reset, timeout, queued-session leaks,
streaming-body abort and bounds. Author RP13 adds a deterministic named assertion
for a queued action that otherwise repeats forever. CI includes this file.
49 operations checks pass. Eleven UI mutations fail named assertions and all49
checks pass after restoration; evidence is under `followup/`.

F4: the mutation driver now sets a60-second process-group timeout. A timeout
raises and cannot count as a demonstrated assertion. A synthetic child/grandchild
heartbeat probe verifies group shutdown; its files are removed. RP13 catches the
non-clearing-queue mutant with an assertion, not a hanging process.

F5: `import-provenance.json` identifies the original preserved UPa-UPi commit/path
and exact SHA-256 equality, plus the original RP1-RP12 prefix. The original review
was accurately unable to establish UP provenance from its supplied export.
Future review exports supply full range diffs excluding only separately preserved
raw review artifacts, explicitly named as such. Both original process findings
remain in the unmodified report.

These are author follow-up qualifications. The fresh verdict covers the production
fix and original regressions, not a later broad roadmap or browser claim. The
real browser state matrix predates the restart correction. Actual file download
qualification remains open.
