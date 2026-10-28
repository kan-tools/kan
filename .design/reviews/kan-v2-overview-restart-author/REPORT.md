# Overview restart render correction

The ongoing independent Opus review of 7ab1afa found UPb: service restart can
reuse job1 with an unchanged manifest. A new sample then updated the age label
but left the prior totals/source list because the browser keyed rendering only
by job and manifest. This author correction keys the complete immutable sample.

27 Operations UI tests pass. Reverting the entire production behavior change
restores the old key and fails the new named restart assertion; restored tests
pass again. The test also checks sample-time replacement with identical rows and
that an identical cached sample does not rewrite totals. No Rust/runtime schema
changed. The original reviewer probe/report will be preserved unchanged when the
review finishes; fresh review of this correction remains required.

The ongoing cold review's nine independent UI probes are now incorporated as
`tests/operations_review_ui.test.cjs` and included in CI. Their fetch harness
honors AbortSignal, so aborted polls actually execute catch/finally paths.
The review export remains unchanged; its original restart failure is preserved.
These author-run incorporated probes do not constitute a fresh review verdict.

All 36 author and incorporated UI checks pass. Three independent-harness
negative controls (restart cache collision, aborted-poll finally race,
aborted-poll error repaint) fail assertions and the restored 36 checks pass.
Raw outputs are under `abort-controls/`; the repeatable driver is
`scripts/operations_review_negative_controls.py`. This is author qualification,
not the pending fresh independent correction verdict.
