# Remaining overview and contention regressions

Author qualification of 219b6af and 2c8ba2a on 2026-10-19; no production behavior
changed by these commits. This is not an independent review verdict.

34 targeted Rust checks passed: two projection unit checks, one snapshot-window
unit check, eleven overview regression checks, nineteen surface checks, and one
contention-wrapper return-fidelity check. Strict all-target v2 Clippy and format
passed. The complete five-file UI CI command passed all 83 Node tests.

Five compiled mutants fail named assertions: omit the post-open copy deadline;
omit copied-state schema/reserve validation; use the parsing window instead of
the copy window; label invalid data busy; discard the wait returned to the
caller while still reporting it on the diagnostic channel. The driver restores
all source files even on failure, then the affected restored suites pass. Raw
logs are preserved here and the repeatable driver is
`scripts/overview_review_negative_controls.py`.

This addresses combined-review A-F3's backend test seams and the prior Library
scope review's wrapper-return gap. The production overview fix already has a
separate fresh Opus approval; these new regression additions will be included in
the next fresh checkpoint review. SourceBusy under sustained writes and the
practical identity-capacity limit remain disclosed, not claimed fixed.

The subsequent real restart browser check is recorded separately in
`../kan-v2-overview-restart-browser/`; actual Library download delivery remains
unverified. No production data, service installation or live cutover occurred.
