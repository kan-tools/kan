# Author correction evidence

Follow-ups to the actual Opus review of e71cdf8, not an independent verdict.
The only UI production correction clears stale partial styling after a failed
catalog retry. The reversion adapter names its exact regression. Documentation
now distinguishes response-body privacy from timing leakage. Other Rust changes
are tests only, including the production-helper test module.

Five formerly surviving mutations now compile and fail named assertions: R03
verified-denial classification, R08 failure-count disclosure, R12 timeout-as-denial,
R24 queue-inclusive whole deadline and R31 live thirteenth-socket refusal. R31's
failure is the test's explicit admission assertion after two seconds, not an
external runner timeout. All mutated source was byte-restored; kan was cleaned
and rebuilt before the restored checks.

Restored budget 3/3, reader 18/18 plus one ignored manual fixture, contention6/6,
Node41/41, Python7/7, strict v2 all-target Clippy and fmt pass. A final test-helper
stop check was then verified by its P4 case (87/87 observations queued). CI's
original failure is retained: the synthetic writer panicked on DatabaseBusy at
BEGIN IMMEDIATE. The helper now skips busy/locked acquisition windows, refuses
unexpected errors, checks stop after sleeping, and still requires held windows
and complete observed/queued equality. Production capture is unchanged.

Whole-production reversion of this correction passes before/after and fails the
named Node assertion under reversion. The adapter classifies the Rust additions
as test-side; it reverts all changed tracked production and docs, not a selected
convenient hunk. Exact logs and generated trailer are retained.

Remaining: fresh correction review; CI on the new commit; tighter +1s upstream
and body bound assertions; client scope-entry shape validation; actual browser
file delivery. This record does not complete the broader frontend roadmap.
