# Health reliability review disposition

Author-maintained disposition; adjacent `.txt` is the exact independent report.
Reviewed production fcd8c6f, parent 833bef3. Actual fresh Claude Code initialized
`claude-opus-5-5`, session `55eb329f-7079-4bf1-959c-7bc3cbc2df2f`. Verdict:
APPROVE WITH FOLLOW-UPS. Report SHA-256:
`4d45456f8078af06a007f02cbabab5ae3e44cb03a6109fe472d4c8e60107cbee`.

The reviewer independently passed focused build/tests/lint/format, reproduced the
whole-production regression and restored behavior, and qualified 30 synchronized
runs (10 under CPU oversubscription) at 80/80 terminals with zero counted losses.
Its 45 tight-loop probes had worst cases 79/80 and 95/96 terminals, with all losses
disclosed. Held-lock accounting and capacity mutations were killed deterministically.
The single-retry mutant survived; sharding alone satisfied the deliberately loose
workload threshold. That test is not evidence for the retry mechanism itself.

A new correction addresses deterministic transient-contention retry evidence,
process-group timeout cleanup, untracked-file disclosure, clearer export/cache
isolation wording, export/timeout regression tests, and the broader “health
telemetry loss observations” unit (session registration and dead-writer wake
failures also contribute). The remaining allocation-under-lock observation is
small fixed-size work, not a claim of hard realtime behavior. The record barrier
is record-specific in this implementation; future writer transactions must keep
that distinction. These corrections require their own fresh review.

Linux CI at fcd8c6f passed runtime suites but failed strict lint because the newer
compiler deprecated AtomicUsize::fetch_update. The correction uses an explicitly
bounded compare-exchange loop, retaining the 1.95 MSRV and finite admission work.
This compiler compatibility failure is distinct from runtime reversion evidence;
no failed compilation is represented as a semantic mutation kill. Migration and
the prior #282 performance job are green. The owned reviewer target was removed
after exit; source and raw probes remain in the permanent review export.

Capacity/rotation and the real reader/full frontend remain separate build slices.
Legacy kan/day backfill is pending under the known two-withheld-claim limitation.
No main merge, live data migration, installation or production key use occurred.

Correction author checks: six operations units, the synchronized integration test
(80/80 terminals, zero counted losses), Node 12/12, Python runner 5/5, and local
strict Clippy/format passed. The retained correction reversion demonstrates only
the UI telemetry-unit wording; it does not establish atomic-loop or process-cleanup
semantics. Those have focused tests and await fresh independent review and CI.
