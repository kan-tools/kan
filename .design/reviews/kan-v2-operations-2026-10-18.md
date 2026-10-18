# Initial operations review — 2026-10-18

Author-maintained summary; the adjacent `.txt` retains the exact independent
report. Frozen reviewed range: 2bbac8b5f9c4b9e101620ac5b53301030989132b through
d55f82128e37b474ce7d22f6c96b04b116711cbb. Actual Claude initialization identified
model `claude-opus-5-5`, session `a489c2e8-3aea-4192-ab26-2f4840d675ea`.
The reviewer returned **BLOCK**. The author began corrections while the reviewer
finished its frozen export; those edits were by this author, not an unrelated
actor, and were correctly excluded from the reviewed range.

The blocking findings were a full journal preventing capture-proxy restart and
brief journal contention terminating the archive worker. The review also found
missing tests for per-peer admission and multiple operational/access-control
invariants, plus a useful limitation: bounded FIFO handoff can lose the latest
cumulative summary under a burst even when the disk is healthy. Lost telemetry
is counted, so this is incomplete coverage rather than a completeness claim.

Independent baseline checks: gateway 17 passed / one ignored; operations four;
operations unit one; surface 19; Node three; all-target encrypted Clippy, format
and citations passed. The initial push CI passed. The reviewer performed eight
hostile probes and a mutation sweep; exact survivors, failures, timeout and
pattern-matching qualifications remain in the retained raw report and logs.
The blocking-send mutant timed out, which was not counted as a runtime kill.

Proposed disposition requires another fresh review. Startup journal I/O moves
behind the nonblocking reporter boundary, full session admission is best effort,
and delivery counts/retries failed telemetry writes without ending raw delivery.
The dashboard makes absent/stale capture reporters explicitly unknown. Added
regressions cover capacity, missing spool, real CLI startup with missing journal,
locking, backoff, backlog age and access controls. Different-source pending tests
run in Linux CI; macOS cannot bind arbitrary 127/8 aliases without host changes.
IPv6 /64 and mapped IPv4 normalization have dedicated unit controls.

The 32-MiB page limit and 100,000-attempt count are independent ceilings, not a
capacity guarantee; the realistic reviewer fixture reached the byte cap near
79,740 attempts. FIFO coalescing remains an explicitly named follow-up. The
operator UI is now also named in CLAUDE.md as the user's v2 exception. No live
kan/day claims were written under the known partial-trust limitation.
