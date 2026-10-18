# Fresh adversarial review: kan-v2 admission-audit correction

Reviewer: fresh Claude Code claude-opus-5-5 agent. I did not write this code. No delegation, and no kan/day writes, so skill Steps 7–8 were not performed.
Range: `git diff HEAD` against the synthetic baseline commit 9c41cb5 (actual baseline 771341e; production a885565).
North star: telos/raw-data-and-projections, as recorded in review-context.txt. It is deliberately unwitnessed. Two main-log claims were withheld. I did not read the empty local export as "no teloi".

**Verdict: APPROVE WITH FOLLOW-UPS**

## Runs (all on the restored tree, freshly rebuilt)
- Operations units: 13/13. Operations integration: 22/22. Collection: 9/9. Surface: 19/19.
- Node: 16 operations UI + 4 theme = 20/20. Python runner: 7/7.
- `cargo fmt --check` passes. Clippy `-D warnings --all-targets` passes with both default and v2-crypto features.
- Whole-production reversion replay with the bundled day engine (`11-reversion.txt`, `reversion-logs/`):
  - Five named tests failed under revert and passed before and after: bounded_pipe_cleanup (watchdog assertion), WAL refusal (:335), session continuity (:962 reserve), sealed byte-stability (:985) and session→attempt escalation (:1005).
  - Every failure was an assertion. There were no compile failures or timeouts.
- The retained production.patch equals the current diff (559/559 changed lines).

## Mutants (each restored by SHA, with a fresh mtime; logs in `mutants/`)
- Killed at an assertion: R01, R03, R05, R07, R08, R09, R13, R14, R15, R16, R17, R18, R19, R20, R21, R22, P01, P03, P06, U01, U02, U04, U05, U06, U07, U09.
- Killed by a panic on an `unwrap` of a semantic open refusal (not a compile failure): R11, R12.
- Survived:
  - R02: the production `offer_pending` call site bypasses the observed helper with a single try_lock. Passes 13 units and 22 integrations.
  - R04: the production `reserve_attempt` becomes a single weak CAS. Same.
  - R06/R06b: the idempotency guard is disabled. Passes the whole suite.
    - Only the reviewer probe kills it (R06c), by showing an earlier `attempt_limit` reason overwritten by a later `sqlite_full`.
    - Session refusals stay byte-stable under R06 because SQLite skips identical cell overwrites.
  - R10: the sealed filter is removed. The guard masks it, and R20 (both removed) is killed.
  - P02: pipe close removed. This is fd hygiene only; boundedness does not depend on it.
  - P04 and P05: equivalent in practice, because the exit-status agreement check already rejects ERROR.
  - P07: any module prefix accepted. P08: unknown Python alias accepted (it still fails later with a KeyError).
  - U03: attempt threshold 0.99. The test sits exactly at 99,000.
  - U08: polling steals focus from an open modal. The mock never clears `focused`, and no test checks activeElement.

## Probes (`zz_review_probe.rs`, temporary in tests/, now removed; `09-`, `10-`)
- An older v2 journal with a session_limit marker and reserve 0 accepts new attempt writes (`record=Ok`). The new binary re-opens what the old binary sealed.
- Repeated session refusals are byte-stable.
- A session-limited journal, then a real SQLite page ceiling: escalates to sqlite_full, reserve 0, and further refusals are byte-stable.
- Header bytes 1,2 / 2,1 / 2,2 / 0,1 and a 16-byte file are refused with no sidecar created and the bytes unchanged.

## Isolation note
At 14:19:19 an external process rewrote the staged `.design/reviews/kan-v2-admission-audit-reversion/08-evidence_operations.txt` in the worktree, replacing it with a stub and a `.gz`. I did not do it.
- The `.gz` decompresses to the staged blob's SHA (2cacc62d…), so the change is lossless.
- The index still holds the 133 MB blob.
- Production sources were unchanged throughout, verified by SHA.

## Not run
- Device ENOSPC, power loss, a crash harness, same-owner path/symlink swap races and multi-process lock races.
- Old binaries running against the new journals.
- A real browser, screen reader or contrast check.
- The full workspace test suite, Linux-only scripts and the full frontend / dedup overview.
- Any live service or data.
