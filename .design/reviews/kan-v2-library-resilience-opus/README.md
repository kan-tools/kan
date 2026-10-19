# Independent Library resilience review

Actual Claude Code `claude-opus-5-5`, session
`8a79286d-effa-4dff-b736-e30cfa1b3b11`, reviewed e71cdf8 against 60f3d36.
The init identity is in `identity.json`; the exact returned text is `result.txt`
and the reviewer's longer report is `evidence/REPORT.md`. Verdict:
**APPROVE WITH FOLLOW-UPS**. This is not approval of later author corrections.

All 278 frozen source hashes match after the review. The reviewer restored and
cleanly rebuilt its source before reporting. Its completed 1.5 GiB target was
removed; raw logs, probes, mutant failures/survivors, and reversion evidence remain.
Initial invalid probe tokens and invalid Unicode substitutions are retained and
explicitly not counted as evidence. No review server remains.

## Disposition

- F1: response-time leakage is now documented in the design and runbook. The
  response-body contract still disallows failed-source identities/count fields.
- F2: added committed-test candidates for denial-only complete coverage, exact
  response key set, and timeout-only partial coverage. Author negative controls
  R03/R08/R12 compile and fail named assertions with these tests.
- F3: added queue-inclusive whole-deadline and actual thirteenth-socket refusal
  tests. Author R24/R31 compile and fail named assertions. The one-second upstream
  and body deadline mutations R11/R13 remain coverage gaps; do not infer exact
  upper-bound coverage from timing tests with wider scheduler tolerance.
- F4: real browser file delivery remains unverified. Desktop/mobile synthetic
  rendering was inspected by the author, not independently rerun by this reviewer.
- F5: failed-retry banner styling has an author correction and regression test;
  fresh correction review remains pending. Client-side scope-entry shape checking
  remains a follow-up; service pin/authorization verification is still required.

The whole e71 production reversion proves the combined scheduling deadline,
body timeout and persistent catalog behavior. It does not isolate every partial
catalog branch; the reviewer's targeted mutations supply separate evidence.

Missing payload rows, collection overview, normalized conversations, search,
annotations/views, analysis and admin remain open roadmap work. No live keys,
archives, deployment, migration, main merge or cutover occurred.
