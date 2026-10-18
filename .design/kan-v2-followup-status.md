# Kan v2 follow-up ledger — 2026-10-18

This is a navigation aid to implementation and review evidence, not an authority
for acceptance. The complete human frontend remains required by
`kan-v2-human-frontend.md`; partial slices do not close that design.

| Workstream | Current evidence | Remaining work |
|---|---|---|
| Health admission/reporter reliability | #283, a04f288; fresh Opus approval with follow-ups; all CI green | Qualification under wider production load; no universal zero-loss claim |
| Capacity and owner rotation | #284, 771341e; fresh Opus approval with follow-ups; all CI green | Merge only with #285 corrections; whole-device/power-loss qualification remains distinct |
| Session-cap continuation, WAL refusal, runner cleanup | #285, 9d300b4; fresh Opus approval with follow-ups; all CI green | Commit the surviving focused test improvements listed below |
| Real Library reader and source/provenance UI | #286, first production df74506; author API/CLI/UI/browser evidence | Fresh review in progress; scope-switch race corrected separately; browser file delivery remains unverified |
| Deduplicated collection overview | `kan-v2-collection-overview.md` | Implement and qualify the bounded projection, typed status, refresh/cancel and human states |
| Normalized sessions and navigation | Parent human-frontend design | Versioned adapters and exact source mapping for messages, tools, branches, attachments and gaps |
| Search and views | Parent human-frontend design | Authorized encrypted projections, filters, frontiers, saved trust-aware views and stable URI extensions |
| Knowledge and annotations | Existing v1 semantic foundations | v2 evidence/claim read adapter and separately authorized append-only annotation signer |
| Human administration | Existing CLI backup/restore/migration/rotation primitives | Typed plan/job APIs and UI for storage, recovery, migration, access, keys and retention |
| Background analysis/day | Server-first architecture | Inspectable run/assessment records, scheduler/worker contracts, grants/quotas and source lineage |
| Deployment and migration cutover | Runbooks and synthetic evidence only | Reader placement decision, real installation/key placement and owner-approved cutover remain separate |

## Exact #285 review follow-ups

The authoritative report and disposition are
`reviews/kan-v2-admission-audit-2026-10-18.txt` and `.md`.

1. Test the first-reason no-rewrite guard directly, not only the earlier sealed
   admission filter. The review contains a focused probe that kills the survivor.
2. Replace modal focus assertions against old element flags with activeElement
   checks. Test that polling leaves focus inside the inspector and closing returns
   focus to the replacement row.
3. Test 90% capacity boundaries exactly, including just below/at/above, for both
   attempts and reporter sessions. A 99% mutant survived broad high-pressure tests.
4. Bind retry tests to production wrappers as well as injected helpers. Helper
   mutation kills do not demonstrate the wrapper actually calls those helpers.
5. Add exact alias and Python output-prefix rejection cases to the reversion
   adapter tests; do not count parse errors as assertion failures.
6. Keep the documented conservative freshness interpretation visible. The
   five-second UI threshold can report a worker unknown during a legitimate
   longer request; separate capture/worker cadence presentation remains a refinement.

Older v2 session-limited journals with a released reserve are deliberately
accepted and writable; this compatibility decision is documented in #285. No
source repair or automatic reserve rewrite is implied.

## Review and merge discipline

Fresh actual Claude Code Opus 5.5 remains the build checkpoint reviewer. Preserve
model/session evidence, exact verdicts and surviving mutants. Reversion evidence
must compile, fail a named assertion, and pass after restoration. The first
Library review was interrupted before a verdict and is not an approval.

PRs remain stacked drafts. Merge order follows their bases; no main merge,
installation, production archive read, key placement or cutover is implied by a
passing development checkpoint. Permanent worktrees live beneath `.worktrees/`.
All temporary fixture servers are stopped after use. Active review exports remain
immutable; author corrections receive their own review afterward.
