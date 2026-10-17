# V2 storage lifecycle review disposition — 2026-10-16

This is the author's disposition, not an independent verdict. The independent reviewers used fresh Claude Code sessions with actual `claude-opus-5-5`, published source only and synthetic fixtures. Private teloi/day state was unavailable; neither report establishes absence of teloi or completes day recording.

## Initial lifecycle review

- Range: `06276fac9bf960f3b0b3f0dbe3c943c10d0676b8..af5bb5fee4e3fce58b59c6ab3646292dff82e800`; storage implementation `6f1fa0e4a3fc1578aa042ae4b54266107988ad73`.
- Session: `4d285b6d-71e2-4d3e-bf99-f01dfebb71aa`.
- Final report SHA-256: `d7078245c5a5ca921f7a5decf7b64d2f61c90f674a3d5c0a9d51e687a5fb7927`.
- Verdict: **APPROVE WITH FOLLOW-UPS**. AC-2 was explicitly not met as written; the verdict was not permission to ignore that finding.
- Independent evidence: build, 67 targeted tests, feature all-target Clippy and formatting; 300 random SIGKILL trials with no unrecovered initialization (166 left a journal); concurrent resume, foreign/profile-marked/malformed files, non-default SQLite settings, hard-link and Unicode aliases, dangling sidecars, standalone backup and WAL probes.
- Public probes live in reviewer scratch; raw final reports and model metadata are retained privately in the worktree's `.local-state/reviews/`. Hidden reasoning is not published.

## Fresh correction review

- Range: `af5bb5fee4e3fce58b59c6ab3646292dff82e800..a8345b3d8d89cb90ea414a0a820bdd7591ab0773`.
- Session: `f14af133-ef44-43f4-9abd-d34bf5e46669`; actual `claude-opus-5-5`.
- Final report SHA-256: `acccd6ae66939266d6820b7a0c8129a1ecbb1ed5b43dc8af88fae2fee689a40b`.
- Verdict: **APPROVE WITH FOLLOW-UPS**. Independently passed the 67-test suite, build, Clippy and formatting. Confirmed malformed profile-marked DELETE files remain byte-identical through resume and ordinary open/backup. Forced hot spilled rollback journals and verified exact committed bytes were restored before rejection. Confirmed valid WAL/crash recovery, bounded lock wait, backup isolation and path checks.
- The exact-schema issue remained a prerequisite for completing lifecycle AC-2, so the author implemented a separate schema-admission slice rather than ticking that criterion early.

## Finding disposition

| Finding | Disposition |
|---|---|
| M1: matching profile markers caused malformed DELETE-mode files to switch to WAL before rejection | Fixed by storage `7243618`, merged into migration `a8345b3`: audit precedes `configure` in ordinary open, covering explicit resume too. Regression adds correct markers with absent schema; causal control restores the old order and fails the test. |
| L1: preexisting foreign WAL can be checkpointed before rejection | AC-2 now distinguishes quiescent DELETE-mode byte preservation from explicitly allowed SQLite journal/WAL recovery. Logical contents are preserved; physical files need not be identical. This makes the criterion consistent with the original architecture's recovery permission. |
| L2: empty-file adoption inherits page size/encoding/auto-vacuum | Documented. Qualification of non-default physical settings remains open before production support. |
| L3: resume accepts symlinked roots while create rejects them | Documented file-vs-root distinction. Root-policy parity remains a follow-up; database file symlinks and broad file permissions are rejected. |
| L4: concurrent empty-file resumes can safely reject one participant | Preserve rejection; retry works. Typed retry diagnostics and convergence ergonomics remain open. |
| L5: missing causal control for create's sidecar guard | Added and demonstrated. Six lifecycle mutants compile, execute and fail their named tests; restored fixes pass. Reviewer SIGKILL probes supplement the tracked process-exit matrix. |
| Related inherited exact-schema gap: extra tables/triggers can coexist with matching profile and valid evidence | Implemented in storage `b956846`: writable open compares all main schema entries (including implicit indexes) against an in-memory canonical schema. Raw recovery keeps its weaker marker-only check. The separate `.design/kan-v2-schema-admission.md` supplies admission and preservation tests; final independent verdict is recorded below. |

## Completion boundary

The lifecycle design closes explicit interrupted-initialization recovery and backup-sidecar inventory/isolation for experimental P3 maintenance. Normal startup still scans the entire archive, and broader storage authority and capacity qualification remains open. P4 authenticated service/key wrapping, P5 encrypted resumable import, P6 capture/spool and P7 independent backup/restore/cutover remain unfinished. Existing v1 stores and live routing were not changed.

Design validation passes its structural checks (five requirements and criteria). Running day from the original checkout warns about v2 files only present in the worktrees and two withheld legacy claims. The design awaits day back-fill; no claim IDs or successful recordings are fabricated.

## Remote validation limitation

The first lifecycle storage push's migration matrix run `38989137108`, job `117267412028`, failed the released `v1.0.0-beta.1` seed writer fixture: the old binary wrote no claims and reported that no claim format was selected. The harness returned `unwritable` against the committed `ok` prediction. This occurred before candidate-reader execution, so it is not evidence of a lifecycle regression; it remains a real unresolved CI failure. No expectation was weakened to turn the failure green. Later head/check status must be read separately before merge.

## Author verification refinements

The schema guard made the prior audit-order mutant survive its old markers-only fixture: an earlier independent check now rejected that file. Commit `f73c52c` gives audit ordering its own canonical-schema/corrupt-content fixture, so removing either schema admission or audit ordering is detected separately. All seven final lifecycle/schema controls compile, execute and fail their named tests; restored fixes pass.

The first full schema run caught an author test error: the independent Python verifier was given a WAL-mode archive after append instead of its documented standalone snapshot. The author stopped schema review session `46fdaa97-dfe7-457c-a6bf-8cb8da5e6b9e` before completion; it supplies no verdict. Test-only `9ba09cb` creates a verified isolated backup before invoking the oracle. The complete corrected suite passes 70 tests (32 storage, seven codec, six preflight, six CLI, 19 surface), plus all-target Clippy and formatting. A new cold review, not continuation of the stopped session, audits the final range.

## Final schema-admission review

- Range: `a8345b3d8d89cb90ea414a0a820bdd7591ab0773..70a43480ac587d0640fd28a839155d9ae50390e5`. Production schema implementation: `b956846`; test refinements: `f73c52c`, `9ba09cb`.
- Session: `37d62cdd-3e8e-41e0-ab2f-c112b3ddee82`; both initialization metadata and final model usage identify actual `claude-opus-5-5`.
- Final report SHA-256: `e05516fc14482e58153cc41512dcd8749d54a4f60b4267c346fa380ab543b1f0`.
- Verdict: **APPROVE WITH FOLLOW-UPS**; no Critical, High or Medium findings.
- Independent build, all 70 targeted tests, Clippy and formatting passed. Fourteen hostile-schema variants were rejected through resume and ordinary writer open/backup. Canonical init, backup and rebuilt archives were admitted. Byte-patched CHECK text that SQLite integrity checking accepted was refused by writer admission. Recovery rebuilt a trigger-bearing archive with missing derived bindings into a canonical admitted archive.
- The reviewer checked Git history and confirmed `SCHEMA` has not changed since its original implementation. Exact DDL comparison therefore does not exclude archives generated by earlier commits of this experimental engine. Extra ANALYZE statistics and user-added indexes are deliberately unsupported, as designed.
- The reviewer inspected causal controls but did not execute source-mutating scripts. Author execution is separate evidence, not attributed to the reviewer. It did not run the full legacy matrix or physical-profile portability tests; private teloi remain unavailable.

Remaining schema-review follow-ups: (1) CLI `verify` should explicitly disclose `writable_admission: not-checked` or equivalent help text; for now it verifies structural evidence only and may succeed where writable open refuses an extra trigger/index. (2) Combining schema admission and the content audit into one read transaction would narrow their snapshot gap, although concurrent owner-issued DDL is outside the declared trust boundary. (3) Add tracked commit-bearing, UNIQUE-only, ANALYZE and sqlite_sequence fixtures beyond the independent probes. Broader physical b-tree forgery is left to integrity checking and the trusted filesystem boundary.

Only documentation changes follow `70a4348`; reviewed production code and tests remain identical. Lifecycle AC-2 is now satisfied within its stated quiescent-file boundary by the additional schema-admission slice, rather than by weakening foreign-schema rejection. These outcomes do not authorize merge to main or deployment.

The later storage runtime-head run `38989786832`, job `117269458601`, independently reproduced the same released seed-writer fixture failure before candidate-reader execution. At the observed check, storage had 20 successful checks, one pending and that failure. Subsequent documentation-push CI is a new run and is not presumed green.
