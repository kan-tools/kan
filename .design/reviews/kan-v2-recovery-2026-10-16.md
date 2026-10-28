# Recovery review disposition — 2026-10-16

This build point adds raw reads and out-of-place reconstruction despite damaged
SQLite bindings and cached commit coordinates. Originals and exact canonical bytes
are retained. The experimental CLI adds `read-record`, `read-object` and `recover`.
It does not perform live migration, encryption, authentication or automatic cutover.

The final fresh combined review returned **APPROVE WITH FOLLOW-UPS** for
`1d89ec56ac5024e25629bd877ca597e19f0c5156..f2419adf42ca2f6a17d1caba5a053f6a7d6b951a`.
The reviewed storage implementation is 0b15b9119f71e3f85e492513841a1f185491a7a5.
Subsequent commits add review records and one limitation regression; production
code remains identical to the reviewed head.

## Fresh reviews

| Scope | Base → reviewed head | Actual model/session | Verdict |
|---|---|---|---|
| Initial storage recovery | ff8d57c → c557451 | claude-opus-5-5 / da152494-9f34-4f5f-abad-8a975027315c | APPROVE WITH FOLLOW-UPS |
| Initial CLI integration | 1bdcda2 → 1d89ec5 | claude-opus-5-5 / fae0f036-197c-4281-8860-21bbcd781b0f | APPROVE WITH FOLLOW-UPS |
| Integrated corrections | 1d89ec5 → f2419ad | claude-opus-5-5 / fb21d3fe-c5da-4325-93ff-d186980f7617 | APPROVE WITH FOLLOW-UPS |

The initial storage report SHA-256 is
`04d097ddc3e1da98a2965cdaacccd23ef8333b97f2006d77c9ba2c00ee2d60ec`.
The initial CLI report SHA-256 is
`7889d7f4a59372d7f2dbe9677837e2177c0e0bb00788b3cb20e8b3ea8435f2f9`.
The combined correction report SHA-256 is
`2ef6d8e051461107bcf494b1b1af1834b793ea9d4dba2bcfbd48f3f5fb433fc8`.
It is `.local-state/reviews/recovery-corrections-report.md` in the migration worktree.
CLI initialization and final model-usage metadata both confirm `claude-opus-5-5`.
Unedited final reports and model metadata are retained privately under
`.local-state/reviews/` in their respective permanent worktrees. Raw model streams
are private and are not published as review reports.

All reviewers were new Claude Code sessions using only published tracked public
source and synthetic fixtures. Private teloi/day process state were excluded;
absence of access does not mean absence of applicable teloi. The full legacy test
matrix was not repeated locally under disk constraints. No legacy trust bypass or
fabricated claim identifiers were used.

## Corrections

- Storage M1: bound SQLite values to 8 MiB and avoid WITHOUT ROWID key seeks in the
  recovery reader. Unix tests measure peak RSS under 64 MiB for 96 MiB corrupt rows;
  ordinary ledger reads remain indexed. Offline recovery object lookup scans keys.
- Storage L1: reject intersecting source/output SQLite filename namespaces in both
  directions, existing target sidecars and tested filesystem aliases.
- Storage L2 / CLI F1: explicitly catalog and type source WAL/SHM coordination
  initialization; document read-only-media/hot-journal failure and preserving all
  source media together. No silent immutable mode or WAL omission.
- Storage L3 / CLI F4/F6: distinguish incomplete retained output from a fully
  committed output followed by a sync/reverification failure. Neither is promoted.
- CLI F2/F5/F7: contextual path errors, JSON path validation before creation, and
  assertions for byte encoding, CIDs and snapshot coordinates.
- CLI F3: document retention of unreferenced staged objects; object counts and hash
  verification do not imply committed references.

Author validation on the integrated correction: 59 targeted tests (23 storage,
seven codec, six preflight, four CLI, 19 surface), all-target feature Clippy,
formatting and whitespace checks pass. Eight causal negative controls compile and
fail their named tests; restored fixes pass. An additional macOS probe measured
about 9.2 MB peak for 9 MiB and 96 MiB corrupt rows, compared with about 110 MB for
the unsafe object seek. This does not assert constant process RSS for every SQLite
operation or establish power-loss durability.

## Remaining boundaries

Normal writer open still performs a lifetime audit. P3 startup/performance,
ordinary initialization recovery, backup-sidecar qualification and classification
review remain separate work. SQL/codec corruption errors retain differing categories;
unified operator diagnostics are a follow-up. A coherently missing suffix needs
external trusted frontier/receipt witnesses. Read-only WAL media may need usable
sidecars or a writable copy. Hostile path replacement races, maliciously rewritten
schemas, large-archive operational qualification and power-cut testing are not
certified by these tests. The stack remains draft, with no merge or deployment.


## Final review evidence and disposition

The final reviewer independently passed all 59 integrated tests, lint, format and
feature-gate checks, and executed synthetic probes for 96 MiB poisoned objects and
keys (roughly 9.3–9.7 MB peak), bidirectional sidecar collisions, Unicode and hard-link
aliases, actual WAL-only committed data, hot journals and non-UTF-8 paths. Original
main/WAL/hot-journal bytes were preserved. It did not execute source-mutating negative
controls, Windows or the full legacy matrix.

Its remaining medium M1 is a raw-damage availability boundary: the safe object scan
can stop at an unrelated corrupt page/oversized key before reaching an intact later
object. This is explicitly documented; a subsequent regression proves the oversized
raw-key case, verifies the intact payload still exists via SQLite's indexed reader,
and confirms canonical record reads remain available. It is the 60th targeted test
and passed after the review; the reviewer ran the preceding 59. There is no promise
of arbitrary physical raw-table salvage. Bounded indexed forensic recovery needs
separate process/storage qualification. Derived-index reconstruction remains supported.

Other follow-ups: more specific hot-journal/source-failure diagnostics; the preexisting
init/backup non-UTF-8 JSON behavior; and non-UTF-8 hard-link aliases through the direct
library API (the recovery CLI rejects non-UTF-8 paths). No production behavior was
changed after the final reviewed head to claim these were fixed.

CI was still running when this disposition was written. Local test success and the
independent review are not a claim that the full remote matrix has completed.
