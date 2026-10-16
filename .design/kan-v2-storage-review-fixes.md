# Feature: storage review corrections, provenance and path handling

## Summary

Address the first storage review's incorrect first-manifest acceptance (F3) and the migration review's bare relative path failure (F4), then integrate the corrected P2 typed codec/oracle. This is a bounded correction round, not completion of P3 readiness.

## Requirements

- REQ-1: Recompute first-use ordering from the canonical journal instead of accepting any manifest that repeats a slot.
- REQ-2: Treat a bare relative filename/directory as having parent `.` for creation and directory sync; preserve no-overwrite backup behavior.
- REQ-3: Keep the independent backup verifier aligned with the typed Python codec without collapsing maps into link/byte sentinel dictionaries.

## Acceptance Criteria

- [x] AC-1: A valid repeated slot passes both verifiers; changing first_manifest to its later use fails both, while canonical raw bytes remain unchanged. (REQ-1)
- [x] AC-2: A child process creates and backs up an archive using bare relative names; success corresponds to a verified backup and a retry cannot overwrite it. (REQ-2)
- [x] AC-3: Existing backup/restore, fault, conformance and surface tests pass with the corrected codec; a fresh Opus 5.5 review judges the exact correction. (REQ-3)

## Architecture

`src/evidence_store.rs` already scans authoritative manifests in sequence and verifies binding reachability. During that scan, join each binding's first_manifest to its journal sequence and require that it is no later than the current occurrence. The existing membership check verifies that the named first manifest contains the same slot. Together, these reject a later occurrence mislabeled as first without an unbounded in-memory map or another history scan.

`src/persistence.rs` retains ownership of file creation and permissions; this round adds no mutation path. Normalize empty path parents to `.` at filesystem-boundary checks and sync. Exercise relative paths in a subprocess to avoid changing the test runner's process-wide working directory. `scripts/verify_evidence_store.py` will consume actual bytes and Link objects after the P2 correction is merged. `tests/evidence_store.rs` independently verifies all behaviors.

## Remaining review work

Storage F1 (full scan on normal open), F2 (raw access/rebuild despite damaged derived bindings), F4 (bundled SQLite backup sidecar catalog), F5 (interrupted initialization recovery), and F6 (derived-field catalog consistency) remain open and must be resolved or explicitly qualified before P4. This round does not quietly waive the parent's bounded-startup requirement. No live migration, deployment, verified independent backup or cutover is authorized by passing these synthetic tests.

## Validation before integration

On the pre-integration parent, all 12 storage tests pass. A private source-revert probe restored the pre-fix Rust implementation: both new regression tests execute and fail. Restoring only the old Python verifier also makes the first-use test fail. Restoring both fixes makes both tests pass. The exact probe and output are retained under `.local-state/reviews/storage-fix-controls.py` and `storage-fix-controls.log`; no live archive was opened. Codec integration and a fresh review are still pending.

## Integrated validation

The dependent branch now includes P2 commit bc24e2b, whose round-3 independent review is pending separately. The verifier consumes typed bytes and Link values directly. All 13 storage, seven evidence-contract and 19 surface tests pass. A new storage/backup fixture uses CID-shaped scope/operation/slot tokens and dynamic Author links. After integration, restoring the old Rust first-use/path behavior still fails both regressions; removing only the Python first-use-order assertion also fails its regression, avoiding a false failure from the changed Python value API. Restored tests pass. Feature Clippy, formatting and whitespace checks pass. This correction's fresh storage review remains pending; the remaining P3 readiness findings above are unchanged.

## Current review outcome

Fresh Claude Code `claude-opus-5-5` review returned **APPROVE WITH FOLLOW-UPS** for ffa8a9f..332a0f4, session `04d54f74-1ac9-4bb2-a8a5-ec5ba2ec9bcd`. The unedited report is `.local-state/reviews/storage-round-2-report.md`, SHA-256 `043e45ac6b49a391babd4b69a60a1e6cd3d6f876fd4c28b1ca04874bcf79ca6b`. CLI init and final usage metadata confirm the actual model. Subsequent review-record/parent-documentation commits change no reviewed implementation. The separately reviewed codec dependency bc24e2b also received APPROVE WITH FOLLOW-UPS.

The reviewer independently passed build, 13 storage + seven codec + 19 surface tests, all-target feature lint, format, whitespace, oracle checks and optimized-mode refusal. Its scratch-write probes were denied; full legacy testing was omitted under disk constraints. Public source was the only review input; private teloi and the author's negative-control logs were not reviewed. The author controls above remain separate evidence.

Low-severity follow-ups for the next storage build point: match the precise Rust corruption error in the first-use test; explicitly compare canonical raw bytes before/after the binding mutation; add hostile three-use and cross-scope pointer mutations. AC-1's unchanged-raw-byte clause currently follows from the test's binding-only SQL update, not a direct byte comparison. These do not replace the still-open P3 startup/recovery/catalog/initialization requirements listed above. Those remain prerequisites to P4 readiness.
