# Feature: raw-source migration preflight and archive maintenance CLI

## Summary

Prepare v1 migration without calling trust-filtered kan reads or opening its all-memory log. Provide a read-only discovery/preview CLI that hashes the exact source bytes, streams CAR framing and block hashes, records omissions and errors, and explicitly distinguishes raw-byte inspection from claim/signature/reachability verification. Expose the tested v2 ledger's explicit init, verify and backup operations in the experimental `kan-v2` executable. Live encrypted import, cutover and independent backup certification remain pending the operator's key-custody and destination choices.

## Requirements

- REQ-1: Discover workspace roots under explicitly selected search paths without following symlinks; surface unreadable paths and documented directory exclusions.
- REQ-2: Inventory only selected evidence media: primary CAR/HEAD/recovery copies, published Markdown claims, public scope inception, and separately labeled overlay recovery evidence. Exclude private keys, credentials, indexes and unrelated project content.
- REQ-3: Hash source files using bounded buffers and detect ordinary concurrent changes. Scan CAR frames before allocation, verify supported block hashes regardless of whole-file size, and report invalid/unsupported material without discarding its raw-file inventory.
- REQ-4: Never infer semantic validity, lineage, complete graph reachability or migration completion from successful file hashes. Preserve explicit incomplete states and prohibit cutover in preflight output.
- REQ-5: Provide executable commands for read-only preflight and explicit archive initialization, verification and consistent backup, without replacing the installed v1 binary or modifying source workspaces.

## Acceptance Criteria

Witnesses executed with `cargo test --features v2-storage --test migration_preflight --test surface_conformance` (6 preflight and 19 surface tests passed). These establish preflight behavior, not migration readiness:

- [x] AC-1: `discovery_and_preview_preserve_bytes_and_exclude_credentials` and `symlink_sources_and_intermediate_scope_links_are_not_followed` cover nested workspaces, excluded directories and symlinks; omissions are reported and observed symlink targets are not traversed. (REQ-1)
- [x] AC-2: `discovery_and_preview_preserve_bytes_and_exclude_credentials` captures primary/publication/overlay bytes while fixture credentials and index contents never appear in output. Source hashes and modification times remain unchanged after preview. (REQ-2, REQ-5)
- [x] AC-3: `independent_car_frames_stream_beyond_ten_megabytes` scans a 12 MiB CAR; `malformed_and_unsupported_sources_are_explicit` covers malformed varints, oversized/truncated frames, bad digests, unsupported hashes and malformed headers. The implementation uses a fixed 64 KiB body buffer and bounded header/digest allocations; this is not a measured process RSS guarantee. (REQ-3)
- [x] AC-4: `discovery_and_preview_preserve_bytes_and_exclude_credentials` asserts unverified signatures/reachability and `ready_for_cutover: false`; `changed_sources_are_not_certified_as_stable` races a fixture writer and proves changing files do not receive a stable hash inventory. Read failures are errors or notices, not empty success. (REQ-4)
- [x] AC-5: `discovery_and_preview_preserve_bytes_and_exclude_credentials` and `real_cli_initialization_verification_and_backup_are_explicit` invoke the actual executable without the old kan binary on PATH, cover all five commands, and reject destination overwrite. (REQ-5)

## Architecture

`src/migration_preflight.rs` owns read-only source traversal and bounded CAR inspection. It never calls `src/store/log.rs` or a trust-filtered CLI. `src/bin/kan-v2.rs` is an experimental CLI front end over it and `src/evidence_store.rs`, enabled with `v2-storage`. It does not replace or impersonate the installed kan executable. The eventual service will use the same ledger, with encryption and admission at its boundary.

Discovery requires explicit roots and emits excluded-directory and read-error diagnostics. Discovery stops with an explicit incomplete notice at 65,536 traversal entries; source preview is bounded to 16,384 files and 128 levels per root. Exceeding either preview bound is an error rather than an incomplete listing labeled complete. Source bytes are hashed in 64 KiB buffers. CAR headers are bounded to 64 KiB; block bodies are hashed as streams, and frame lengths are checked against remaining file bytes before reading. Unknown hash/codec profiles are retained as unsupported evidence. This scanner establishes framing and supported block hashes only, not MST reachability or claim authenticity.

Symlink checks and metadata comparison detect ordinary local races. They do not establish an atomic snapshot or defend against an adversary concurrently swapping ancestor directories. Import requires an immutable snapshot rather than upgrading these checks into a security boundary.

The preview records a file-level observation rather than claiming an atomic multi-medium snapshot. The actual importer must acquire/pin immutable source snapshots, build a disk-backed reachability/claim inventory, encrypt selected bytes, and reconcile receipts. It must not treat this preflight as its verified completion manifest. Git history is explicitly not inventoried by this slice; working-tree publication bytes are retained as observations. Private recovery credentials belong in the separate encrypted backup procedure, not evidence ingestion.

Build the experimental executable with `cargo build --features v2-storage --bin kan-v2`. Its read-only entry points are `kan-v2 discover <search-root>...` and `kan-v2 preview <workspace-root>`. JSON goes to stdout; errors go to stderr. Keep these inventories private: filenames and source associations are sensitive metadata. The `.local-state/` directory is ignored for private development reports. This executable is separate from the installed `kan`; `cargo run` still defaults to the original command.

`kan-v2 init <archive-directory>`, `kan-v2 verify <database-file>`, and `kan-v2 backup <archive-directory> <new-destination-file>` expose the lower-level ledger's maintenance operations. They do not supply encryption, service admission or a live importer. Use synthetic archives for these operations until the encrypted service profile is implemented. A local backup is not independent backup certification.

## Resolved Questions

- Continue toward v2 and preserve original evidence instead of repairing day.
- Make safe source discovery and inspection available while encrypted service deployment choices remain pending.
- Keep archive administration explicit and separate from read-only preflight.

## Open Questions

The operator's answers on owner-held archive keys, first deployment and independent backup destination are pending. No live data is uploaded or cut over by this tool. The parent design's real harness/provider choice still gates capture integration.

## Out of Scope

- Claim graph reconstruction, signature/admission decisions, lineage mapping, actual encrypted upload, resume receipts, day replacement and live cutover.
- Private-key export or automatic trust changes.
- A claim that an inspected source or locally copied database is an independently recoverable backup.

## Derived-data recovery extension

See `.design/kan-v2-recovery-cli.md` for `read-record`, `read-object` and `recover`.
All take database files; `recover` requires a new destination file, leaves the
source intact and does not promote the result. Failed outputs remain for inspection.
These commands do not change preflight into a live encrypted importer.
