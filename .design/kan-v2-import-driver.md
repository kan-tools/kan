# Feature: Resumable encrypted v1 snapshot import

## Summary

Turn the v1 preflight allowlist into an encrypted raw snapshot stream through the existing durable queue. Preserve exact source bytes, including malformed or unsupported evidence, and explicitly retain the preflight's omissions and uncertainty. Import coverage is separate from verified recovery and cutover.

## Requirements

- REQ-1: Select one explicit workspace, raw store or public identity-history root using `src/migration_preflight.rs`. Require an explicit source-lineage token and destination spool; never infer lineage from a repository name or upload private credentials outside the existing allowlist.
- REQ-2: Pin a deterministic inventory commitment including source hashes, per-chunk hashes, selection notices, scope, writer, audience and recipient. Import requires the operator's expected plan ID and rejects source/route changes before admitting any new bytes.
- REQ-3: Preserve large files as bounded encrypted raw chunks with source-file and chunk coordinates. Retain an encrypted inventory and final observation; malformed source data remains raw evidence, not trusted claims or silently omitted bytes.
- REQ-4: Resume through deterministic operation IDs and the owner-trusted spool's retained operation history. Never regenerate a retained request. Bound new admissions per invocation, preserve partial progress on full queues or interruption, and keep network delivery separate.
- REQ-5: Independently verify decoded framing, inventory hashes and complete reconstructed source bytes in synthetic tests, including sources larger than 10 MiB, source changes, bounded batches, capacity exhaustion and restart. Never report operational migration/cutover complete merely because queue coverage is present.

## Acceptance Criteria

- [ ] AC-1: Plan output is deterministic for the same explicit source and route, changes with lineage/recipient/bytes, and excludes private-key fixtures. A mismatched expected ID leaves the queue unchanged. (REQ-1, REQ-2)
- [ ] AC-2: Actual CLI can resume bounded batches after delivery and restart, producing one operation per inventory/data/completion chunk; changed bytes are refused and partial progress is retained. (REQ-3, REQ-4)
- [ ] AC-3: A separate decoder reconstructs a malformed source over 10 MiB byte-for-byte from decrypted archived requests and verifies the committed inventory and per-file hashes. Notices remain visible and cutover stays false. (REQ-3, REQ-5)
- [ ] AC-4: Wrong writer, recipient, selected root or plan, symlink sources and oversized inventories fail explicitly; no source file is modified. (REQ-1, REQ-2, REQ-5)

## Architecture

`src/evidence_import.rs` will compose `src/migration_preflight.rs`, `src/evidence_delivery.rs` and `src/evidence_spool.rs`. Plans are reconstructed read-only from an explicitly selected source and contain stable 512-KiB chunk hashes. The complete plan is bounded to 32 MiB and 262,144 data chunks. Source files are checked against preflight whole-file hashes while planning; every chunk is checked against the pinned plan again immediately before queue admission. Empty files have an explicit zero-length chunk. Source-root paths and notices stay inside the encrypted inventory, with only caller-visible plan output exposing the selected local paths.

The plan ID is a domain-separated SHA-256 of canonical serialization. It binds an explicit 32-byte lineage token, selected source root and mode, preflight observations, per-file chunk hashes, and the spool scope/writer/audience plus public encryption recipient. No frontier or pending count enters the plan ID. Plan construction does not mutate the queue or create keys. Import execution compares the exact expected plan before admission, checks the signing identity, and allocates deterministic 128-bit operation IDs from the plan ID and ordinal. Inventory pieces come first, raw source chunks follow, and the final observation comes last after a fresh plan comparison. Each plaintext frame has a versioned binary prefix, bounded JSON header identifying plan/kind/coordinates, and exact raw content; the whole frame is HPKE encrypted before queue admission.

Retained operation IDs are local resume hints under the spool's existing owner-trust assumption, not cryptographic proof that an arbitrary source has been imported. The importer skips an already-retained operation and never reseals its bytes. A consumer must independently decrypt the stream, verify plan/operation membership, all chunk and whole-file hashes and the final observation before claiming a recovered snapshot. Coherent raw spool edits or another process intentionally forging this importer's deterministic operation IDs are not prevented by this local progress mechanism. A final queue observation is explicitly not an authenticated completeness certificate, backup, or cutover witness.

The CLI adds `import-plan` and `import-v1` with explicit source, spool, source ID, recipient and selection mode; execution also requires the expected plan, signing key and finite batch limit. Queue capacity errors stop the batch and preserve earlier admissions; operators drain with the existing command and repeat against the same pinned source. No extra database, plaintext staging directory or mutable progress file is introduced. Destination scope and writer are inherited from the queue. Larger/multiple source selections use independent plans in the aggregate archive; same-named repositories remain distinct through explicit lineage tokens.

All persisted bytes pass through the existing signed request/spool/ledger boundaries in `src/persistence.rs`. The new import plaintext frame is an encrypted opaque subformat and must be cataloged with its reader/verification rule. Existing v1 source records/signatures are preserved byte-for-byte; this importer does not promote them into v2 semantic trust or repair damaged authority. A later authorized reader/extractor builds those views.

## Open Questions

Production custody, independent destination backup, verified restoration/cutover and final live-source delta remain open in the parent architecture. Source writes should be quiesced for a final snapshot; this read-only importer detects observed changes but does not lock unrelated legacy writers. Day record backfill remains pending because of the known partial-trust/worktree limitation, not because the log is empty.

## Out of Scope

- Automatic discovery of credentials, live source deletion or repair, trust promotion, provider capture, a complete restore CLI, deployment or main merge.

## Decoder review correction

The independent oracle now uses explicit runtime checks rather than Python assertions and requires an external `--expected-plan` commitment. That commitment binds source lineage, recipient, route, inventory and all chunk/file hashes. Reports preserve inventory completeness and notices, and label only selected-file byte verification as proven; transport authentication, claim validity and cutover remain separate. Regression witnesses must reject corruption with Python optimization enabled and reject a fully self-consistent replacement stream against the original expected plan.
