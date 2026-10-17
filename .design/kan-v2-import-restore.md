# Feature: Verified offline import restoration

## Summary

Recover a pinned v1 import from an explicit local archive or standalone backup into a new private directory. Authenticate retained requests and reconcile deterministic operations, inventory, chunks and complete file hashes without consulting damaged derived lookup fields or promoting legacy claim trust.

## Requirements

- REQ-1: Require an external expected plan commitment, scope, original writer and recipient private key. Read a single pinned RecoveryReader transaction and locate operations using authoritative manifests, never derived lookup columns.
- REQ-2: Authenticate selected signed requests, their exact manifest and structural receipt bindings, recipient encryption, framing and original plan. Missing, duplicate, substituted or malformed selected evidence must fail closed.
- REQ-3: Bound archive scan, inventory, frame and chunk counts. Stream reconstructed files into a create-new owner-only directory; reject unsafe paths and collisions and never overwrite source or existing output.
- REQ-4: Publish a completion report only after every selected byte and the final observation have verified and output files/directories have been synchronized. Preserve incomplete output on failure; never infer success from directory existence. Preserve omissions and explicitly distinguish selected-byte verification from server attestation, legacy trust, independent backup and cutover.
- REQ-5: Demonstrate actual CLI restoration above 10 MiB, empty and nested files, independent frame-oracle agreement, derived-damage tolerance, hostile evidence/path rejection, and interrupted output with no completion report.

## Acceptance Criteria

- [x] AC-1: Round-trip a synthetic malformed source above 10 MiB from a standalone archive and compare complete bytes and hashes with the original and independent Python decoder. Original data remains unchanged. (REQ-1, REQ-2, REQ-5)
- [x] AC-2: Wrong plan/key/writer/scope, missing or duplicate operations, corrupted signed objects, malformed frame/plan, unsafe paths and occupied destination fail without a successful report. Derived lookup damage does not prevent restoration. (REQ-1, REQ-2, REQ-3, REQ-5)
- [x] AC-3: Files are streamed with bounded chunks; record-count admission and protocol limits fail explicitly. Output files/directories are private; crash/fault injection leaves no final report before all verification and syncs. Retrying an occupied directory is refused. (REQ-3, REQ-4, REQ-5)
- [x] AC-4: Report includes the externally pinned plan, source lineage, route, selected-file hashes, operation sequence/manifest provenance, notices and pinned archive frontier; claims of server attestation, independent backup, semantic trust and cutover remain false/unverified. (REQ-2, REQ-4)

## Architecture

Add `src/evidence_restore.rs` and a `restore-import` command in `src/bin/kan-v2.rs`, behind v2-crypto. Extend `src/evidence_store.rs` RecoveryReader with a raw frontier query inside its existing read transaction. Two bounded sequential raw-manifest scans locate first the possible inventory operations, then all plan operations. Read-only source opening can create SQLite WAL coordination sidecars as already documented; source records are never rewritten. Missing sequence rows or invalid raw record encodings conservatively fail even when unrelated to this plan. This is an offline recovery tool, not a scale-qualified live query path.

Decode the existing KANI v1 profile independently of the importer implementation. Require canonical plan JSON and its domain-separated hash, strict structural fields, original route/recipient, consistent preflight inventory, safe unique relative paths, canonical hashes, file/chunk lengths and bounded counts. Each selected request must match its authoritative manifest and receipt issuer/audience, explicit scope/writer, deterministic operation ID, header coordinates and HPKE recipient. Stored receipts are unsigned: structural binding proves no authenticated service admission or current completeness. The archive frontier is an observed pin, not an externally authenticated archive root. An owner who can coherently rewrite the archive remains trusted for historical sequence placement; the external plan and request signatures protect the recovered content.

Create a new private output root containing `files/`, exact `plan.json`, and `report.json` written last. File and directory creation flows through typed `EvidenceRestore` capabilities in `src/persistence.rs`, declared in `src/surface.rs` and `tests/fixtures/read-write-surface.tsv`. Stream one chunk at a time, verify hashes before accepting a file, sync files and all created directories before publishing a synced report. Failure leaves inspectable partial plaintext output. Existing paths are never reused; separate file/report namespaces avoid collisions. Parent directories and the running user are trusted against concurrent filesystem replacement; do not restore into an attacker-writable parent. No automatic cleanup deletes forensic partial results. An observer boundary supports deterministic interruption tests without a production CLI fault switch.

Limits follow import v1: 32 MiB inventory, 512 KiB chunks, 262,144 data chunks, 16,384 files. Scan at most a caller-selected positive number of raw records (default 1,000,000); keep only selected ordinal-to-sequence mappings and bounded inventory in memory. Underlying recovery object reads may scan raw object keys, so total I/O can be quadratic; no throughput claim. The new directory is not an atomic directory publication: only a complete valid report identifies success, and a crash during report writing may leave invalid/truncated JSON. A valid report proves the preceding selected-byte verification, not survival of hypothetical filesystem/hardware corruption after sync.

## Open Questions

No new user decision is required for this additive offline build point. Production key custody, live final-delta capture, independent-host backup drills and cutover remain the parent roadmap's explicit gates. Day/kan design and review claim backfill remains pending because the legacy reader withholds partial-trust claims; this does not establish an empty log or absence of teloi. The user's server-first raw-evidence recovery goal is the review north star.

## Out of Scope

Remote transport restore, all-history writer-chain certification, service-signed receipt redesign, automatic source repair/deletion, semantic import of legacy claims, production migration, deployment, main merge and post-hoc extraction. These remain sequenced after this recovery witness.

## Validation boundaries

Synthetic interruption uses abrupt child-process exit at four observed boundaries;
it is not a power-loss or physical ENOSPC test. The scan-limit test exercises a
small explicit limit; the maximum 32-MiB plan and 262,144-chunk allocations are
validated in code but not materialized at their full boundary in this suite.
The restore output parent is trusted. Old source bytes and their semantic defects
are preserved; the tool does not make a malformed legacy CAR readable by v1.

## Independent review and retained regressions

The initial implementation received fresh Opus 5.5 APPROVE WITH FOLLOW-UPS with
no correctness blocker. Eleven independent probes, including a separate archive
signature/HPKE/selected-byte oracle and multipart inventories, are retained in
`tests/evidence_restore_adversarial.rs`. Three targeted mutation controls cover
receipt binding, canonical plans and inventory-frame coordinates. Individual data and completion coordinate call sites remain a nonblocking coverage follow-up. Production source is
unchanged by this coverage follow-up. Review identities and evidence are recorded
in `.design/reviews/kan-v2-import-restore-2026-10-17.md`.
