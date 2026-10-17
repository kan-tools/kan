# Offline verified import restore

This experimental command reconstructs the selected bytes of a v1 import from a
local archive database or standalone backup. It does not modify the v1 source,
repair legacy claims, deploy a service, or enable cutover. Build with `v2-crypto`.

Keep the original `import-plan` commitment separately from the archive. Select an
explicit recipient private-key file (exactly 32 raw bytes, owner-only), original
scope and original signing writer. The archive's observed frontier is not an
externally authenticated completeness certificate.

```sh
kan-v2 restore-import /backup/archive.sqlite /private/recovered-snapshot \
  --expected-plan ORIGINAL_64_HEX_PLAN \
  --scope ORIGINAL_64_HEX_SCOPE \
  --writer ORIGINAL_DID_KEY \
  --recipient-key /private/recipient.key \
  --max-records 1000000
```

The destination must not exist and its parent must exist and be trusted against
concurrent replacement. Unix output directories use mode 0700 and files mode
0600 (subject to a stricter umask). Recovered plaintext is sensitive; choose its
location deliberately. This command does not find, create or back up keys.

Output:

- `files/`: exact selected paths and raw bytes, including malformed CAR data and
  empty files. Names such as `report.json` inside the source remain under files/.
- `plan.json`: exact original canonical inventory, with lineage, route, recipient,
  chunk hashes and source selection observations.
- `report.json`: written last, after file verification and sync. It includes file
  hashes, operation ordinal/sequence/manifest provenance, the observed archive
  frontier, notices and explicit limits on what was proven. The same JSON is
  emitted to stdout on success.

A missing or malformed report means incomplete output. Failure/interruption
retains partial plaintext files; inspect or remove them yourself, then use a new
destination. Existing output is never resumed or overwritten. A valid report
states that preceding selected-byte verification completed; process success can
still be lost after that point, and no report protects against later media damage.

The report verifies outer signed requests and recipient encryption, and reconciles
every required deterministic operation and chunk against the external plan.
Stored receipts are **unsigned**: their binding is checked structurally, with no
claim of authenticated server admission. The command does not certify every
archive writer chain, historical sequence placement or archive completeness.
`claim_signatures` remains `not-verified`; `independent_backup`,
`server_attestation` and `ready_for_cutover` remain false. Selected-inventory
coverage and notices retain their original meaning, including exclusions.

The recovery reader pins one SQLite transaction and ignores derived lookup fields.
It needs readable schema/raw tables and contiguous sequence rows. Invalid raw
records or sequence holes conservatively fail even outside the selected plan.
Opening a WAL database can create coordination sidecars, so preserve the source
media and sidecars together. Perform crash recovery on a separate writable copy
if necessary. A standalone normalized backup avoids live WAL retention.

Limits are 32 MiB of inventory, 16,384 files, 262,144 data chunks and 512 KiB per
chunk, plus the explicit archive record limit. Files stream one chunk at a time;
plan, selected-operation mappings and report provenance remain in memory. Raw
object lookup may scan object keys, so total I/O can be quadratic. This is an
offline recovery tool with bounded protocol allocations, not a measured
large-archive throughput guarantee. Restore does not require the original source,
spool, active service grant or signing private key.

Before production cutover we still need independent-host backup/restore drills,
final live-source delta reconciliation, custody/rotation/erasure operations,
collector/gateway recording-gap behavior and capacity qualification.
