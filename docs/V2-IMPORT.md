# Experimental raw v1 snapshot import

This importer queues encrypted copies of the raw evidence selected by the v1 preflight. It preserves damaged/unsupported records with their warnings. It does not repair source data, confer semantic trust, switch clients, or certify backup/cutover. Keep the original v1 files and existing backups.

## Legacy workspace reminder

The v2 `kan` executable checks the current directory and up to 63 parents for
legacy `.claims` or `.kan` workspace markers, stopping at the nearest Git boundary.
It does not follow marker-directory symlinks, open source logs or load credentials.
A detected workspace produces a stderr reminder for humans and agents; stdout,
command exit status and source data remain unchanged. From the reported project
root, `kan preview .` is the read-only inventory step.

The reminder deliberately does not label the project definitely unmigrated:
successful migration retains original evidence, and `.kan/V2_FENCE` alone is not
a completion receipt. Follow the [fenced migration and reversible client cutover
runbook](V2-LIBRARY.md#fenced-migration-and-reversible-client-cutover): configure the
destination and owner target, quiesce old writers, fence/finalize and deliver,
independently back up and verify, then explicitly activate and restart clients.
Raw import alone does not complete that sequence. Agents must surface the notice
to the owner, not interpret it as authorization to perform migration or deletion.

For a project whose migration is already verified, pass `--no-migration-notice`.
This suppresses only the current invocation and writes no acknowledgement or
migration state. The advisory is not an exhaustive data-discovery or status audit;
use explicit source plans for standalone stores and identity roots.

Build `kan` with `--features v2-crypto`. First initialize a destination queue as described in [encrypted delivery](V2-DELIVERY.md). Use a separately backed-up recipient key and a dedicated writer whose frontier begins with that queue. The importer never discovers credentials. Selection follows the preflight evidence-name allowlist; it cannot recognize a credential deliberately placed or hardlinked under an allowed evidence name. Inspect the selected inventory before admission. No proof of possession of the recipient private key is built in; test decryption separately before bulk import.

Select an explicit source directory and a stable 32-byte lowercase-hex lineage token. A token identifies your selected source lineage; a same-named repository is not automatically the same source. The default selection is `workspace` (the existing `.kan`/`.claims` allowlist). `store` selects a raw log directory; `identity` selects public `identity/ledger/events` beneath an explicitly supplied config root. Run separate plans for separate roots, using the same aggregate destination as appropriate.

```sh
kan import-plan "$SOURCE_ROOT" --selection store --spool "$QUEUE" \
  --source-id "$SOURCE_LINEAGE_HEX" --recipient "$RECIPIENT_PUBLIC_HEX"
```

Review the inventory, exclusions and unavailable/unsupported notices in the JSON output. Save its `plan.plan` commitment as `PLAN_ID`. A plan includes absolute source provenance and the destination scope/writer/service/recipient, so moving roots or changing the route produces a different plan. It does not depend on queue position or delivery progress. Plan construction hashes selected files and their chunks without changing source data or queue contents. Omitted/unavailable evidence remains omitted; an empty selected inventory cannot establish that the source had no history.

```sh
kan import-v1 "$SOURCE_ROOT" --selection store --spool "$QUEUE" \
  --source-id "$SOURCE_LINEAGE_HEX" --recipient "$RECIPIENT_PUBLIC_HEX" \
  --expected-plan "$PLAN_ID" --key "$SIGNING_KEY" --limit 128

kan spool-drain "$QUEUE" --endpoint "$ENDPOINT" --limit 128
```

Freeze or quiesce the selected directory before planning and resuming. Changes even to excluded entries (such as a new lock file or notes file) alter the committed notices and invalidate the plan. Repeat those two commands against the same pinned source until queue coverage is present and pending import operations are acknowledged. Rerunning `import-plan` reports local progress for its reconstructed plan. Preserve the original expected ID when executing: do not automatically accept a new commitment merely to get past a changed-source error. A new final source delta should be an explicitly reviewed new snapshot.

Each import invocation admits at most the specified number of new operations (1–1024). A full queue or another error stops it without rolling back earlier admitted chunks. Drain the queue, inspect progress and retry; original signed ciphertext bytes remain retained until acknowledgment. A concurrent frontier conflict is also a stop/reconcile condition. The importer never turns an archive retry into an inference call and never drops a rejected head.

The default rich-metadata profile exposes ciphertext sizes and chunk counts; import traffic obfuscation is not implemented. Data chunks are at most 512 KiB; a raw file can exceed the old 10-MiB legacy limit. The plan itself is capped at 32 MiB and 262,144 data chunks; exceeding these limits fails explicitly. The driver rescans the pinned source to detect observed changes and rechecks each chunk before encryption. It does not lock legacy writers, and its repeated scans plus current full-audit queue startup are not qualified for large operational deployments.

The archive contains an encrypted inventory, exact raw source chunks and a final observation. That last record means the importer observed local queue coverage against the selected source. `queue_coverage_complete` relies on owner-trusted operation history. It is not an independently verified copy, a backup, or authorization to erase v1. Another process intentionally forging the importer's deterministic operation IDs, or coherent owner edits/rollback of the spool, can invalidate that local progress interpretation.

An authorized reader must verify signed requests, decrypt the frames, reconstruct and verify the plan commitment, check every chunk and whole-file hash, and retain the stated omissions before claiming recovered evidence. `scripts/verify_import_stream.py` is an independent format/reconstruction oracle for ordered decrypted fixture frames. It requires the expected plan saved from source planning, rather than accepting the stream's own claimed plan:

```sh
python3 scripts/verify_import_stream.py "$DECRYPTED_FRAMES" --expected-plan "$PLAN_ID"
```

The expected hash binds the original source lineage, recipient and route as well as file bytes. Verification remains active under Python `-O` and `PYTHONOPTIMIZE`. The report exposes selected-inventory completeness and all notices, and reports verified selected file bytes separately from transport/claim authentication and cutover. This fixture decoder does not authenticate archive transport. The experimental offline `restore-import` command now performs selected-request authentication and byte reconciliation from an explicit archive; see `docs/V2-RESTORE.md`. Independent-host backup drills, final delta reconciliation and cutover remain required build points.
