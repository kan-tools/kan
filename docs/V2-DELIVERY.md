# Experimental encrypted delivery

Build with `cargo build --features v2-crypto --bin kan-v2`. This is a manual encrypted delivery path for bounded raw chunks. It is not yet the harness proxy, multi-chunk migration driver or production deployment. Credentials and directories must already exist. Never point an experiment at your only copy of source data.

The writer uses the existing kan P-256 signing-key file format. The archive recipient is a separate X25519 key: the sender only needs its canonical 32-byte public key as lowercase hex. Offline recovery requires the matching raw 32-byte private key in an owner-only regular file. These commands never mint, install or discover keys. Backing up and testing recovery of that private key remains an operator responsibility.

The examples use explicitly supplied shell variables for the queue path, scope token, writer DID, service DID, recipient public key, signing-key file and service URL. Scope is 32 bytes encoded as lowercase hex; operation IDs are 16 bytes encoded as lowercase hex. Select a dedicated writer for a new empty queue. An existing remote writer frontier cannot be adopted by initializing a new empty queue.

```sh
kan-v2 spool-init "$QUEUE" --scope "$SCOPE" --writer "$WRITER" \
  --audience "$SERVICE" --budget 67108864

kan-v2 queue-input "$QUEUE" --key "$SIGNING_KEY" \
  --recipient "$RECIPIENT_PUBLIC_HEX" --operation "$OPERATION_HEX" < event.bin

kan-v2 spool-status "$QUEUE" --operation "$OPERATION_HEX"
kan-v2 spool-drain "$QUEUE" --endpoint "$ENDPOINT" --limit 128
```

`queue-input` performs no network I/O. Its success means the encrypted signed request is durable in the local spool; it does not mean the server has acknowledged it. Input is limited to 1,048,481 bytes, including binary and empty input. Oversized input fails instead of silently truncating or splitting it. Larger event segmentation and a durable source plan will be supplied by the migration/capture drivers.

Preserve each operation ID before attempting admission. If the process exits or output is lost, inspect that operation. A known operation is either pending or locally acknowledged. Reusing an operation in `queue-input` fails, even for identical input: fresh encryption is not an exact-byte retry. An unknown operation can be retried against the retained source after the failed producer has exited. Concurrent producers can lose the frontier race and must reconcile before retrying; status is not a reservation. Operation lookup proves retained identity, not equivalence to an arbitrary source file. The CLI reads operation details and queue totals separately, so concurrent draining can make them reflect different instants; re-read after concurrent work settles for reconciliation.

`spool-drain` needs neither signing nor recipient private keys. It sends only the retained request and trusts the destination identity bound into the queue. It emits one JSON progress line per locally committed acknowledgment, followed by queue status. Any transport error, signed rejection, conflicting concurrent acknowledgment or reported output error stops the command. A broken pipe is detected, but an already-closed stdout descriptor can exit successfully without output; inspect operation status after any uncertain result. Previously acknowledged progress remains committed. Repeat the drain after reconciliation; never delete the head or recreate the queue to make an error disappear. A permanent rejection needs explicit writer/queue recovery, which this command does not automate.

The budget limits pending signed-request bytes, not total filesystem allocation. SQLite journals, lifetime operation metadata and the latest acknowledgment consume additional space. Startup still audits history. These commands do not establish large-scale performance, power-loss recovery, independent backup or anti-rollback protection against the local owner.

For offline inspection of a still-pending request:

```sh
kan-v2 spool-head "$QUEUE" > retained-request.json
kan-v2 decrypt-request retained-request.json --recipient-key "$RECIPIENT_PRIVATE_FILE" \
  --scope "$SCOPE" --writer "$WRITER" > recovered-event.bin
```

`spool-head` emits exact signed bytes and never removes them. `decrypt-request` verifies the signature, explicit scope/writer pins and authenticated encryption before writing any plaintext. The writer pin identifies the outer request signer, not who originally encrypted or authored the plaintext: another writer can copy ciphertext within the same scope and sign a new wrapper. Signature validity does not establish historical service authorization. Redirection creates files under your shell's permissions; use an owner-only directory and appropriate umask for plaintext. The server's separate `rpc` read capability can return retained requests after local dequeue; extracting those bytes requires parsing the signed response, not treating the response itself as an encrypted request.

Service endpoint restrictions, issuer verification, bounded response handling and explicit signed access grants are inherited from the service transport. No environment proxy or redirect is followed. The built-in development listener remains loopback-only. Production service configuration, recovery-key custody, provider forwarding and visible capture-gap signaling remain subsequent build points.

## Managed erasure and restored queues

Enroll every managed sender with the independently retained, pinned owner custody
configuration for its admitted archive. Keep this configuration outside spool
backups. The same owner history must govern ingest and read services. For example:

```sh
kan-v2 spool-drain "$QUEUE" --endpoint "$ENDPOINT" \
  --erasure-history "$ERASURE_CONFIG" --limit 128
kan-v2 spool-watch "$QUEUE" --journal "$JOURNAL" --endpoint "$ENDPOINT" \
  --erasure-history "$ERASURE_CONFIG"
kan-v2 spool-status "$QUEUE" --operation "$OPERATION_HEX" \
  --erasure-history "$ERASURE_CONFIG"
```

`spool-head`, `queue-input` and the import commands also accept
`--erasure-history`. Annotation outbox JSON accepts an optional `erasure_history`
Access object with `directory`, `binding`, `owner` and pinned `minimum`, matching
the independently initialized custody configuration. Enrollment survives a queue
restore because it is supplied by the operator, not loaded from the queue.
Missing or incompatible custody refuses managed content operations.

An operation selected by current custody is reported as `erased`, even before
local physical cleanup. A managed sender refuses to export or replay it and
rejects a delayed acknowledgment for it. Delivery keeps a custody lease through
the network exchange; new owner authorization must retry while a prior send is
in flight. Unaffected requests ahead of selected requests remain deliverable.

To reconcile a stopped sender explicitly:

```sh
kan-v2 reconcile-spool-erasure "$QUEUE" --erasure-history "$ERASURE_CONFIG"
```

This removes ciphertext retained in selected admitted pending requests and the
last acknowledgment. It preserves minimal signed authorization and canonical
manifest commitments sufficient to continue the writer's chain. The first such
cleanup upgrades the queue to profile 3; earlier binaries refuse to reopen it.
A selected pending request behind an unrelated predecessor remains deferred;
deliver the predecessor with current custody and retry cleanup. No acknowledgment
or admission is invented. Managed delivery also performs this safe retirement
when the head or last acknowledgment is selected.

Page reclamation, offline backup purge, unpublished cancellation and published
derivative cleanup have separate statuses. A reconciled admitted queue alone is
not evidence of complete cross-store erasure. Retain any backup until its owner
explicitly authorizes deletion; do not activate it through an unenrolled sender.

## Annotation source guards

An annotation sender also needs the current custody of its **sources**, which
may be different archives from its publication destination. Supply
`--publication-guard GUARD.json` to `spool-head`, `spool-drain` or `spool-watch`.
The configuration contains absolute `database`, `signing_key` and `recipient_key`
paths for its encrypted reader workspace, plus `sources`: the independently
pinned erasure Access objects covering every source citation and known ancestor.
Keep this configuration independent of workspace and queue backups.

```sh
kan-v2 spool-drain "$QUEUE" --endpoint "$ENDPOINT" \
  --erasure-history "$DESTINATION_CUSTODY" \
  --publication-guard "$SOURCE_GUARD" --limit 128
```

Library annotation queueing records an authenticated binding from the exact
signed request to its annotation before the queue commit. The binding is
encrypted in the workspace and joins source-dependent erasure cleanup. Managed
senders check that binding, the retained annotation and correction/analysis
ancestors, and hold current source custody through delivery and acknowledgment.
They need the workspace key, not the destination's decryption key.

A missing binding, missing ancestor, uncovered source, erased dependency or stale
restored workspace refuses publication. An old operation ID alone cannot
authorize substituted ciphertext. Old queues without bindings require explicit
reconciliation; enabling the guard does not invent their source provenance.
Guarded head export also refuses before writing request bytes. The traversal is
bounded to 4,096 ancestors, 8 MiB of declarations and five seconds per attempt;
refusal leaves the original queue intact. Ordinary capture/import queues use
their destination custody and are not annotation publication queues.
