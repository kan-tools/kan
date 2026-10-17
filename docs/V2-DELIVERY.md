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
