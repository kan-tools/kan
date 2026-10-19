# Evidence Library

The experimental Library serves real, authorized evidence inventory and exact
source ranges. It is the first browsing slice of Kan Studio. It is not yet the
complete frontend: semantic search, normalized sessions, annotations, saved
views, analysis, administrative jobs and an integrated Operations area remain
required build items. No example or synthetic success is served by this app.

Build with `v2-crypto`. Give the reader a dedicated signing identity with only
`inventory: true, append: false` at each selected service. Keep it separate from
the storage-service signer, capture writers, the inference gateway, and admin
principals. Configure an existing scope decryption key explicitly; the Library
never creates or discovers keys. Location is portable; no production deployment
default is selected by this implementation.

Use an owner-only JSON file containing 1–16 distinct entries:

```json
[
  {
    "scope": "<64 lowercase hex characters>",
    "endpoint": "https://your-service.example/v1/rpc",
    "issuer": "did:key:<storage-service signer>",
    "private_key_file": "/absolute/path/to/existing-32-byte-recipient-key"
  }
]
```

The config, existing signer, raw 32-byte recipient keys and a distinct access
token file are owner-only. Remote endpoints require HTTPS; HTTP is accepted
only on literal loopback. The browser-facing listener requires literal loopback;
remote use goes through an authenticated tunnel.

```sh
kan-v2 library --config /absolute/path/reader.json \
  --signing-key /absolute/path/reader.identity \
  --token-file /absolute/path/reader.token \
  --listen 127.0.0.1:7284
```

Only the address is printed. Open that address and enter the reader access token.
The client stores tokens, pins and displayed content in tab memory only. System,
Light and Dark use the shared appearance controller; only that enumerated
preference is persisted. Lock or page exit clears the client state. This is not
a promise to scrub OS swap, browser internals or previously requested downloads.

The catalog queries current grants before exposing authorized scope pins. Switch
scopes to inspect each scope's own snapshot. Refresh snapshot explicitly to include
newer commits. Inventory pages list committed sequence, manifest and receipt
identities. Signature, service admission and trust in content are separate;
a signing key does not prove the speaker claimed inside captured bytes.

Source reads first recheck membership at the pinned snapshot, then verify the
signed retained request and manifest before scope-bound decryption. Unknown
formats remain inspectable. UTF-8 is shown only if the selected bytes decode
exactly; other ranges show hex. Offsets are half-open byte ranges. The first UI
reads 64 KiB at a time and does not accumulate previous ranges. Download exports
only that range as a `.bin` file after another authorization check, not the full
object or a transcript. No source HTML, external images or attachment scripts
are executed.

Every valid source/page/export read contacts the service before returning data,
so an effective remote grant revocation denies the next read. Malformed and
out-of-range requests can be refused locally without contacting it. To replace local reader keys, scope
selection or browser token, restart the explicitly configured reader; it has no
hidden config watcher or administrative mutation API. Service grant rollout
remains governed by that service's own restart/configuration contract.

Bounds: 40 inventory records per API page, 256 KiB per API source range, 16 KiB
request body, four executing browser connections plus eight queued connections,
a 6-second queue deadline, 5-second header deadline, 3-second body deadline and 35-second overall
connection deadline including queue time. Additional connections are refused;
this is bounded burst handling, not immunity to a hostile local process. A range currently decrypts one bounded
service object in memory. It is not streaming decryption. The current service can fail an entire inventory
page containing a missing or damaged object. Authorization errors lock the view;
other read failures clear the inspector and remain visibly unavailable, allowing
retry or selection of another scope. No failed page is presented as empty success.

Validation and review are recorded with the implementation checkpoint; do not
interpret this runbook as proof that uncompleted acceptance criteria passed.

## Unavailable evidence and safe display

Authorization failures lock and clear the Library. A missing response (404),
verification/server failure, or transport failure clears the source inspector
but keeps other already-authorized browsing controls available. An unavailable
page displays no rows or counts from its failed response. Refresh the snapshot
or select another scope to recover. This does not bypass verification or skip
unreadable rows silently.

The current storage Page RPC verifies referenced objects as it reads records.
A damaged or missing object can therefore make its containing page unavailable;
this first reader does not yet return per-occurrence unavailable-evidence rows.
The service reports absent retained bytes as corruption, so physical absence and
corruption are not independently distinguished by the Library. That remaining
backend contract is required for full browsing coverage.

Directional formatting controls default to hex, like control bytes. An explicit
UTF-8 toggle shows the exact original text; it does not sanitize or rewrite the
source. Byte ranges remain the unambiguous comparison/export representation.

The reader refuses a signing principal equal to any configured storage issuer.
A verified signed access-denial result omits the scope without identifying it.
Unreachable, malformed or unverifiable sources instead produce `coverage: partial`
alongside any successfully authorized scope pins. Failed scope identifiers,
endpoints and counts are not returned in the response body. Response timing can
reveal how many groups contain stalled checks; this profile does not hide timing.
Even if no scope succeeds, partial is
visibly distinct from a completed check with no currently authorized scopes.
The persistent coverage notice survives page/source navigation. **Retry sources**
clears old pins, rows and plaintext before rechecking grants; lock also clears
coverage. A failure while retrying leaves coverage unknown and retry available.

Each upstream signed read has a five-second deadline. Catalog checks run in
groups of at most four (sixteen configured scopes maximum): up to twenty seconds.
A source range requires two calls, up to ten seconds. Queue + header + body +
maximum catalog budget is thirty-four seconds inside the thirty-five-second
connection limit. Scheduling/CPU overhead can still exhaust the whole deadline;
a slow healthy service is temporarily unavailable, never declared absent.
Cancellation drops the in-flight checks. Excess connections remain refused.
The visible capability matrix is populated from the authenticated API; unknown
capabilities are labeled client-unsupported, never presented as working controls.
