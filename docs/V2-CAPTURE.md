# Experimental capture forwarding

`kan-v2 capture-post` forwards one opaque POST to an explicitly configured URL.
It records gateway observations as encrypted, signed local-spool entries. This
is the first P6 transport witness, not a complete harness proxy or a production
provider adapter. No real provider or credential profile has been selected.

Build with `--features v2-crypto`. Initialize a spool as in
[V2-DELIVERY.md](V2-DELIVERY.md), using an existing explicit writer key and the
archive recipient's public key. Then, against your own fixture endpoint:

```sh
kan-v2 capture-post --endpoint http://127.0.0.1:9000/fixed \
  --spool /private/archive/capture-spool --key /private/keys/writer.json \
  --recipient "$ARCHIVE_RECIPIENT_HEX" --deadline-seconds 300 \
  < request.bin > response.bin 2> capture-health.jsonl
```

The paths and public-key variable are examples, not selected deployment values.
The request is `application/octet-stream`; arbitrary headers and authentication
are not supported. The endpoint must be HTTPS or literal-loopback HTTP, without
URL credentials, query or fragment. Captured content cannot change that endpoint.
Redirects, ambient proxies, automatic decompression and reqwest retries are disabled.
Connection pooling is disabled too, preventing hyper-util's pre-wire resend on
a canceled pooled connection when a library caller reuses a Route.
One invocation means one attempt. **Re-running this command is a new inference
attempt**, even when the previous outcome was unknown. To retry only storage,
use `spool-drain`; it sends existing archive events, never provider requests.

Stdout contains only the response body, including non-2xx bodies. Stderr emits
JSON health after each observation: attempt identity, observer, counts of
observed/locally queued/unconfirmed events, recording-gap state, response status
and terminal outcome. It contains no prompt, response bytes, URL or underlying
storage error. Transport/output failure additionally emits a generic error and
returns nonzero. Non-2xx and recording gaps do not themselves cause nonzero exit;
inspect status and recording_gap. Health is volatile and written best effort:
if stderr is closed or the host dies, no monitor can infer missing signals.
A blocked stderr can delay forwarding; callbacks and SQLite admission are
synchronous in this experimental path.

A readable spool whose writer differs from the signing key is a configuration
error and fails before the provider call. Missing/unopenable/full spools do
**not** stop the provider call. An enqueue error
is marked unconfirmed, not definitely lost: an error may follow a durable commit.
The next retained event includes the cumulative preceding unconfirmed count,
and ordinal discontinuities expose missing observations. There is no reserved
control space yet. A restart cannot establish exact coverage for events that
never reached a durable boundary. Locally queued never means remote committed;
remote acknowledgment and backups are separate stages.

Request admission is bounded to 16 MiB per invocation and capture chunks to
64 KiB. Response bodies stream without a total-size cap, awaiting the output on
each subchunk; transport-library buffers are additional. These limits do not
restrict archive lifetime size. The I/O deadline is a cumulative 1–86400-second budget across network/output
awaits, starting after synchronous request capture. This attempt's synchronous
recording and health callbacks run outside that budget. Slow/locked admission
can still extend wall-clock duration substantially, but cannot by itself turn a
fully delivered and flushed response into outcome-unknown. A blocked health
callback can still stall indefinitely; this is not a wall-clock deadline. No latency, physical disk exhaustion or power-loss
qualification is claimed.

The recorded lifecycle is started → request chunks → request end → forwarding
intent → response head/chunks → terminal. Forwarding intent is not proof that a
provider received anything. Completed means body EOF and successful output flush;
it does not mean model success or that the consumer durably stored those bytes.
Disconnect, I/O deadline, output failure or dropping the future gives unknown
provider outcome. Drop attempts a final event; abrupt process termination cannot.
Captured response chunks may include bytes the consumer never received.

KANC2 v2 consists of five magic bytes, a four-byte big-endian JSON header length,
the typed compact JSON header and zero to 65536 exact body bytes. Header fields:
version, attempt (random 32-byte lowercase hex), observer (collector or gateway),
ordinal, observed_at_unix_micros, elapsed_micros, unconfirmed_before and event.
Wall time is the recorder's self-reported UTC observation time in microseconds
(null if the host clock cannot be represented). elapsed_micros is monotonic time
since recorder creation. Neither establishes trusted global time or harness
creation time; stdin has already been read before CLI recording starts. Each
observation samples these clocks before admission. Wall time may move backward.
This correction advances the unmerged KANC1 draft, which omitted clocks. Old
KANC1 bytes remain raw evidence; their missing observation times cannot be recovered. Body offsets count observed entity-body
bytes. Operation ID is the first 16 bytes of SHA-256 over
`tools.kan.capture.operation.v1\0`, raw attempt bytes, observer byte (collector 0,
gateway 1), and ordinal as unsigned big-endian u64. The outer signed request
binds scope/writer; an event does not establish another observer's behavior.
KANC2 IDs do not extend the accepted kan URI grammar.

Only body bytes and the explicit lifecycle fields are covered here. TLS packets,
HTTP transfer framing, arbitrary headers/trailers, expanded attachments, tool hooks
and hidden harness events are not captured. The reusable recorder can be used by
collector adapters, but `capture-post` produces gateway observations only. The
remaining P6 work includes authenticated encrypted collector/gateway transport,
request streaming, the chosen real provider/harness profile, persistent health and
control reserves. Production key custody, independent-host backup drills and
explicit cutover remain required before using v2 as the primary archive.


Capture opens its spool with a 100 ms SQLite busy timeout to tolerate brief WAL
setup contention. Each Recorder allocates at most 100 ms of busy wait per
admission from a one-second allowance, debited only by actual busy-handler sleep. Once spent, immediate admission continues. Failure reports a gap but never
latches off the rest of an attempt; later observations can recover. The scoped handler shares each admission allowance across statements and restores caller policy on unwind. OS sleep overruns remain possible; this is not a hard wall-clock deadline. Startup audit, fsync, crypto and reporting
remain synchronous. Ordinary offline spool operations retain their wait policy.

The gateway branch also fixes concurrent queue preparation: writer reservation,
frontier selection, encryption/signing and enqueue share one IMMEDIATE
transaction. This prevents competing captures from repeatedly signing stale
frontiers. A synchronized 80-request admission fixture checks this directly;
a two-stream fixture checks recorder/queue integration with the normal offline
wait policy, independently of the production capture latency allowance. These are correctness
fixtures, not capacity qualification. Waiting still obeys the capture allowance;
short but repeatedly contended bursts can also exhaust an observation’s wait and yield
visible gaps, but a conflict does not silently discard an entire stream.
