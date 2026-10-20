# Experimental authenticated collector/gateway

The network path is harness → loopback collector → TLS 1.3 gateway → provider.
Use the network example only with private/source-restricted ingress; pending
connection admission remains vulnerable to connection churn, as detailed below.
TLS terminates inside the gateway; do not put a plaintext TLS-terminating proxy
between collector and gateway. The gateway CA authorizes clients for one
instance. Use a dedicated CA and replace configuration/restart for revocation.
Provider TLS uses normal verified HTTPS; plaintext is allowed only for literal
loopback fixtures. No ambient proxy, redirect, idle pooling or automatic retry.

Both observers write encrypted evidence into separate, explicitly provisioned
spools using existing signing keys and archive public recipients. The storage
service receives only ciphertext when those spools are drained. Keep distinct
writer identities/spools for the two observers. Storage failure reports JSON
health with gaps and does not stop inference. An exchange ID joins observations;
it does not certify shared clocks, remote admission or exactly-once inference.
A harness retry creates another exchange and may invoke the provider again.

Build with `cargo build --features v2-crypto --bin kan-v2`. All certificate, key
and token files supplied to these commands must be owner-only regular files
(maximum 64 KiB); parent directories must be trusted. Client identity is PEM
containing its certificate chain and private key. The archive signer is the
existing kan signing key, separate from TLS credentials.

```sh
kan-v2 gateway --listen 0.0.0.0:8443 \
  --certificate server.pem --tls-key server.key --client-ca clients-ca.pem \
  --provider https://provider.example/fixed \
  --spool gateway.spool --key gateway-signing.key --recipient ARCHIVE_PUBLIC_HEX

kan-v2 collector --listen 127.0.0.1:8181 \
  --gateway https://gateway.example:8443/v1/forward \
  --server-ca server-ca.pem --identity collector-identity.pem --token-file local.token \
  --spool collector.spool --key collector-signing.key --recipient ARCHIVE_PUBLIC_HEX
```

POST `/v1/forward` with `Authorization: Bearer <local token>` on the collector.
This generic profile forwards opaque POST bodies and status codes, using
`application/octet-stream`. Provider credentials, protocol-specific headers and
harness paths are supplied by the following harness profile, not this command's
generic default. Do not point a real harness at this body-only route.

Requests are bounded to 16 MiB; responses stream through a 64-KiB application
buffer plus transport buffers. Eight authenticated slots cover verified TLS connections or token-authenticated
local requests through response. Up to 32 pending unauthenticated connections
use a separate queue with at most eight pending connections per IPv4 address or
IPv6 /64. Excess new connections are refused; admitted handshakes are not evicted.
Idle sockets cannot reserve authenticated slots; authenticated overload is refused.
This corrects the previous oldest-eviction churn defect. Shared-NAT clients still
share a pending budget, and multiple sources can saturate the global pool. Use
private/source-restricted ingress until deployment-specific capacity is qualified.
TLS/header reception is limited to
15 seconds, request bodies to 30 seconds, connections to 24 hours. The ordinary
I/O budget is cumulative awaited send/read/write/flush time. Synchronous audit,
crypto, fsync and health callbacks are not hard-latency bounded. Without `--health-journal`, CLI stderr
reporting can block; supervise it with a continuously consumed private log pipe.
The optional durable reporter and operator dashboard are described in
[V2-OPERATIONS.md](V2-OPERATIONS.md).
No payload, token or upstream error details enter health output.

A disconnected downstream aborts its owned forwarding task. Upstream truncation
causes an incomplete downstream response, never a synthesized clean EOF. Bytes
already written may exceed bytes actually consumed by the harness. Completion
means local HTTP body EOF and successful local output flush, not model success,
end-user receipt or remote archive acknowledgment. There is no resume/fallback
inference path. Existing `spool-drain` and continuous `spool-watch` are separate archive-delivery commands.

TLS private keys and provider plaintext exist in gateway memory. The OS, process
isolation, swap, crash dumps and backup policy remain operator responsibilities.
This is experimental software, not a completed production custody/erasure or
capacity qualification. No production deployment or live migration is implied.

`tests/fixtures/gateway-tls` contains intentionally public synthetic test keys.
Never use them for an instance. Tests use only local fake providers.


## Claude Code profile

Select `--profile anthropic` on both commands. Set `--provider` to the provider
origin (for example `https://api.anthropic.com/`), add
`--provider-key-file provider.token` on the gateway, and set `--gateway` to the
TLS gateway origin (without `/v1/forward`). Point Claude Code's
`ANTHROPIC_BASE_URL` at the loopback collector origin and supply the local token
through `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`. Use explicit per-invocation
configuration; do not replace your existing global harness configuration.

This profile accepts `/v1/messages` and `/v1/messages/count_tokens`, with optional
`?beta=true`. It forwards opaque bodies and the open `anthropic-*` and
`x-claude-code-*` header families, plus content type/accept/user agent/request ID.
Response status, end-to-end headers (including provider cache-control), SSE
pings and body bytes are preserved. An absent request content-type stays absent
in this profile; the opaque profile alone supplies application/octet-stream.
Hop-by-hop headers, fields named by Connection, content length (reframed),
cookies and authorization fields are removed. The gateway installs only its
explicit provider API key. Local and provider tokens are not interchangeable.
If both local authentication headers are present, both must match the local token.

KANC2 HTTP metadata observations preserve normalized header names and hex-encoded
values, with credential/cookie omissions named explicitly. `request` records
incoming headers; `request-outgoing` records the built application request after
filtering and credential installation. The gateway names its installed API key
as an omission. This is the constructed request before client defaults, not a full wire-header
attestation: reqwest may add `accept: */*` when absent, as well as generated
framing/host fields. These later additions are outside `request-outgoing`. Individual frame header JSON is bounded to 128 KiB. Large metadata is
serialized as complete normalized HttpMetadata JSON and retained in ordered
HttpMetadataChunk bodies of at most 64 KiB with offset/total coordinates; it
must be reassembled before interpretation. This prevents metadata size from
turning otherwise valid inference into a capture-framing failure. These are library-visible HTTP observations, not packet
captures. TLS peer identities are authorized by the configured instance CA;
this version does not record certificate fingerprints or offer per-client grants.

Compatibility guidance: [Claude Code gateway protocol](https://code.claude.com/docs/en/llm-gateway-protocol)
and [connection configuration](https://code.claude.com/docs/en/llm-gateway-connect).
Unsupported paths fail explicitly. This does not intercept hidden local tools,
files, hooks, cloud-provider variants, OAuth sessions or traffic that bypasses
the base URL. Harness retries remain new attempts and can invoke the provider
again even though kan itself never retries.

The opt-in compatibility witness runs the installed harness in an isolated
configuration with synthetic credentials, no tools/MCP/plugins and a local fake
provider through both hops:

```sh
KAN_CLAUDE_BIN=/opt/homebrew/bin/claude cargo test --features v2-crypto \
  --test evidence_gateway real_claude_code_uses_both_hops -- --ignored --exact --nocapture
```

It verifies a synthetic `KAN_HARNESS_OK` response, not actual model inference.
Normal CI runs the deterministic protocol and TLS fixtures without requiring a
Claude installation. No live deployment or production-key selection is implied.

On macOS, set `KAN_TLS_ORACLE_PYTHON=/opt/homebrew/bin/python3` when the system
Python lacks TLS 1.3. The independent TLS witness fails explicitly in that case.


Capture begins after authentication, route checks and complete bounded request
admission. Rejected or incomplete uploads, failed TLS handshakes, HTTP transfer
framing and trailers are not archived by this profile. Collector and gateway
coverage must be assessed separately; neither observer certifies the other's
missing events. This is an inference API capture profile, not universal network
or harness activity capture.

The synthetic independent witness `scripts/verify_gateway_evidence.py` reads
SQLite/JSON and HPKE with Python, checks both observers against external body
expectations, reassembles metadata chunks and retains unknown event frames. It
is not a production archive reader or independent outer-signature verifier.
The older body-only witness scripts remain scoped to their original fixtures.
Rust `Header`/`Event` are closed typed views: an unknown variant is an explicit
decode failure, never permission to discard the original archived bytes.

## Explicit session relationships

The Anthropic collector profile captures optional `x-kan-session`,
`x-kan-parent-attempt` and `x-kan-transition` headers and forwards them to the
configured gateway. The gateway records them and strips them before the inference
provider. They do not change authentication, routing or inference retries. The
Library interprets these as observer-recorded claims with source citations; see
[V2-LIBRARY.md](V2-LIBRARY.md). Existing `x-claude-code-session-id` capture can
provide session membership without inventing parent/branch relationships. Session
metadata is not proof of the claimed human/assistant identity.

## TypeSafe decision profile

`--profile typesafe` on both collector and gateway exposes only
`POST /v1/systemone`, with no query string or arbitrary destination. Configure the
gateway's `--provider` as an explicit HTTPS origin (for TypeSafe,
`https://api.typesafe.ai/`) and supply its raw API key through the owner-only
`--provider-key-file`. The collector keeps its separate local token and mutual
TLS identity; it never receives the provider key. The gateway creates the provider
Bearer header after stripping incoming credentials. The same credential omissions,
encrypted request/response capture, gap reporting, stream bounds and shutdown
behavior apply. Request bodies and response bytes pass through unchanged; this
profile does not classify or execute the returned decisions.

The Library's `typesafe-system-one` analysis adapter calls the local collector
using its local token. Provider configuration is not supplied by the browser or
extracted from source text. See [typed analysis](V2-LIBRARY.md#background-extraction-and-day-assessment)
for recipe questions, answer validation and exact run history. This profile's
protocol contract comes from the [TypeSafe HTTP documentation](https://docs.typesafe.ai/introduction/quickstart#call-it-the-api);
no live provider request or installation is part of the synthetic qualification.
