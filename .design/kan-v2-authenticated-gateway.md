# Feature: Authenticated collector and gateway transport

## Summary
Continue P6 with a local loopback collector, mutual-TLS transport terminating inside the trusted gateway, and single-attempt streaming provider forwarding. Archive storage still receives only HPKE ciphertext through the existing spool/drain path. This serves the user's server-first raw evidence architecture and telos/raw-data-and-projections; legacy claim/bridge backfill remains pending under the partial view.

## Requirements
- REQ-1: Require TLS 1.3 and client certificates at the gateway, using only explicit trust roots and credentials. The collector authenticates the gateway against its explicit CA and hostname. No plaintext remote listener, ambient proxy, redirect or transport retry.
- REQ-2: Authenticate loopback harness callers with an explicit local bearer token; allow only POST /v1/forward and configured upstream routes. Bound requests to 16 MiB, connections to eight and request reception to 30 seconds. Preserve response status and body bytes, including non-2xx.
- REQ-3: Capture separate collector and gateway observations into their configured encrypted spools. Storage unavailability continues inference with visible local health gaps. Never equate local completion with remote archive acknowledgment.
- REQ-4: Stream with bounded application buffering and backpressure; disconnects abort the owned forwarding task, propagate an incomplete response rather than clean EOF, and never retry inference. Shutdown drops owned connections/tasks.
- REQ-5: Verify real TLS with synthetic CA/client/server credentials, rejected unauthenticated/wrong-root clients, exact binary traffic, recording gaps and disconnect behavior. No production credentials or real provider calls.

## Acceptance Criteria
- [x] AC-1: A real mutual-TLS client succeeds; missing or foreign client identity and wrong server trust fail before provider invocation. Plain HTTP is rejected. (REQ-1, REQ-5)
- [x] AC-2: Two-hop collector→gateway→fake-provider returns exact status/body with separate observer evidence; bad local token, unsupported route and oversized input do not reach provider. (REQ-2, REQ-3, REQ-5)
- [x] AC-3: Missing/locked spools report gaps and do not alter successful response; downstream cancellation and upstream truncation produce unknown outcomes and do not create retries. (REQ-3, REQ-4, REQ-5)

## Architecture
Add `src/evidence_gateway.rs`, reusing `src/evidence_capture.rs`, `src/evidence_spool.rs`, `src/persistence.rs` and `tests/fixtures/read-write-surface.tsv`. Explicit TLS configuration uses rustls, its standard certificate verifier and TLS 1.3 without early data; collector reqwest trusts only the configured CA. The CA is the authorization boundary for this single-tenant experimental instance. Provider credentials are absent in the generic body profile; the accompanying explicit Anthropic profile is specified in `.design/kan-v2-claude-harness.md`. Each HTTP connection serves one request with no idle pooling. Eight permits cover handshake through response. A 64-KiB duplex buffer connects forwarding to the HTTP response body; dropping that body aborts its owned task. Only a successfully completed forward permits clean EOF. Request/response status and encrypted body observations use the existing recorder with the correct observer. A collector-generated random exchange ID is retained as a bounded TransportLink event at both observers, passed only to the gateway and never the provider. This is an observation link, not a uniqueness or cross-observer chronology proof. KANC2 readers must preserve unfamiliar event variants rather than treating them as absence.

A local bearer token protects the literal-loopback collector against unrelated local clients. Explicit secret files must be bounded, owner-only regular files. Configuration and credentials are loaded once; no ambient discovery. Health goes through a caller-provided callback and must remain prompt; no hard filesystem/callback latency guarantee. CLI commands expose listener addresses for testing and administration. Existing archive drain remains a separate command; provider traffic is never an evidence retry queue. Same-host root and the gateway process are trusted plaintext observers. TLS ends inside that process; external TLS termination is unsupported. Disk holds archive ciphertext, while OS swap/crash dumps and process isolation remain operational responsibilities.

## Open Questions
No new decision blocks this generic transport. The accompanying harness profile adds provider credentials and protocol headers; production custody, deployment and cutover remain unselected. Instance CA rotation/revocation uses restart and replacement configuration, not a live multi-tenant control plane.

## Out of Scope
Real provider calls, production deployment, OAuth pass-through, cross-request exactly-once inference, durable replay suppression across harness retries, raw TLS packet capture, full harness hooks, background extraction, main merge and live migration. A harness retry is a new observation/attempt and may invoke the provider again; the proxy itself never retries.
