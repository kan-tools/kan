# Feature: Authenticated opaque service boundary

## Summary

Add a versioned, bounded signed request/reply boundary over `src/evidence_store.rs`, with independently granted append and inventory capabilities. Persist the original signed append request as the referenced opaque object so transport authentication does not disappear after admission. Keep payload encryption and key custody outside the blind store; this build point uses opaque fixtures and does not claim production encrypted capture.

## Requirements

- REQ-1: Authenticate canonical request bytes using an explicitly admitted static did:key principal; deny unknown principals, scopes and capabilities before consulting evidence. Inventory authorization is independent of append authorization and consumer trust.
- REQ-2: Preserve exact signed append requests, bind scope, operation, writer position/predecessor and opaque bytes, and return the original committed receipt on exact retry. Changed content under the same operation conflicts without replacement.
- REQ-3: Bound requests, payloads and pages; return typed invalid, access-limited, conflict, missing, corrupt and unavailable states. Read authentication expires; immutable signed append requests remain retryable after offline spooling.
- REQ-4: Sign replies over the exact request commitment, result and issuer. A client pins the expected service identity; another request's response or an edited response must fail verification.
- REQ-5: Open a partition only after validating existing committed request signatures and their manifest bindings. Reject mixed-scope or foreign-format partitions without altering their authoritative bytes. Historical signature validity is independent of current grants.
- REQ-6: Keep all persistence through the existing ledger commit owner and retain v1 behavior. A service partition may cover many encrypted project annotations; distinct routing scopes use distinct partitions beneath a centralized installation.

## Acceptance Criteria

- [ ] AC-1: Capability matrix proves append-only cannot read, inventory-only cannot append, unrelated scopes/principals are denied without evidence disclosure, and revocation does not erase historical evidence. (REQ-1, REQ-5)
- [ ] AC-2: Restart, lost-reply retry, changed-content conflict and stale-predecessor tests preserve exact request and receipt bytes and one committed occurrence. (REQ-2, REQ-6)
- [ ] AC-3: Invalid signatures, noncanonical JSON, duplicate/unknown fields, expired reads, oversized payloads/pages and corrupt persisted requests fail with explicit states. (REQ-3, REQ-5)
- [ ] AC-4: Independently inspect stored request bytes and verify response request-binding, issuer pinning and signature failure after mutation. (REQ-2, REQ-4)

## Architecture

`src/evidence_service.rs` will own the pure wire contract and partition dispatcher. `src/sign.rs` provides existing did:key signing/verification; this is an explicit initial service credential profile, not a reinterpretation of imported authors or a replacement for RFC 1 system identities. The profile's limitations remain explicit in `rfcs/4-evidence-contract.md`.

Wire version 1 uses exact compact JSON emitted by the declared ordered Rust structs, ASCII lowercase hex for byte strings, no unknown fields or duplicate fields, and no alternate serialization accepted. Signatures cover a domain prefix plus the SHA-256 of the canonical unsigned request. A signed append request is retained byte-exactly in one existing opaque object. Its coordinates determine a canonical RFC 4 manifest; the slot is the SHA-256 of its operation bytes. The receipt is generated only by the service and committed with that manifest. Replies sign their exact unsigned canonical bytes and bind the incoming request hash. The service receipt's original canonical bytes survive key changes; response signatures certify the serving instance and do not retroactively certify original receipt signatures.

One append accepts at most 1 MiB opaque payload, and one page at most 128 records. Read requests expire within five minutes. Replay of immutable append is deliberately allowed through the existing operation conflict boundary; clients must spool the exact signed bytes. Unknown clients and scopes receive access-limited uniformly, including for absent objects. Retrieval is by committed sequence, so orphan staged objects are not exposed as events.

One partition holds one routing scope. Startup audits retained signed requests and checks every manifest/receipt binding before serving it. This currently inherits full-history startup verification from `src/evidence_store.rs`; the bounded-startup and 10/100-GiB qualification remain open P3 work and are not hidden by this interface. The service has no decryption method or key field. The caller supplies ciphertext; blind storage cannot attest that a caller encrypted its bytes correctly.

Grants are explicit owner-supplied runtime policy. This boundary does not yet preserve signed grant history, implement key rotation, expose a network listener, or establish encrypted client/gateway transport. Those remain dependent P4 work. No global configuration, keys or live archive are created by these APIs. Day recording remains unavailable because of the existing partial-trust read limitation; backfill this tracked design later.

## Open Questions

Production owner-key custody, recovery package and the initial operating profile remain pending the user's answer. They do not block this encryption-independent request and capability contract.

## Out of Scope

- Claiming encrypted capture, a production network service, historical admission-policy proof or operational readiness from opaque fixtures.
- Importing user data, deploying, selecting global identity keys, changing trust, or changing existing evidence record bytes.

## Loopback transport extension

Expose the same dispatcher through an experimental `v2-service` feature. `src/evidence_http.rs` uses Hyper HTTP/1 with bounded bodies, 16 active connections, one request per connection and timeouts. The built-in listener accepts loopback addresses only. A client permits HTTPS or literal loopback HTTP, disables redirects/proxies and verifies the pinned service signature and request commitment. No unauthenticated health endpoint reveals archive contents. Network errors remain errors; RPC errors remain signed typed results. Service restart reads explicit owner-selected grants and signing credentials, never resolves a default identity.

CLI `serve`, `sign-request`, and `rpc` expose these primitives. None encrypts payloads, mints keys, or imports user data. `sign-request` reads a bounded JSON request from stdin and signs using an explicitly selected owner-only key. `rpc` sends an already signed request and emits a verified signed reply. Limits apply before JSON parsing and before response accumulation. Request bodies and internal errors are never logged.

Transport acceptance witness `http_roundtrip_and_rejections`: exercise real loopback HTTP, exact retry, wrong issuer, wrong route, invalid/oversize bodies and denied grants; verify that the same library request has the same durable result. TLS reverse-proxy deployment, encrypted payload generation, persistent grants and remote-host operation remain unqualified. This listener is a development/API boundary, not a production remote service claim.

Implementation references: [Hyper server API](https://hyper.rs/guides/1/server/hello-world/) and [bounded HTTP bodies](https://docs.rs/http-body-util/latest/http_body_util/struct.Limited.html). Dependencies remain pinned by Cargo.lock; no wire behavior depends on an unpinned documentation version.
