# Feature: Claude Code Anthropic Messages capture profile

## Summary
Complete the requested first real harness integration on the authenticated collector/gateway branch. Claude Code talks to the loopback collector using an explicit synthetic/local gateway credential; the gateway substitutes an explicit provider API key. Preserve opaque JSON/SSE and protocol metadata without parsing or rewriting model content. This serves telos/raw-data-and-projections and the user's server-first capture goal.

## Requirements
- REQ-1: Add an explicit Anthropic Messages profile alongside the generic body profile. Accept only POST /v1/messages and /v1/messages/count_tokens, optionally beta=true; require fixed origin configuration. Never derive a destination host from harness content.
- REQ-2: Authenticate local callers through x-api-key and/or Authorization with exact explicit-token matches. Strip local credentials before remote forwarding and install a separately configured provider key only at the gateway. No OAuth or ambient credential discovery.
- REQ-3: Preserve request bodies, streaming response bodies/status, open anthropic-* and x-claude-code-* request headers, and end-to-end response headers. Remove hop-by-hop headers and nominated Connection fields. Capture normalized HTTP metadata with explicit credential omissions, observer-local clocks and exchange links; no full raw-wire claim.
- REQ-4: Exercise the installed Claude Code executable in an isolated configuration against a local synthetic provider through both collector and mutual-TLS gateway. Verify observed request provenance and a recognizable final harness result. Do not use a real provider account or production credentials.

## Acceptance Criteria
- [x] AC-1: Representative opaque Messages JSON, SSE events/pings, non-2xx bodies, beta/version/custom capability headers and count-token routing survive both hops exactly; unsupported paths/query values fail before provider. (REQ-1, REQ-3)
- [x] AC-2: Synthetic local credential is absent at provider; gateway uses only the explicit synthetic provider key. Wrong/ambiguous credentials fail before forwarding. Encrypted metadata records omit secret values explicitly. (REQ-2, REQ-3)
- [x] AC-3: A retained opt-in test invokes the actual installed Claude Code with isolated settings, no tools/MCP/plugins/session persistence, synthetic credentials and local base URL, and gets the fixture's expected result. Logs report version and synthetic-provider limitation. Normal CI runs deterministic protocol fixtures without requiring Claude installation. (REQ-4)

## Architecture
Extend `src/evidence_gateway.rs` with an explicit profile and path/header policy, `src/evidence_capture.rs` with bounded HTTP metadata observations and status/header output, and `src/bin/kan-v2.rs` with profile/provider-key flags. Existing `src/persistence.rs` and `tests/fixtures/read-write-surface.tsv` remain unchanged: all archive writes use the existing encrypted spool. Header names are HTTP-library normalized; transfer framing, TLS packets, credentials, cookies and local harness-only events are outside this observation boundary. Credential omissions are recorded as omissions, never fabricated raw values. Body bytes are not parsed, normalized, summarized or recoded.

Official compatibility guidance consulted 2026-10-17: https://code.claude.com/docs/en/llm-gateway-protocol and https://code.claude.com/docs/en/llm-gateway-connect . The profile passes open protocol header families and opaque bodies to avoid baking current capability values into the gateway. Independent provider/HTTP fixtures verify wire behavior. A real harness smoke test is a compatibility witness using a synthetic provider response, not real inference or complete coverage of every Claude feature.

## Open Questions
Claude Code is the initial profile after the optional harness-choice question received no answer during independent work. The user can select additional profiles afterward. Production API key custody, deployment, backup/cutover and broader harness event adapters remain open; legacy design-record/bridge backfill remains pending under the partial-trust limitation.

## Out of Scope
Real paid provider calls, OAuth forwarding, Codex/OpenAI or cloud-specific Anthropic profiles, model discovery, full filesystem/tool/hook interception, bypass traffic that ignores the configured base URL, deployment, main merge and live migration. Unsupported requests fail explicitly rather than silently escaping the collector.
