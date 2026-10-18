# Authenticated gateway and Claude Code review

Fresh actual `claude-opus-5-5`, session `1615fd80-ae92-4b08-9d7d-80ef7f4e7c7c`.
Range: `9d9e16c04a07489dcab83dbe4dbe888b5e406318..f70f52be23d168b7c813fee18d3d72dcbf28bc18`.
Verdict: **APPROVE WITH FOLLOW-UPS**.

[Exact original report](kan-v2-gateway-2026-10-18.txt), UTF-8 SHA-256 `6a605c14012f97e461303d66ac28b7186a85e7b228989115002431e62e0a8976`.

The review independently verified 10 gateway fixtures, 43 capture fixtures, 11 spool tests, two spool units, delivery/import/migration callers, surface checks, lint, the actual isolated Claude Code smoke and seven runtime mutation controls. Twelve additional hostile probes are retained in [the public probe source](kan-v2-gateway-probes.rs), separate from the implementation tests.

Corrections prepared for fresh review: unauthenticated connection-slot starvation; explicit outgoing request metadata and credential omissions; HTTP header fidelity. Additional evidence work promotes authentication/resource probes and independently decodes both observer spools. Remaining production gates include durable/harness-visible health, source-event adapters, custody/erasure, capacity, backup and cutover. The review does not certify complete P6 or production deployment.

The correction separates pending unauthenticated connections from authenticated
slots, atomically arbitrates promotion/eviction, captures outgoing application
headers and explicit provider-key omissions, and preserves cache-control/absent
content-type in the Anthropic profile. New tests retain TLS-version, duplicate
credential, slot-limit and body-timeout probes; independent Python readback now
checks both normal and actual-harness spools and segmented metadata.

The generated-admission commit fault hooks remain a low-priority follow-up;
existing crash tests cover the shared transaction/storage mechanism but do not
inject at that new entry point. Harness-visible/durable health remains beyond
proxy stderr, and source-event adapters remain open. No claim of full P6 or
DoS/capacity qualification is made.
