# Experimental signed service review disposition — 2026-10-17

## Initial review

Fresh Claude Code `claude-opus-5-5`, session `f9f2103b-7c1f-4513-8d23-7418b00c3043`, range `d953afca0d71bb38dec58627235184b437162aa8..ecab2bc7e398bdd7db1e7b3e938929d206cd30c3`. Final report SHA-256 `cb442b4fada6058d831b22a3c277a9b7016bcdd508795d9dce48e2f53eed5f75`. Verdict **APPROVE WITH FOLLOW-UPS**, explicitly static and conditional: tool permissions prevented runtime checks. This does not satisfy the runtime review gate. Private day/telos records were unavailable, not absent. Raw report and metadata are retained privately; no hidden reasoning is published.

The author corrected both substantive findings: seconds-to-milliseconds conversion for immutable receipts, and competing service instances mixing scopes. Service commits now enforce a single scope inside the existing SQLite write transaction. The first commit establishes the binding of an empty partition; startup, snapshot-tip, page and read validation fail closed on foreign evidence. Raw owner access remains outside the service capability boundary. No schema or canonical historical record is rewritten.

Additional witnesses cover exact retry after restart with a still-admitted writer, high-S signature rejection, retained bad signatures, wrong original receipt issuers, changed manifest bindings, unchanged standalone backup hashes across rejected admission, and independent OpenSSL verification of bytes selected directly from backup SQLite. Missing objects referenced by committed service records report corrupt evidence. Four executed runtime negative controls cover request signatures, capabilities, audience and retained issuer binding, followed by restored passing tests.

Remaining follow-ups: bounded startup/capacity qualification; production key/grant-file hardening and custody; retained policy history; orphan staging accounting; local connection starvation and broader transport adversarial probes. Replies have no independent freshness nonce; transient failures cannot establish permanent non-admission. The development listener and opaque fixtures do not establish production readiness or complete P4.

A fresh runtime-capable correction review is required before this slice is recommended for merge.
