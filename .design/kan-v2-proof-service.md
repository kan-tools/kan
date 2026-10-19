# Feature: authenticated proof-aware archive reads

## Summary
Expose admitted and copied archive metadata through a signed, explicitly
selected read protocol that remains useful when payloads are unavailable.
This implements the remote-read portion of the approved evidence-availability
and full human Library design. It grants no append, recovery-job or key authority.

## Requirements
- REQ-1: Every request binds protocol version, owner-selected profile/archive/scope/issuer, principal, expiry and command. Canonical signatures use a separate proof-read domain. Unknown/revoked principals and expired or foreign requests fail before archive access.
- REQ-2: Capabilities explicitly identify the proof-read protocol and operations. Snapshot, descending page and source operations never silently fall back to legacy ascending reads. Canonical decimal strings carry browser coordinates.
- REQ-3: Each page reopens a retained selected frontier, audits the full current metadata chain and verifies its continuation. Later appends are excluded; rollback, fork and corruption beyond the selected pin fail. Return exact manifest, receipt and proof bytes with sampled availability.
- REQ-4: Source reads reconstruct selections through verified metadata, then freshly check payload hash and retained writer signature. Missing/corrupt payloads are typed results. A prior Available sample confers neither access nor continued availability.
- REQ-5: Keep issuer signing keys and local paths in the service. Enforce request, serialized reply, work, row and payload bounds. Reuse the transport's no-store, bounded worker and endpoint policies when integrating HTTP. Preserve existing v1 wire behavior.
- REQ-6: Qualify both profiles, copied historical provenance, canonical signatures/coordinates, current permission changes, unavailable payloads across restart, concurrent append and adversarial reply validation. Require fresh actual Opus5.5 review at the integrated checkpoint.

## Acceptance Criteria
- [ ] AC-1: Signed request/reply tests reject noncanonical bytes, altered binding/command, wrong signatures, unknown/revoked principals and expiry, with denial before metadata access. (REQ-1, REQ-2, REQ-6)
- [ ] AC-2: Both profiles return a signed snapshot and descending pinned pages with exact proofs; appends, forks, rollback and current metadata corruption have the specified behavior. (REQ-2, REQ-3, REQ-6)
- [ ] AC-3: Missing/corrupt evidence remains browsable, while source reads return its current typed state and available source retains verified historical writer provenance. (REQ-3, REQ-4, REQ-6)
- [ ] AC-4: HTTP enforces bounds/no-store/access and unchanged legacy behavior; Reader verifies capabilities, pins, every proof and next cursor before rendering or decrypting. (REQ-1, REQ-2, REQ-5, REQ-6)
- [ ] AC-5: Browser checks cover available/missing/corrupt records, stable navigation and actual download delivery. Semantic controls, focused tests, strict lint and fresh independent review pass. (REQ-4, REQ-5, REQ-6)

## Architecture
`src/evidence_proof_service.rs` owns the proof-read wire contract and a service
configured with one explicit archive binding, issuer identity, current grants,
path and resource budget. Protocol version2 uses separate signing domains and
will use `/v2/read`; legacy `/v1/rpc` and its envelopes retain their meaning.
Capabilities name `kan-proof-reader/1` and the exact read operation set. Replies
bind the hash of the entire canonical signed request. No request selects a
filesystem path or server-side identity.

Wire frontiers contain a decimal through-coordinate and canonical manifest and
attestation CIDs; the request's explicit binding supplies archive/scope/issuer.
The empty frontier has neither CID. Source selections are reconstructed by
`Inventory::open_at` plus a verified one-row `page_from`; no JSON-to-Selection
shortcut is added. A snapshot includes the exact copy plan for profile3 so the
Reader can distinguish retained historical receipts from current admission.

Each command checks current grants before opening metadata. Metadata-only
startup is intentionally insufficient for admission, and the read service has
no append command. Source bytes remain encrypted on this service boundary;
scope decryption stays in the authorized local Reader. Present-time writer
verification and issuer-attested purpose remain separate fields in the UI.
One monotonic deadline spans a command's metadata opening, page verification and
fresh source sampling. Item and metadata-byte budgets bound each of those passes
separately; a source command can perform three bounded passes. These limits do
not promise to preempt blocked filesystem calls or bound exact allocator RSS.

The local Reader must not accept arbitrary browser frontier JSON as verified
continuation or selected membership. It verifies pages from the authenticated
snapshot, then issues signed continuation/selection tokens binding the exact
snapshot hash, explicit archive binding, reader principal, purpose and next or
selected frontier. Each later call verifies that token before contacting the
service. Page and source token purposes are distinct. These tokens attest only
to prior local verification; they are not grants, so every call still performs
current remote authorization and every source read freshly checks its bytes.
This avoids holding transactions between clicks or repeatedly embedding the
whole prior page chain in browser requests. The Reader signing key stays local.

## Status and integration boundary
This is a continuation of the approved design, recorded Git-first under
day#168/kan#197. No live log/keys or excluded claims are read or reconstructed.
All acceptance criteria remain open. The first code checkpoint implements the
wire/service layer; HTTP, Reader and Library acceptance must follow before
claiming a complete human browsing path. Archive discovery, annotations,
background processing and owner jobs remain in the overall v2 roadmap.

The service/wire, shared HTTP adapter and verified Reader candidates are now on
disk. Seven service tests, a real loopback transport test and five Reader tests
cover both profiles, exact encrypted source decryption, faulty signed replies,
tokens, revocation and later payload loss. Author qualification at bdbf136 passed
82 integrations, strict all-target v2 Clippy and formatting; see
`.design/reviews/kan-v2-proof-service-author/`. Independent review remains pending. The human Library integration is still open.
`day design check` refused this worktree because it has no separate kan workspace;
the exact diagnostic is retained in `.local-state/design-check.txt`. Validation
and kan/bridge recording remain unavailable, not passing or an empty log.
