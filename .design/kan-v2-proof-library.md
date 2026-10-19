# Feature: proof-aware human Library

## Summary
Continue the approved human frontend and evidence-availability designs: browse
admitted and copied archives even when individual payloads are missing or corrupt.
Use the existing Library, with explicit archive identities and verified navigation.

## Requirements
- REQ-1: Preserve existing legacy Library config and API behavior. Permit an explicitly selected proof protocol alongside legacy scopes, at most 16 configured sources in total. Distinguish archives sharing one scope. Never fall back to legacy on proof-read failure.
- REQ-2: Catalog checks current authorization before showing a source. Keep partial coverage honest and bound the entire per-source snapshot check to five seconds; retain existing four-way waves, socket and request limits.
- REQ-3: Keep signed pins and purpose-bound selection/continuation tokens through Library API and browser navigation. Source and export always reauthorize and freshly verify retained data. Numeric coordinates use decimal strings.
- REQ-4: Render sampled available/missing/corrupt state per row and typed current unavailability in the inspector without invented bytes. Preserve metadata provenance; distinguish issuer attestation, retained historical receipt and current writer verification. Clear previous plaintext on every new read, loss, denial and lock.
- REQ-5: Provide bounded exact source ranges, binary-safe display and real browser download delivery. Keep keys, paths and signing authority outside browser responses, no persistent plaintext, no new storage surface. Preserve dark/system theme and responsive keyboard controls.
- REQ-6: Exercise real CLI/HTTP and mixed-source browsing with both archive profiles, revoked access, loss after inventory, invalid tokens, shared-scope archives, pagination and signed hostile replies. Qualify semantic controls and actual fresh Opus5.5 review before integrated acceptance.

## Acceptance Criteria
- [ ] AC-1: Old config and API tests pass; mixed catalog uniquely selects two archives with the same scope, and unauthorized/failed sources respectively omit/mark partial without disclosure. (REQ-1, REQ-2, REQ-6)
- [ ] AC-2: Pinned next/previous navigation excludes later appends; forged, wrong-purpose or cross-archive tokens fail. Both profiles retain exact receipt provenance. (REQ-3, REQ-4, REQ-6)
- [ ] AC-3: Missing/corrupt tip and middle captures remain browsable after restart; source loss after an Available row clears plaintext and shows typed unavailability with provenance. Revocation on read/export locks the view and delivers no bytes. (REQ-3, REQ-4, REQ-6)
- [ ] AC-4: Actual CLI config produces a usable Library; actual browser receives exact downloadable bytes and shows safe content, dark/system theme and responsive layout. Focused tests, lint and fresh review pass. (REQ-1, REQ-5, REQ-6)

## Architecture
`src/evidence_library.rs` retains its legacy serve wrapper and introduces a
mixed Readers configuration. An explicit source ID selects a configured proof
Reader, never an arbitrary remote endpoint. Legacy entries keep scope IDs;
proof IDs include profile, archive, scope and issuer and occupy a separate
namespace. Catalog version2 adds per-entry protocol/capabilities while legacy-only
serve retains version1. Four concurrent five-second whole snapshot checks per
wave keep 16-source discovery within the existing connection deadline.

ProofPage and ProofSource actions carry the signed Pin plus optional continuation
or required selection Token. The Rust proof Reader validates them. Presentation
returns canonical string ranges and provenance, with no plaintext fields on
unavailable responses. Browser state retains opaque tokens for Previous/Next and
selected rows; each read/download checks current availability and access anew.
No browser pin or token is a current grant. Sources sharing a scope remain distinct.

CLI array entries gain an optional protocol (default legacy), and proof entries
require explicit profile/archive in addition to existing scope/issuer/endpoint/key.
Only configured server-side key files are read. A separate metadata-only proof
read service CLI uses the owner binding and explicit grants; no append command
or writable admission opener is introduced.

Selected Content currently acquires legacy inputs through `evidence_content`.
Proof selected Content must preserve unavailable selections and coverage instead
of silently omitting them. Its adapter remains an explicit next integration in
the overall human Library roadmap, not a claim of semantic completeness here.
Per-source capability labels must expose that limitation. Archive-wide sessions,
search, annotations and owner jobs remain in the approved roadmap.

## Process
This strengthens the existing approved design using day:design, then proceeds to
implementation. Git-first under day#168/kan#197: no live log/key reads, excluded
claim reconstruction or invented witnesses. Day schema/record/bridge validation
is unavailable in this worktree without its own kan workspace; retain the exact
check diagnostic. All acceptance criteria remain open until demonstrated.

## Candidate and operating configuration
The candidate adds `serve-proof` plus mixed `library` configuration and explicit
proof actions in the existing local API. A proof entry is the following shape;
all placeholders here describe owner-supplied values, not generated credentials:

```json
{"protocol":"kan-proof-reader/1","profile":"copied","archive":"64 lowercase hex digits","scope":"64 lowercase hex digits","issuer":"pinned did:key","endpoint":"http://127.0.0.1:7283/v2/read","private_key_file":"/absolute/owner-only/recipient.key"}
```

The config is an owner-only JSON array. Omitted protocol retains the legacy
entry shape; profile/archive are refused on legacy entries. The signer and UI
token are existing explicit owner-only files. `serve-proof ARCHIVE --binding
BINDING.json --signing-key ISSUER.key --grants GRANTS.json` opens metadata without
writer admission. Binding is a closed JSON object with profile/archive/scope/issuer.
It binds to literal loopback by default, with a four-second metadata budget;
items and metadata bytes have explicit CLI ceilings. Restart applies a changed
grants file; this CLI does not promise dynamic file watching or access history.

Author UI checks currently pass 58 tests (52 existing plus six proof scenarios).
Rust/real CLI qualification and independent review are pending. The required
`day design check` refused this worktree's absent kan workspace; the exact error
is in ignored `.local-state/design-check.txt`. This is unavailable validation,
not a passing schema check. No live service has been started or migrated.
