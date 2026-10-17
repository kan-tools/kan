# Feature: Complete the explicit legacy inventory surfaces

## Summary

Extend `src/migration_preflight.rs` beyond workspaces containing `.kan`: find publication-only workspaces, inspect explicitly selected log directories, and inventory explicitly selected public identity history. Reports distinguish selected-surface coverage from signature validity and historical completeness. These are read-only prerequisites to encrypted import, not a live migration.

## Requirements

- REQ-1: Discover and preview `.claims` publication-only workspaces as well as `.kan` workspaces without following symlinks or selecting credentials.
- REQ-2: Permit explicit log-directory and system public-identity-history previews. Inventory only known evidence names/extensions; never enumerate credential contents or resolve the user's default identity implicitly.
- REQ-3: Give every notice a typed category and report incomplete selected-surface inventory on failed, changed, unsupported or truncated inspection. Policy exclusions must remain visible without masquerading as errors. File-level observations are not atomic snapshots or proof of historical completeness.
- REQ-4: Preserve byte hashes, source namespaces, original input files and memory bounds, including malformed and larger-than-10-MB evidence. Expose the same distinctions in CLI JSON.

## Acceptance Criteria

- [ ] AC-1: Publication-only discovery/preview returns the original published bytes' digests with no `.kan` creation. (REQ-1, REQ-4)
- [ ] AC-2: Explicit-store preview includes CAR/HEAD/damaged files and excludes a synthetic secret; identity-history preview includes only public CBOR events and never credentials/profiles. Missing selected history reports incomplete. (REQ-2, REQ-3, REQ-4)
- [ ] AC-3: Symlinks, malformed CAR, unreadable files and policy exclusions have typed notices and appropriate selected-inventory status; CLI fixtures agree with the library. (REQ-3, REQ-4)

## Architecture

The public-history allowlist follows `src/identity/ledger.rs`; it never consults `src/identity/system.rs` for credential resolution. Keep `preview` as the workspace interface and add `preview_store` and `preview_identity` for explicit selection. `src/bin/kan-v2.rs` exposes `preview --store` and `preview-identity`. Reports name the selection kind. Public identity events are observations of `identity/ledger/events/*.cbor` under an explicitly supplied configuration root; importing them does not certify their validity or completeness. Workspaces retain a missing-public-history disclosure until a separately selected identity inventory accompanies import.

Every notice carries `excluded`, `unavailable`, `unsupported`, `changed`, or `limit`. Coverage is complete only within the declared allowlist and only when inspection found no non-exclusion notices or CAR scan failures/unsupported hashes. It says nothing about Git history, other stores, unselected identity history, or the trust frame. Inventory source paths remain relative to their selected root; distinct selections are never merged by repository name.

This serves the parent raw-evidence migration and provenance goals in `.design/kan-v2-buildout.md`. The day partial-trust read failure still prevents reliable log backfill; tracked designs are the continuation record.

## Open Questions

None for the local read-only inventory contract.

## Out of Scope

- Upload, decryption, source rewriting, cutover, or automatic selection of global identity files.
- Claim verification, Git-history completeness, or certifying a live directory as an atomic snapshot.
