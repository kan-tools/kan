# Feature: Authenticated metadata for unavailable evidence

## Summary
Make missing or damaged payloads visible as individual retained occurrences while
healthy neighbours remain browsable, including after restart. Persist independent
service attestations of exact metadata before relying on them without payloads.
This serves `telos/raw-data-and-projections`: evidence loss is represented, never
hidden by a projection or repaired by inventing historical provenance.

## Requirements
- REQ-1: Retain an independently verifiable issuer attestation binding the exact manifest, receipt, scope, local sequence and preceding admitted frontier. A missing payload must not turn unsigned raw-ledger metadata into authenticated service admission.
- REQ-2: New admission commits metadata and its attestation atomically under the existing audited-frontier transaction fence. Exact retries preserve the original receipt/attestation. No success acknowledges an uncommitted attestation; crash recovery cannot expose half-admitted records.
- REQ-3: Authorized inventory returns each metadata-verified occurrence with explicit available, missing or corrupt payload state. Metadata/signature/partition/frontier corruption remains a whole-request integrity error. Unknown or denied principals see the same access-limited shape before metadata disclosure.
- REQ-4: Startup and pinned reads can verify a complete metadata chain despite absent payloads. Source access always rechecks authorization, selected-snapshot membership, current object hash, retained writer signature and scope decryption; an available marker is a sampled observation, never an offline read grant.
- REQ-5: Upgrade existing archives by an explicit owner-triggered copy into a new profile, preserving original canonical bytes and source files. Verify each retained request before producing a present-time verification attestation; never backdate it or call it historical admission. An already missing un-attested request cannot be upgraded as verified.
- REQ-6: Declare every attestation and index surface, preserve backup/recovery/migration invariants, and distinguish metadata-complete from payload-complete. Rebuildable indexes never establish trust. No implicit erasure, automatic schema rewrite or production archive migration.
- REQ-7: Expose per-occurrence states in the same Library API/UI with source links, coverage and provenance labels. Raw source absence, corruption and unsupported semantics remain distinct. Retained original bytes are never replaced with generated content.
- REQ-8: Qualify atomicity, old/new reader compatibility, hostile raw append, loss at startup/tip/middle, authorization and deterministic whole-fix reversion. Obtain fresh actual Opus 5.5 review before accepting the build.

## Acceptance Criteria
- [ ] AC-1: Delete/corrupt one synthetic payload in a proof-bearing archive; restart and browse its neighbours while the exact retained row remains missing/corrupt. Missing tip and a missing middle record have separate cases. Metadata tampering, foreign scope/issuer, wrong sequence/predecessor and forged signatures refuse inventory. (REQ-1, REQ-3, REQ-4, REQ-7, REQ-8)
- [ ] AC-2: Fault injection and process-death tests around attestation insertion and commit show both metadata/proof or neither; old exact retries preserve byte-identical receipt and proof. Concurrent raw append between audit and insertion still conflicts. Removing attestation binding fails a named assertion. (REQ-1, REQ-2, REQ-8)
- [ ] AC-3: Owner-copy upgrade verifies a pinned source, changes no source file/record bytes, records present-time proof purpose, resumes without changing existing output records, and refuses missing/invalid legacy requests. Old binaries refuse the new profile before writes. (REQ-5, REQ-6, REQ-8)
- [ ] AC-4: Denied/unknown requests disclose no availability, counts or object IDs. Grant revocation between inventory and source/export prevents disclosure; payload loss after an available observation returns explicit unavailable state. Reader rejects modified availability replies and metadata/proof substitutions. (REQ-3, REQ-4, REQ-7)
- [ ] AC-5: Backup/recovery preserve exact proofs and label payload-incomplete outputs; full restore verification continues to reject missing source bytes. Surface catalog, typed mutation capability and fixture/conformance matrix cover every new stored field and index. (REQ-5, REQ-6, REQ-8)
- [ ] AC-6: Real CLI and browser show available/missing/corrupt rows, never fabricated source; provenance distinguishes current writer verification from issuer attestation. New RPC capability negotiation fails explicitly against old servers. Fresh Opus review and compiled assertion-based reversion evidence are retained. (REQ-1, REQ-7, REQ-8)

## Architecture

### Existing boundary that must change explicitly

`src/evidence_store.rs` schema version 1 stores canonical manifest and unsigned
receipt bytes in commits. `Ledger::open` runs full object/binding verification;
`Service::new` and `audit_suffix` in `src/evidence_service.rs` additionally read
and authenticate every retained signed append. Page rechecks objects and Snapshot
rechecks the tip. A missing object can therefore block opening the store itself,
not just a Library page. Removing one Page check is insufficient and would weaken
`.design/kan-v2-service-hardening.md`'s tested admission invariant.

`src/evidence.rs` already defines canonical evidence records and domain-separated
signing preimages, but explicitly does not define a signature envelope or service
admission authority. Specify a separate service-attestation envelope in RFC 4
before implementation; do not silently reinterpret the existing unsigned Receipt.
Register any new module through `src/lib.rs` and keep the payload-independent
verification API separate from full evidence verification.

### Proof contract and atomic admission

Use a versioned, domain-separated issuer-signed envelope over exact manifest CID,
receipt CID, scope, global local sequence, previous sequence/manifest commitment,
issuer, attestation purpose and issued-at time. Define closed field sets, canonical
encoding, safe integer limits, max encoded bytes and signature algorithm in the
protocol update. The predecessor binds service ordering, which the current
per-writer manifest chain alone does not establish. Sequence one names an explicit
empty predecessor. A forked same-height predecessor or a skipped sequence fails.
A proof has purpose `admitted` for new service admission or `retained-verified`
for explicit upgrade verification; those purposes are never interchangeable in
provenance text.

Add a new SQLite profile version with an authoritative attestation per commit,
and only derived lookup coordinates. Within the existing immediate transaction,
check the audited frontier and duplicate identity first. A new service commit
receives the selected sequence and exact receipt, signs that immutable tuple,
and inserts proof together with commit/bindings before commit. A signing failure
rolls the transaction back. Duplicate retries return the stored proof and receipt;
they never mint a different proof for a newly constructed retry receipt. Signing
is bounded local work; no network or historical signature scan occurs under the
write lock. Raw-ledger APIs cannot synthesize service proofs.

Attestations prove what the configured service verified/committed. After payload
loss they do not independently re-prove the original writer signature. The UI
must say issuer-attested metadata and show the proof purpose/time. Full writer
verification still requires the retained signed request. Content trust and claimed
speaker attribution remain separate from either signature.

### Proposed protocol values

The new statement is canonical DAG-CBOR `{v: 1, kind: "service-attestation",
body}`. The closed body fields are `issuer` (existing static Author), `scopeToken`
(32 bytes), `sequence` (positive safe integer), `manifest` and `receipt`
(record CIDs), `previousSequence` (safe integer), `previousManifest` (null only
at the empty predecessor, otherwise record CID), `purpose` (`admitted` or
`retained-verified`), and `issuedAt` (safe Unix milliseconds). Require
previousSequence = sequence - 1. The proof envelope is closed
`{statement: <exact canonical statement bytes>, signature: <64 bytes>}` and its
entire encoding is limited to 16 KiB. The signature input is canonical DAG-CBOR
`{domain: "tools.kan.service.attestation.v1", statement: <statement CID>}`.
Use the existing `sign::Identity` P-256 signer and pinned did:key verification
machinery (64-byte signature encoding); reject unsupported identity versions. This is a proposed new service-purpose signature, not the
existing Receipt signing preimage. Independent codec fixtures must pin exact
bytes/preimages/CIDs and reject noncanonical/duplicate/unknown fields.

Use new signed `InventorySnapshot` and `InventoryPage` commands and corresponding
outputs for the proof-bearing profile. `InventorySnapshot` commits to the metadata
frontier; `InventoryPage` carries metadata/proof/state at that pin. Keep existing
Snapshot/Page/Read outputs unchanged for legacy service endpoints. The reader
configuration explicitly selects legacy or `proof-inventory-v1` per scope; a
configured proof scope never silently falls back after rejection. Catalog scope
entries disclose their verified profile only after that scope check succeeds.
Mixed legacy/proof scopes can coexist, with legacy availability limitations
visible. A schema-1 service cannot advertise payload-independent browsing.

The copy upgrade is a separate CLI operation with a pinned source plan and an
explicit destination and signer. Its plan must name source through/tip, source
profile, issuer, scope, destination profile 2 and recipe version 1. Execution
requires that exact plan, preserves a durable resumable mapping using the same
new authoritative proof table, and refuses differing resume inputs. CLI naming
can follow the existing archive/import command grouping; the complete plan fields
and no-in-place semantics above are required regardless of spelling.

### Read path and availability

Introduce an explicit metadata-inventory capability/RPC; preserve legacy Page/Read
semantics for existing callers. Its signed response binds the requested pin,
contiguous row sequence, exact metadata/proof and sampled payload state. The
reader independently verifies issuer proofs and snapshot linkage before exposing
any row. A proof-bearing prefix may include unavailable payloads but never an
unverified metadata row. A missing proof or invalid metadata chain remains an
integrity failure, not a cosmetic unavailable badge.

Opening for metadata inventory uses a read-only SQLite transaction and verifies
schema/metadata/proof continuity without requiring object existence. It must not
create WAL/temp/copy files or rebuild indexes while browsing. Existing full
`Ledger::open` and full `verify` retain their strict meanings. First implementation
runs damaged archives through this explicitly degraded read-only path; capture
writes remain on the strict writable path until owner recovery restores payload
integrity. Existing proxy spool/fail-open-with-visible-gap behavior covers write
unavailability. This makes the loss visible without quietly weakening writable
store integrity. A later append-while-degraded mode needs its own storage proof.

Availability is sampled from object existence and CID/length verification. Do not
interpret arbitrary I/O/SQLite errors as missing. Metadata corruption, unsupported
schema or inaccessible storage refuse the request. Absence of an object is
missing; existing bytes with the wrong hash/length are corrupt. A source request
revalidates payload and writer signature even if inventory just said available.
A valid object with unsupported semantic content remains available raw bytes.

Add a capability to the Library catalog and a typed inventory row state. Failed
source reads clear the inspector and retain the row's metadata/proof for context.
Counts separately name metadata-verified occurrences and sampled available
payloads; never label their difference erased or lost-in-transit without evidence.
No local cache grants access after revocation.

### Existing archives, backups and recovery

An explicit owner-copy upgrade reads a pinned legacy source, verifies each
retained signed request and all manifest/receipt/partition bindings, and writes a
fresh profile with exact original record bytes and sequence. New attestations
say `retained-verified` at the actual upgrade time. They do not assert that today's
key performed historical admission or that an unsigned historical receipt was
signed then. Missing payloads without existing trusted proofs are a hard failure;
retain the original for later recovery. Do not claim the new design recovers
already-lost ground truth.

Resume binds source snapshot, destination profile, issuer, scope and upgrade
recipe/version, and compares existing records/proofs rather than replacing them.
No in-place schema mutation or automatic conversion on open. Extend backup and
read-only recovery to carry all proof bytes. Metadata-only recovery must visibly
report missing/corrupt payload references and may not pass the existing full
restore contract in `src/evidence_restore.rs`.

Update `src/surface.rs`, `src/persistence.rs`,
`tests/fixtures/read-write-surface.tsv` and `tests/surface_conformance.rs` together.
New proof bytes are authoritative evidence. Indexed issuer/sequence/CID fields
are disposable coordinates checked against proofs, never admission authority.
If the new profile needs another persisted file, its complete WAL/temp/backup
surface must be specified before introducing it; the preferred design retains
one SQLite transaction boundary.

## Resolved Questions
- Payload-independent browsing requires a retained proof, not a blanket removal of payload verification.
- Existing canonical manifests/receipts remain byte-identical. Upgrade adds a new present-time verification statement and preserves the original archive.
- Begin with explicit degraded read-only inventory. Continuing writes into a payload-damaged archive is not silently added to the current strict writable contract.
- The full frontend roadmap remains required. This change cannot reconstruct missing bytes or certify conversation completeness.

## Open Questions
No new deployment/key-placement preference is selected here. The concrete
protocol values above are proposals to be reviewed together with the RFC update,
not existing wire compatibility. Before implementation, the protocol pass must
supply independent exact-byte fixtures and downgrade refusal. This document is
a build contract under development, not an implemented format or satisfied
acceptance criterion. No unresolved owner preference blocks that technical pass.

## Out of Scope
Inference-provider changes, automatic deletion/retention, owner erasure execution,
reconstruction of already-missing bytes, arbitrary SQLite file corruption repair,
append-while-degraded, production migration/cutover and deployment. Search,
normalized conversations, annotations, analysis and admin remain later approved
roadmap work, not cancelled by this storage prerequisite.

## Process record
Grounded in the actual store/service/reader/recovery and surface code after the
Library resilience checkpoint. The main log read still withholds two claims;
raw-data-and-projections is deliberately unwitnessed. No fabricated witnesses,
kan/day writes, production archive reads or build cache in this design worktree.

Validation: read-only `day design check` from the main checkout passes eight
requirements, six criteria, mappings and placeholders. Five branch-only paths
warn because they are absent from main; all exist in this worktree. Two claims
remain withheld. Worktree-local recording remains unavailable under day#168 /
kan#197; Git records are the agreed backfill path.
