# Feature: bounded metadata inventory with explicit payload availability

## Summary
Implement the read-only storage boundary required by
`kan-v2-evidence-availability.md`: verified issuer metadata remains inspectable
when retained payloads are absent or damaged. The owner supplies the exact profile
and archive/scope/issuer pins. This serves `telos/raw-data-and-projections` without
claiming that issuer metadata re-verifies a missing writer signature. The initial implementation has author qualification under
`reviews/kan-v2-inventory-author/` and fresh independent APPROVE WITH FOLLOW-UPS
under `reviews/kan-v2-inventory-opus/`. The type-corruption and test-coverage
corrections have separate author evidence under
`reviews/kan-v2-inventory-followups-author/`; their fresh review remains pending.
No parent frontend criterion is closed.

## Requirements
- REQ-1: Select profile 2 or 3 explicitly, validate its canonical schema and owner binding, and preserve authoritative database and retained WAL bytes. Never invoke writable open, integrity_check over objects, schema repair, immutable SQLite mode, or profile autodetection.
- REQ-2: Verify the complete canonical metadata/proof chain in a pinned read transaction without requiring any payload. Refuse malformed metadata, missing/extra proofs, foreign scope/issuer/archive, invalid sequence/chain/purpose and plan mismatch. Profile 2 remains admitted-only; profile 3 enforces its planned retained prefix and historical receipt issuer.
- REQ-3: Return bounded descending pages anchored to the verified frontier. Every returned row carries exact manifest/receipt/proof bytes and an independently sampled available/missing/corrupt payload state. Metadata errors refuse the whole operation; storage I/O errors never become missing.
- REQ-4: Source selection comes only from a verified occurrence. A fresh read transaction rechecks owner configuration, exact selected proof/records, payload length/hash and retained writer signature. Prior availability and an occurrence selection confer no remote grant.
- REQ-5: Keep startup audit, page work, payload samples and source reads separately budgeted. Bound metadata and object materialization, page count and bytes. Failures and exhausted budgets are explicit, never empty-success results or false coverage.
- REQ-6: Profile-3 recipe metadata status is independent of sampled payload coverage. A metadata reader never calls a damaged or partial archive capture-ready and has no admission API. Bundle-aware APIs remain a different explicit boundary.

## Acceptance Criteria
- [ ] AC-1: Missing tip/middle and wrong-length/hash payloads survive restart as explicit rows; healthy neighbours retain exact metadata and available source. Cases cover both profiles. (REQ-1, REQ-2, REQ-3)
- [ ] AC-2: Valid proofs do not mask wrong owner/profile, metadata/receipt mutation, missing/extra proofs, reordered or mixed-purpose history, mixed historical issuers, or changed profile-3 recipe/membership. (REQ-2, REQ-6)
- [ ] AC-3: A payload removed or corrupted after inventory is refused by fresh source access; exact selected metadata is rechecked against a fork/replacement. Source signatures are verified separately from issuer proofs. (REQ-3, REQ-4)
- [ ] AC-4: WAL-backed reads retain source database/WAL bytes; source coordination sidecars follow the declared read-source boundary. No writable integrity scan touches oversized corrupt objects. Subprocess memory probes bound large-row materialization. (REQ-1, REQ-5)
- [ ] AC-5: Pages stop at bounded count/bytes and exactly the expected predecessor. Bad budgets, early empty pages and cancellation refuse explicitly. A full audit exceeding its configured budget never creates a verified handle. (REQ-2, REQ-3, REQ-5)
- [ ] AC-6: Fresh Opus review and compiled controls demonstrate payload-independent metadata access, source revalidation, purpose/owner binding, limits and no source mutation. RPC authorization, cursors and real Library rendering remain distinct later criteria. (REQ-1, REQ-2, REQ-3, REQ-4, REQ-5, REQ-6)

## Architecture

The provenance and non-destructive projection constraints originate in
`docs/SPEC.md`; the v2 profile contracts below specialize its immutable-evidence
principle without treating disposable query state as authoritative records.

Preserve the raw-data/projection and provenance rules in `CLAUDE.md`. The concrete
reader is `src/evidence_store/inventory.rs`, using proof verification from
`src/evidence_attestation.rs` and explicit profile/binding helpers in
`src/evidence_store/attested.rs` and `src/evidence_store/copied.rs`. Its direct
regressions live in `tests/evidence_inventory.rs`; no fold or semantic log write
is added by this reader.

### Authority and startup

Use a separate owner-side `inventory` type rather than a flag on writable
`Archive`. A constructor takes explicit profile and Binding. The SQLite connection
uses the existing declared read-source capability, installs metadata allocation,
busy-wait and VM cancellation limits before the first SQL read, and starts a read transaction
before reading its profile. Validate the exact schema using bounded schema fields;
do not use the writable `verify_contents` / `PRAGMA integrity_check` path, which
materializes payloads and can encounter oversized WITHOUT ROWID rows.

Startup performs an explicit metadata-chain audit. Scan bounded raw manifest,
receipt and proof envelopes in sequence and verify them against the owner context
and the preceding verified statement frontier. Read-only inventory is ready only
after that audit completes. Startup cost is proportional to retained metadata and
is disclosed; a page does not secretly repeat it. Maintain bounded working memory,
a configured total-record/work budget and explicit cancellation/deadline checks.
The audit does not claim to repeat absent writer authentication or decryption.
It validates issuer attestations and structural metadata, not historical truth.

The pinned handle is a snapshot, not a live grant or freshness assertion. A new
snapshot requires a new audit until an incremental verified-prefix design is
reviewed. RPC startup/job integration must expose that work instead of making the
first browser page wait on an undisclosed whole-archive scan. A later optimization
must preserve the same proof contract and is not part of this first reader.

### Pages and availability

After the startup audit, at most 40 rows are returned newest-to-oldest. The first
row matches the selected expected frontier; each verified proof supplies the next
predecessor. The empty predecessor terminates, never an empty page before genesis.
Return exact proof/record bytes, purpose/time and sampled state. Each manifest in
this service profile must name exactly one bounded retained signed request.

Payload lookup deliberately scans by CID with `NOT INDEXED` / unary `+cid`:
SQLite's WITHOUT ROWID key lookup can allocate a corrupt oversized payload before
its configured value limit applies. The independent child-process memory fixture
checks this boundary, and the indexed-lookup negative control must fail it.
Each sample therefore costs a linear object scan, subject to VM cancellation;
this first implementation does not claim indexed large-archive page latency.

A lookup with no object at its expected CID is missing. An existing object with a non-BLOB SQL storage class, invalid length or hash
is corrupt. Test the storage class before evaluating length or materializing
bytes; corrupt TEXT can otherwise allocate a large value or fail an entire page. A SQLite error, invalid metadata or
unsupported schema refuses the operation. Available means the sampled object
matches its content address and declared length; it is not renewed writer
verification, current authorization, decryption or semantic support. Unknown
content remains available raw bytes when those checks pass.

Storage budgets include count, canonical record/proof bytes and sampled payload bytes; the API
must not promise forty maximum-sized payload hash checks inside a tiny byte cap.
This typed storage API has no wire encoding; the later RPC adapter must separately
bound its encoded response, including routing/selection overhead. Each storage
row has bounded decoded fields and the row-count cap also bounds that overhead.
Either a smaller nonempty page with an exact next frontier fits, or return a named
budget error. Never partially expose a page that failed metadata verification.
Staged orphan objects are outside ordinary occurrence browsing. Owner recovery
has a separate whole-object inventory because a profile-3 recipe also binds them.

### Fresh source access

A verified row yields a typed occurrence selection containing its original pin
and exact row frontier/record commitments. It is not a bearer authorization token.
The storage API is owner-side; the later RPC/reader adapter must authenticate and
check the current grant before disclosing even existence or integrity failures.

Source access uses a fresh bounded read transaction, not the pinned inventory
connection's stale payload snapshot. Verify explicit profile/owner/plan binding,
select the exact canonical row, verify its proof at the selected frontier, and
then check the current payload, original signed request and receipt audience.
For retained-verified rows H may differ from C only after the C proof and plan's
historical issuer are verified. Ordinary admitted rows still address C. No live
Append audience rule changes. Decryption remains the authorized reader's work.

### Copy metadata and recovery

For profile 3, recompute the recipe's original metadata/inventory commitment
without reading payload bytes. Expose a carefully named `recipe_metadata_match`
(complete or partial/unverified) separately from page-local payload observations.
Do not reuse the strict writer's `source_copy_complete` success label for a
metadata-only result. A complete commitment binds expected original object CIDs
and lengths even if some bytes are now absent. A partial inventory cannot prove
it matches an unavailable source; only resumption against the audited source can
establish that relationship. An admitted suffix with a mismatched original recipe
is invalid. None of these states authorizes writable admission.

No recovery ledger or bundle is created by reading. The separately versioned
recovery-bundle design must preserve copy-local loss/resolution history and avoid
standalone-member escape. Its physical schema requires its own independent review
before a writer exists. Missing unattested legacy data remains unrecoverable as
verified provenance; retain original files without inventing replacement claims.

## Integration order

1. Read-only storage type and synthetic boundary qualification.
2. Independently reviewed recovery-bundle encoding/publication design and writer.
3. Explicit proof service mode, signed InventorySnapshot/Page and source RPC,
   current grants, reader cursors/occurrence tokens and proof-aware spool release.
4. Library rows, coverage/provenance labels and real browser/source-download tests.
5. Versioned capture/provider adapters and complete session browsing.

This is a sequence within the approved full frontend roadmap. Search, annotations,
saved views, analysis/day and administration are not cancelled or declared complete.

## Risks and limits

The first full metadata audit can be slow and refuses when its work budget is
exhausted. It is not a large-archive throughput qualification. Arbitrary SQLite
page damage, unknown schemas and inaccessible media may still prevent inventory;
the reader is not a forensic database repair tool. Same-ID forks and privileged
arbitrary rewrites need explicit owner handling; signatures do not establish
cross-host non-equivocation or persistent rollback protection.


### Adapter lifetime and cancellation obligations

The inventory pins a read transaction until its handle is dropped. In WAL mode a
long-lived handle prevents checkpoint progress beyond that snapshot and can grow
the WAL while capture continues. The later RPC/job adapter must enforce bounded
handle lifetime, explicit expiration/reopen, and cancellation of abandoned work;
it cannot retain one inventory forever as an invisible server cache. Map both
explicit budget/cancellation errors and SQLite OperationInterrupted to a bounded
operation failure, without reporting empty results or missing payloads.
