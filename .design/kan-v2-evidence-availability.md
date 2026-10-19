# Feature: Authenticated metadata for unavailable evidence

## Summary
Make missing or damaged payloads visible as individual retained occurrences while
healthy neighbours remain browsable, including after restart. Persist independent
service attestations of exact metadata before relying on them without payloads.
This serves `telos/raw-data-and-projections`: evidence loss is represented, never
hidden by a projection or repaired by inventing historical provenance.

## Requirements
- REQ-1: Retain an independently verifiable issuer attestation binding the exact manifest, receipt, archive identifier, scope, local sequence and preceding admitted manifest and attestation-statement frontier. A missing payload must not turn unsigned raw-ledger metadata into authenticated service admission.
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
- [ ] AC-3: Owner-copy upgrade verifies a pinned source, changes no source file/record bytes, records present-time proof purpose, resumes without changing existing output records, and refuses missing/invalid legacy requests. Legacy binaries refuse logical record/schema writes to the new profile; released read-write SQLite openers may checkpoint an existing WAL before refusing, so this is not a physical-media no-write guarantee. (REQ-5, REQ-6, REQ-8)
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
receipt CID, scope, global local sequence, previous sequence/manifest/attestation-statement commitments,
issuer, attestation purpose and issued-at time. Define closed field sets, canonical
encoding, safe integer limits, max encoded bytes and signature algorithm in the
protocol update. The predecessor binds service ordering, which the current
per-writer manifest chain alone does not establish. Sequence one names an explicit
empty predecessor. A forked same-height predecessor or a skipped sequence fails. The statement CID
also commits to receipt, purpose and time, so a snapshot cannot silently substitute
a different valid statement for the same manifest.
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
body}`. The closed body fields are `issuer` (existing static Author), `archiveId` (32 bytes), `scopeToken`
(32 bytes), `sequence` (positive safe integer), `manifest` and `receipt`
(record CIDs), `previousSequence` (safe integer), `previousManifest` and `previousAttestation` (both null only
at the empty predecessor, otherwise record CIDs; the latter is the preceding
statement CID, not an envelope hash), `purpose` (`admitted` or
`retained-verified`), and `issuedAt` (safe Unix milliseconds). Require
previousSequence = sequence - 1. The proof envelope is closed
`{statement: <exact canonical statement bytes>, signature: <64 bytes>}` and its
entire encoding is limited to 16 KiB. The signature input is canonical DAG-CBOR
`{domain: "tools.kan.service.attestation.v1", statement: <statement CID>}`.
Use the existing `sign::Identity` P-256 signer and pinned did:key verification
machinery (64-byte low-S r||s signature encoding); reject DER, high-S, non-P-256
keys, noncanonical did:key encodings and unsupported identity versions. The
verification method must be the exact principal plus its fingerprint fragment.
This is a proposed new service-purpose signature, not the
existing Receipt signing preimage. Independent codec fixtures must pin exact
bytes/preimages/CIDs and reject noncanonical/duplicate/unknown fields.

Use new signed `InventorySnapshot` and `InventoryPage` commands and corresponding
outputs for the proof-bearing profile. `InventorySnapshot` commits to `(archiveId, through, tip, attestation)` where tip is the
manifest CID and attestation is the statement CID; genesis is `(archiveId, 0, null, null)`.
This anchors exact receipt/purpose/time as well as the manifest. The statement
CID is stable across alternate valid ECDSA signatures; exact retry still returns
the stored signature bytes. `InventorySnapshot` commits to that metadata
frontier; `InventoryPage` carries metadata/proof/state at that pin. Keep existing
Snapshot/Page/Read outputs unchanged for legacy service endpoints. The reader
configuration explicitly selects legacy or `proof-inventory-v1` per scope; a
configured proof scope never silently falls back after rejection. Catalog scope
entries disclose their verified profile only after that scope check succeeds.
Mixed legacy/proof scopes can coexist, with legacy availability limitations
visible. A schema-1 service cannot advertise payload-independent browsing.

The copy upgrade is a separate CLI operation with a pinned source plan and an
explicit destination and signer. Its plan must name source through/tip, source
profile, historical receipt issuer, current service issuer, scope, fresh destination archiveId, destination profile 2 and recipe version 1. Execution
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
schema/metadata/proof continuity without requiring object existence. Reuse the
explicit read-source boundary of `RecoveryReader::open`: no schema/index repair,
checkpoint, evidence write or plaintext copy. SQLite may initialize coordination
WAL/SHM sidecars; declare those exact physical surfaces and capability at the open
site, as the existing recovery reader does. Read-only media without usable
sidecars and hot rollback journals fail closed. Never use immutable mode to
silently ignore a live WAL. Crash recovery belongs on an explicit separate copy.
Qualification must distinguish unchanged authoritative database/retained WAL
bytes from permitted coordination-file changes. Existing full `Ledger::open` and
full `verify` retain their strict meanings. First implementation
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
Production credential placement and live cutover remain owner-controlled deployment
choices. The build uses synthetic identities only. The protocol fixes one current
service issuer per destination archive: the copy job runs on that service host
using its configured signer, so the design requires no private-key export to a
remote CLI. Historical receipt issuers remain unchanged. The first Opus design
review blocked the original proposal; its report and probes are retained under
`.design/reviews/kan-v2-evidence-protocol-opus/`. The correction below requires a
fresh review before storage integration. No runtime acceptance criterion is closed.

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

## Protocol preparation evidence

The proposed RFC 4 section now fixes statement-CID chain/snapshot commitments,
low-S P-256 signature encoding and downgrade refusal. Independent fixtures use
public test private scalar 1 and synthetic existing RFC 4 metadata; no actual
service admission or production identity is involved. Run the checker with the
existing crypto-oracle Python environment (cryptography 46.0.3); `--check` does
not rewrite fixtures and `--write` is explicit regeneration. The initial Opus review returned BLOCK; the correction retains that report and
adds archive/issuer/page-linkage rules plus labelled negative vectors. Rust parity,
a fresh correction review and the complete storage/service/reader implementation
remain required before this design's acceptance criteria can be checked off.

## Protocol correction after independent review

### Issuer and archive binding

Each new profile-2 archive has a random immutable 32-byte archiveId in authoritative
profile metadata and every proof. Fresh owner-copy destinations get new IDs;
resumption and byte-preserving backups keep the original ID. One archive holds
one scope and one configured current service issuer. All statements in its chain
use that issuer, including upgrade proofs. The owner-copy job executes on the
service host with the service's configured signer; a remote browser/CLI never
receives the private key. This defines the software boundary, not a choice of
production credential provider or path.

For admitted, receipt.issuer equals statement.issuer equals the configured issuer.
For retained-verified, the original receipt and its issuer are retained exactly;
the current configured issuer attests that the explicit upgrade verified the
original signed request, partition and pinned legacy issuer. That historical
issuer can differ. Inventory checks the exact canonical receipt CID and all
receipt-to-manifest bindings in both cases. It does not reinterpret an unsigned
historical receipt as a signature by the historical issuer. The UI names both
identities and present verification purpose/time. A legacy source with mixed
receipt issuers or scopes refuses this first partition-only upgrade profile.

A backup restored to a second writer can still fork under the same archiveId and
key. Archive IDs distinguish independently created archives; they do not prevent
issuer equivocation. A signed snapshot selects an exact branch by its tip statement
CID. No signature detects equivocation across independent readers. This first
reader has no persistent monotonic pin and makes no rollback/freshness guarantee
across refresh or restart. The owner must prevent simultaneous restored writers.

### Descending pages and verified cursors

Proof inventory reads newest to oldest. A page is anchored at an expected frontier
(archiveId, sequence, manifest CID, statement CID). The first row must match that
exact frontier, verify its issuer/scope/archive/record bindings and signature,
and supply the preceding frontier; every next row matches the previous row's
committed predecessor. Genesis terminates at sequence zero with two null CIDs.
An empty page before genesis, skipped row, inconsistent complete flag, foreign
archive, or same-height fork is an integrity error. At most forty rows are checked
per page. First-page work is bounded independently of archive length.

For subsequent pages the authorized reader issues an opaque, domain-separated
cursor only after verifying the preceding page. It binds the original signed
snapshot digest, scope, reader-instance nonce and exact next frontier. Authenticate
it with an ephemeral per-reader MAC key; never accept unsigned client frontier
coordinates. The key/nonce live only in process memory; restart invalidates cursors
and the UI restarts at the latest page. This is a disposable verification shortcut,
not evidence or an access grant. Every page and source request still authenticates
to the configured service and rechecks current grants. Cursor bytes grant neither
plaintext nor scope authority. No persistent pin/cache or automatic history scan
is added. Bound cursor size, envelope decoding, page bytes and MAC verification.

A source/export selection carries a separate reader-authenticated occurrence token
binding original pin, archive, scope, sequence, exact manifest/receipt/statement
CIDs and reader instance. Mint it only for a verified inventory row. The reader
checks the token, contacts the service under current authorization, matches the
exact retained row and verifies hash, signed writer request and decryption. It
never rescans an unbounded prefix or treats an available badge as authorization.
Legacy snapshot/page/source behavior remains unchanged.

### Admission, degraded serving and recovery

A proof-profile Append reply carries exact stored proof bytes and a profile tag.
The proof-aware spool release verifies the signed reply, manifest/receipt binding,
configured issuer/scope/archive and proof signature. It does not infer contiguous
inventory from one admission reply. Exact retries return the original proof;
retained-verified is acceptable for an exact operation copied from legacy only
when the verified manifest matches the pending request. Legacy clients never
silently select this mode. Profile-2 raw Ledger commit APIs are unavailable;
only the authenticated service admission transaction may issue admitted proofs.

Degraded inventory is an explicit owner-selected server mode with a separate
read-only metadata reader. It authenticates requests and checks grants before
reporting integrity or availability. It serves InventorySnapshot/Page and bounded
source reads, refuses Append, and never invokes strict writable open as a fallback.
An archive that cannot open even for metadata cannot serve inventory; its errors
must not leak archive contents to unknown principals.

The first owner-copy upgrade accepts only a complete pinned legacy snapshot.
Prefix-only salvage is not supported and must not be described as full migration.
A payload-incomplete recovery copy remains profile 2 with exact proofs and missing
references. Its authoritative, copy-local recovery descriptor binds archiveId,
source pin and observed unavailable references; declare this surface with the
implementation. It cannot pass full restore or strict writable open until an
explicit owner recovery verifies all payloads. Backup/rebuild preserve both proof
bytes and recovery descriptors; old profile-1 readers refuse user_version 2.

### Revised conformance gate

Persist positive and re-signed negative vectors with exact expected failure
labels. Verify configured archive and scope, predecessor commitments, canonical
issuer algorithm/spelling, receipt bindings and purpose-dependent issuer rules.
Test semantically valid alternate statements with changed purpose/time/receipt
against a pinned successor. Keep envelope and nested-statement framing failures
separate from signature failures. Assertion-removal mutation tests must fail the
specific fixture check, not compilation or an unrelated signature check.

### Correction review follow-ups and audience transition

The second independent protocol review approves design readiness with follow-ups;
its original report is retained in `.design/reviews/kan-v2-evidence-protocol-correction-opus/`.
It is not runtime approval. Resolve its audience concern without changing normal
Append authentication: every live command still addresses the current service C.

For a retained-verified source row, the reader first verifies its C-signed proof
and exact receipt CID at the selected pin. It then verifies the retained original
request signature and its manifest binding with `verify_retained_request`, which
already requires original request.audience == original receipt.issuer H. That
historical equality replaces the legacy reader's audience == current C check
ONLY for this proof-verified purpose. Admitted rows still require H == C. The
current reader's live Read request always addresses C and rechecks its current
grant. Never relax ordinary live request audience validation or infer a historical
grant from H's name in an unsigned receipt.

A pending request addressed to H cannot simply be sent as Append to C. A new,
explicit proof-profile RetryImported command wraps the exact original signed
request in a current-C signed request by the same writer. Require current append
grant, current scope/archive configuration, valid outer authentication, matching
inner writer, and a stored retained-verified proof whose manifest commits to the
exact inner bytes and whose historical receipt binds their audience H. Return
that exact existing receipt/proof; never stage payloads, insert a new record,
re-sign an attestation, or accept a missing/mismatched operation through this
command. Failure uses the same access-limited shape. This is a read-confirmation
path for an already imported operation, not an audience-redirection exception.
A legacy client cannot select it without explicit proof-profile configuration.

Archive IDs come from the owner-create/upgrade plan, provisioned out of band in
reader/spool configuration; never trust-on-first-use from a snapshot. Resume binds
the exact destination archiveId. Source planning/copy covers a fixed tip, not a
catch-up subscription. Live cutover must quiesce legacy admission before pinning
its final plan and account for pending spools explicitly; later legacy appends
are absent from that destination and cannot be silently treated as migrated.

Proof purpose is a storage audit invariant in addition to individual signature
validity: retained-verified occurs only in a contiguous upgrade prefix, all with
one pinned historical receipt issuer; later admission creates admitted only.
Normal admission never mints retained-verified (an exact retry can return one).
The full-chain audit and descending pagination state must enforce that invariant.
The pure per-proof codec can verify individually valid assertions in other
orders; its mixed-purpose vectors do not demonstrate a producible archive.
Timestamps are issuer observations, not ordering authority: issuedAt is bounded
but may regress with the host clock. Sequence/chain commitments establish order.

Availability and snapshot frontiers are signed service assertions. Missing/corrupt
state is not independently verified by the reader. Available becomes reader-verified
only when source bytes, writer signature and decryption pass. A receipt's historical
issuer is an unsigned field committed by the current service's proof. UI labels
must retain those distinctions; no view implies independent completeness or freshness.

An incomplete-recovery descriptor is an append-only observation (observer, sampled
time, source pin, unavailable references), not current availability authority.
Owner recovery retains that observation and appends a resolution after verifying
all payloads; it never deletes or overwrites the loss observation. Strict open is
controlled by current full verification and the descriptor/resolution contract,
not an unlabelled removal of the marker. Declare both physical record surfaces
with the profile-2 implementation.

## Storage checkpoint scope

The first runtime slice lives in `src/evidence_store/attested.rs`: an owner-side
profile-2 storage API with explicit configured archive/scope/issuer binding,
atomic metadata/proof insertion, and exact stored-proof retry. It is not wired
into an HTTP listener or CLI yet. A trusted caller supplies the current grant;
a remote request must never select that grant. Existing profile-1 service and
raw Ledger APIs cannot open profile 2, including through initialization resume
or recovery. Writable profile-2 open still requires all retained payloads.

This checkpoint performs a complete read-transaction audit before each append,
then checks the manifest frontier, proof frontier and proof count under the
immediate transaction. Historical signature verification remains outside the
write lock. As with the existing append-only service fence, this protects against
concurrent append and tip replacement; it does not promise safety against an
arbitrary privileged process rewriting an earlier row after its audit while
preserving the observed tips. No finite endpoint fence establishes that stronger
filesystem threat model. The strict next audit refuses such corruption.
The full pre-admission scan is a correctness baseline, not a large-archive
throughput qualification. A cached verified-prefix optimization needs its own
integrity and performance review before production use.

Full store audit also enforces unique manifest and writer-operation identities
through exact schema validation plus integrity checks, contiguous sequence,
retained request verification, and a retained-verified prefix from one historical
issuer followed by admitted records. Ordinary Append cannot confirm a retained
record; RetryImported remains a later explicit command. Time regression is
allowed: signed sequence, not wall-clock time, determines ordering.

No full acceptance criterion is closed solely by this checkpoint. Copy upgrade,
initialization recovery for profile 2, proof-preserving backup/rebuild, degraded
read-only inventory, framed cursors, proof-aware spool release and Library UI
integration remain required. The independent codec review's source-oracle and
page-vector follow-ups remain open; its short-key regression and framing labels
are incorporated here. A separate detached proof API is required before spool
release consumes the codec.


### Storage review follow-ups

Fresh actual Claude Code Opus 5.5 approved 9f1dffa with follow-ups for the owner-side
checkpoint only. The unmodified report and probes are retained under
`.design/reviews/kan-v2-proof-storage-opus/`. Its retry-race, real historical-issuer,
non-P-256 and true signature-corruption probes are incorporated into CI. A receipt
change during retry is now a conflict, not invalid caller input. SQLite limit
configuration errors propagate. Explicit indexes on the proof tables must also
appear in the independent surface inventory; no index currently exists beyond
INTEGER PRIMARY KEY row coordinates.

The review demonstrated that the SQL helpers are inventoried conventions, not a
compiler-enforced ban on arbitrary raw SQL. Global SQL mutation enforcement remains
open under AC-5; the existing filesystem policy must not be described as enforcing
SQL calls. Also, PRAGMA integrity_check can materialize a hostile oversized
WITHOUT ROWID object before SQLITE_LIMIT_LENGTH rejects it (pre-existing in the
legacy writable opener). The future degraded reader must use bounded raw scans
and must not inherit that writable integrity-check path. Profile-2 initialization
resume, upgrade-plan/history pin, recovery observations, configured service grants,
backup/rebuild and a reviewed scalable admission path remain prerequisites before
production evidence or RPC exposure.

## Proof lifecycle build contract

The next prerequisite extends the existing profile-2 owner API without silently
changing its schema. Explicit initialization resume accepts either an empty,
unversioned interrupted output with the supplied owner binding, or an existing
profile-2 archive whose binding and full audit match. It never adopts profile 1,
replaces a binding, repairs records, or guesses the issuer. The empty-file opt-in
has the same ambiguity as legacy resume: an empty foreign file is indistinguishable.

`Archive::backup` produces a new standalone SQLite file and verifies the entire
output payload/metadata/proof chain against the explicit owner binding. A new
proof-aware recovery reader pins a read-only source, carries exact proof bytes
into a new single-transaction rebuild, rebuilds disposable coordinates from raw
records, and validates before commit and after durable output publication. It
refuses missing payloads, proof gaps/extras, invalid proofs, binding mismatch and
conflicting canonical records. This is full recovery, not degraded inventory or
metadata-only recovery. Source main database and retained WAL remain unchanged;
SQLite coordination-sidecar behavior retains the existing declared read-source
boundary. Destination collision/sidecar checks reuse the existing recovery path.

No new persisted field/file is introduced. Proof copying uses the inventoried
`EvidenceAttestation` SQL helper; existing backup/recovery file and sidecar
capabilities own destination media. Tests must prove byte-identical proof/record
round trips, refusal after corruption, wrong-owner and legacy-profile refusal,
interrupted initialization at every boundary, process-death rebuild behavior,
source invariance, and derived-index repair without changing evidence. Fresh
Opus review is required. Copy-upgrade plans, historical issuer pins, metadata-only
resolution records and RPC remain separate required work; no parent AC closes
from this prerequisite alone.

Owner CLI uses the existing `init`, `verify`, `backup`, and `recover` commands
with the all-or-none `--proof-archive`, `--proof-scope`, `--proof-issuer` pins.
Omitting them preserves profile-1 behavior; it never guesses profile 2 from disk.
`init --resume` is the explicit interrupted-creation opt-in. JSON distinguishes
proof-purpose-dependent verification from historical completeness and never
labels a local backup independent or automatically promotes rebuilt output.
