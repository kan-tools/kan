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
A payload-incomplete recovery is an explicit recovery bundle. Its archive member
retains its original profile (2, or 3 with exact upgrade plan/inventory), exact
proofs and missing references. Copy-local observations live in a separate
append-only recovery ledger, not in a widened profile-2 schema. The bundle
contract below governs its opening, backup, resolution and complete-output
publication. Old profile-1 readers still refuse the archive member's profile.

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

As refined by C-F1 below, this mixed-purpose rule belongs to profile 3 only;
profile 2 refuses every retained-verified row.

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
all payloads; it never deletes or overwrites the loss observation. A recovery
bundle remains a recovery artifact; resuming capture requires explicit publication
of a separately verified complete output. Removing a marker is never recovery.
Declare both physical record surfaces and bundle validation with the future
recovery-bundle implementation; neither belongs to the exact profile-2 schema.

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

The original mixed-purpose profile-2 checkpoint below is superseded by C-F1:
profile 2 is admitted-only, and these positive historical-prefix cases must be
re-established under profile 3.

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

## Next copy-upgrade schema decision (not implemented)

Profile 2 has an exact schema and no durable upgrade-plan field. Copy migration
will use a separately versioned profile 3 rather than silently enlarging profile 2
or inferring an unfinished copy from whichever records happen to exist. Existing
profile-2 APIs retain their admitted-only meaning after C-F1 (experimental
plan-less retained prefixes are refused); profile-3 support must be added
explicitly to owner lifecycle, inventory and admission paths. This supersedes the
earlier copy-plan destination-profile-2 placeholder only; attestation envelope
version 1 and original manifest/receipt bytes remain unchanged.

Profile 3 adds one authoritative `upgrade_plan` singleton containing a bounded
canonical plan envelope. The plan names recipe version 1, source profile 1, exact
source through/tip, a framed digest over every ordered source manifest, receipt
and retained-request CID, one historical receipt issuer H, target scope, current
issuer C, target profile 3, and an owner-generated 32-byte nonce. The fresh archive
ID is the domain-separated SHA-256 commitment to those exact canonical plan bytes.
The owner pins that ID out of band; the stored plan must recompute to it. This
provides a durable binding for resume even before the first copied record, without
a mutable progress/completion flag or a second authoritative sidecar. The raw
plan is not historical admission evidence; C's retained-verified proofs continue
to make only their stated present-time verification claim.

Planning pins and fully verifies the entire legacy source, including all retained
signed requests, before creating any destination. It refuses missing, damaged,
foreign-scope, mixed-issuer or invalid requests. Copy execution recomputes the plan
against a fresh pinned source and requires the exact expected commitment. Each
record preserves sequence, signed request, manifest and receipt bytes and commits
its new retained-verified proof atomically with destination metadata. Restart
compares every existing destination-prefix record and proof against the same plan
and source; it never replaces existing output bytes or re-signs an acknowledged
row. Small explicit batches bound each invocation; incomplete output stays a
visible resumable copy, not a capture-ready archive.

Completion is derived by verifying the planned prefix length and complete framed
digest, including H, before allowing new admission under C. An incomplete planned
prefix cannot accept ordinary Append. The proof chain must contain exactly that
retained-verified prefix followed only by admitted rows. Merely checking that all
present payloads exist is insufficient. Owner CLI reports source-copy completeness
separately from payload completeness and never promotes or erases automatically.
Empty legacy sources require explicit H in the plan, since no receipt can supply
it; empty history is not evidence of capture completeness.

Before implementation, extend the typed SQL surface and independent catalog for
the exact plan bytes and derived singleton coordinate. Backup/recovery must carry
and verify the plan exactly, retain incomplete-copy state, and refuse a changed
plan even when all individual proofs remain valid. Qualification needs independent
canonical plan vectors, plan-field mutations, alternate valid source snapshots at
the same through/tip, partial-copy admission refusal, concurrent destination
changes, every interruption boundary, exact resume bytes, and source/WAL invariance.
No profile-3 runtime or source migration is claimed by this design decision.

### Draft canonical copy-plan codec

The next source-only worktree `.worktrees/kan-v2-copy-upgrade` starts with an
explicit recipe codec. It has no planner, destination writer, profile-3 schema,
CLI or implicit conversion. Decoding is structural validation only, never a
source-verification or authorization result. The existing lifecycle review is
independently auditing the profile-3 design before its storage build proceeds.

Proposed closed DAG-CBOR fields: `recipe=1`, `sourceProfile=1`, `targetProfile=3`,
`sourceThrough` (unsigned safe integer), `sourceTip` (DAG-CBOR SHA-256 CID, null
iff through is zero), `sourceDigest` (32 bytes), `historicalIssuer` (canonical
static did:key), `scopeToken` (32 bytes), `issuer` (canonical static P-256 did:key),
and `nonce` (32 owner-generated bytes). The codec limits the complete plan to
4,096 bytes, rejects missing/unknown fields and preserves canonical byte/link
types. Its archive ID is SHA-256 of ASCII `tools.kan.archive.copy-plan.v1`, one
NUL byte, then the complete exact canonical plan bytes. The fixed domain makes
the concatenation unambiguous. Compare that commitment with the separately
provisioned owner pin; do not derive the expected pin from received bytes.

Current issuer C must use P-256 as required by the proof profile. Historical H
may use any canonical static key accepted by the retained service request codec;
its presence is a source/audience pin, not authentication of an unsigned old
receipt. The source planner must verify every signed request against that H and
all records against the target scope before returning a usable execution plan.

Five independently encoded positive byte/commitment vectors and 33 labelled
malformed plans are proposed under `.design/fixtures/copy-plan-v1.json`; the
stdlib-only generator imports no Rust and invokes no archive. The Rust draft
checks exact bytes, all owner/source-field commitment changes, and refusal cases.
Compilation, semantic negative controls and fresh review remain required. No
source or destination migration is implemented by this draft codec.

### Draft read-only source planner

`evidence_store::copy_upgrade::PlannedCopy` opens a profile-1 source in a pinned
read-only transaction, requires the exact healthy legacy schema and full contents,
then checks every retained signed service request against explicit historical H
and target scope. It emits no plan until the whole snapshot passes. This first
planner refuses damaged derived indexes; the existing separate recovery workflow
can rebuild those into a new file before planning. It adds no destination writes.

The source digest is SHA-256 of ASCII `tools.kan.archive.copy-source.v1`, one NUL,
then two framed sections. A frame is unsigned 64-bit big-endian byte length plus
those exact bytes. First frame ASCII `commits`, then unsigned 64-bit big-endian
through. Each record in ascending sequence order contributes its unsigned 64-bit
big-endian sequence and framed manifest bytes, receipt bytes and canonical raw
retained-request CID bytes. Next frame ASCII `objects`, then unsigned 64-bit
big-endian object count. Every retained object in lexical CID-string order
contributes framed canonical raw CID bytes and unsigned 64-bit big-endian length.
The full audit already verifies each CID against its exact object bytes.

This explicitly binds staged-but-uncommitted blobs too. Destination copying must
preserve all of them without inventing commit/admission attestations for objects
outside the committed stream. A new staged object changes the plan even when
through and tip are unchanged. No source file or blob is erased. This refines the
earlier committed-stream-only fingerprint before any destination implementation.

Reconfirmation compares the externally pinned archive ID first, then reopens and
fully verifies a source and compares the exact resulting recipe bytes. Matching
through/tip alone is insufficient: a structurally valid changed unsigned receipt
at the same frontier must refuse. Holding the planner pins the original snapshot
while later WAL admissions occur. Full source auditing retains the existing
offline integrity-check/materialization limitations; request lookups use the
indexed path only after the full size/hash audit in the same pinned transaction; this
is not the future bounded degraded-inventory reader.

Runtime draft tests target pinned-source/later-append refusal, same-frontier
receipt changes, explicit owner/audience/scope selection and missing payloads.
No copy/resume destination or profile-3 mutation is implemented yet.

### Original-object inventory in profile 3 (design refinement)

Preserving staged objects also requires retaining their original membership after
new capture adds more objects. Profile 3 therefore needs an immutable
`upgrade_objects` table alongside `upgrade_plan`: canonical original object CID
as the key, plus its original byte length. These are authoritative copy-plan
inputs bound by the owner-pinned source digest, not inferred from current objects
or timestamps. The table must not impose a foreign key that destroys inventory
metadata when payloads become unavailable. Writable opens still require payloads.

The source digest's object section uses the exact ordered inventory and its row
count. Copy/resume validates that the partial inventory is an exact prefix of
the pinned source inventory; completed inventory and the planned record prefix
must reproduce the complete source digest before admission is allowed. Every
inventory row and its copied payload commit atomically. Once complete, ordinary
admission never changes this table. Full audits after later admission recompute
the original source commitment from the planned record prefix and this immutable
inventory, while separately validating newer admitted rows and objects.

Backup/recovery must preserve both plan and original-object inventory exactly,
including an incomplete-copy state. Missing/corrupt original payloads remain
distinct from unavailable metadata. A copied staged blob carries no fabricated
admission or capture assertion and cannot appear in scoped occurrence inventory
until a real committed record references it. Mutation surfaces, catalog entries,
partial-prefix crash tests, later-admission tests and degraded-read behavior all
need qualification before profile-3 destination writes are implemented.

A copy recipe pins one old-source snapshot. Reopening after additional legacy
admissions or staging refuses the old recipe; it does not silently extend the
planned prefix. Operational cutover must therefore settle legacy delivery and
freeze that source before the final plan. New capture can queue under the new
issuer while the fixed copy completes, subject to the existing visible-gap
policy if durable capture capacity is exhausted. Unadmitted historical-audience
requests are not converted by RetryImported, which only confirms already retained
records. The eventual cutover plan must inventory such pending requests and
resolve them explicitly; this source planner neither stops a process nor drops
or relabels pending traffic. Deployment and live cutover remain separately
authorized operational work.

### Destination execution order (proposed; not implemented)

The owner executor must verify the externally pinned recipe and current signing
key before creating output. It holds the verified read-only source snapshot for
the invocation. Creating a new destination and resuming an existing destination
are separate explicit actions; neither can adopt profile 1 or 2. Initialization
commits the exact profile-3 schema, owner identity and plan together. Resume of an
empty interrupted file follows the existing explicit-owner ambiguity rule.

Copy original objects first, in the plan's canonical CID-string order. Each
payload and inventory row enter one transaction. Before advancing, compare all
existing original inventory/payload bytes against the source's exact prefix.
Then copy source records in sequence, preserving raw manifests, receipts and
request bytes; each new retained-verified proof commits with its record. Existing
proofs are verified against C and the fixed plan and preserved byte for byte.
Their present-time issuance timestamps need not equal those of later batches.
Restart never signs a replacement for an already committed proof.

Each invocation has explicit object, record and byte budgets. A single maximum
permitted object must fit the declared byte budget; exhausting a budget yields a
resumable status, not partial success disguised as completion. These budgets
bound copied work, not the full-source or destination audit cost. The source
planner's offline audit limitations therefore remain visible.

Every destination batch acquires SQLite's write transaction and revalidates the
prefix inside that transaction before mutation. Concurrent owner invocations
must either observe and validate the newer prefix or refuse with a conflict.
No process-local progress counter is authority. Completion requires the entire
source record prefix and original-object inventory to reproduce sourceDigest;
an empty recorded history with staged objects is incomplete until those objects
are copied. Normal admission requires that verified completion and can only add
current-issuer admitted proofs after the retained prefix. A resumed already
completed destination may contain later admitted rows; those must be independently
audited and may never be truncated to make it resemble the original source.

The owner API must expose copied-object count, copied-record frontier and explicit
source-copy completion separately from payload completeness and historical
capture completeness. Backup/recovery cannot mint completion or attestations.
Crash qualification covers initialization, object/inventory transactions, each
record/proof transaction and the boundary before the first new admission, with
source bytes unchanged and all acknowledged destination bytes preserved.

### Cold review decisions C1-C6 (proposed refinements)

The first cold review approved design readiness with required clarifications.
These decisions refine the proposal; their implementation and fresh review remain
required.

**Plan custody and one writer.** The plan is unsigned canonical data, not an
admission envelope. Before creating a destination, the owner retains its exact
bytes as a private plan artifact and pins the domain-separated archive ID
separately. Both create-from-plan and explicit resume take those same bytes plus
the external pin; they verify the commitment before inspecting or creating output.
An interrupted empty output has no authority to choose a plan. Resume therefore
requires resupplying the exact artifact; losing it never permits automatic
re-planning or a guessed nonce. The future CLI must durably write and verify the
plan artifact before it can create output, with a declared file mutation surface.
The current read-only planner only returns bytes and performs no artifact writes.

A recipe identifies one logical archive and one designated admitting destination.
Running it twice or resuming both an incomplete copy and its backup can create
same-ID forks. Local locks do not prevent cross-host forks. Only one destination
per recipe may admit; cutover/recovery must fence the old writer before activating
another. A backup is read-only until an explicit takeover. Reusing a plan is never
documented as provisioning an independent archive; independent creation requires
a fresh nonce. Cryptographic anti-equivocation is not claimed.

**Identity binding at every entry point.** Profile-3 archive_identity must equal
`(plan.archive_id(), plan.target().scope, plan.target().issuer)`. The plan's recipe,
source and target profiles must match recipe 1, profile 1 and profile 3. Writable
open, verification, backup, rebuild and degraded inventory all check this against
explicit owner configuration. No opener may infer the trusted binding from the
stored plan or silently drop it. A changed plan remains invalid even if each
individual retained proof verifies. Standalone profile 2 remains unchanged.

**Recovery observations are copy-local, separate from logical archive schema.**
Profile 3 adds only upgrade_plan and upgrade_objects. Loss observations and their
resolutions belong to a separately versioned recovery-bundle format, because two
physical copies of one archive can have different availability. They do not
change what the issuer's admission proof says, and they are not schema extensions
to profile 2 or 3. This explicitly supersedes the earlier ambiguous instruction
to add descriptor/resolution surfaces "with the profile-2 implementation."

An owner-provisioned recovery-bundle handle pins its copy identity, archive
identity/profile and source frontier, and requires the accompanying append-only
observation ledger. It never auto-detects standalone mode when that ledger is
missing. Bundle APIs must verify observer identity, bounded canonical records,
predecessor linkage and the configured observation frontier before using claims.
Observations state what that observer saw at that time; they never certify current
availability. Source proofs retain their separate issuer authority. The physical
record encoding, publication protocol and surface inventory require a dedicated
design/implementation checkpoint before any bundle writer exists.

Bundle backup/rebuild preserves the archive's exact proofs, any profile-3 plan
and original-object inventory, and the full observation/resolution history.
Existing standalone-file backup commands are insufficient for a bundle and must
refuse a bundle handle, rather than silently copying only its archive member.
The bundle itself is never capture-ready. Explicit owner resolution verifies all
payloads, appends a resolution without rewriting loss observations, and publishes
a new complete standalone output with the original logical profile and proofs.
The bundle is retained as ground truth, and the resolution identifies the exact
complete output/frontier; publication failure cannot count as completed recovery.
Merely filling missing blobs or deleting a descriptor never activates capture.
Low-level standalone archive APIs make no claim to validate an accompanying
recovery bundle; instance configuration must select the bundle-aware boundary.

**Framing, audit cost and source scope.** The byte framing is the explicit
sequence/count/domain recipe specified above and tested by the independent
Python oracle. A live PlannedCopy handle reuses one fully audited pinned source
across batches. Reopening after interruption currently requires a fresh full
source signature audit before that handle is trusted; the cost is deliberately
visible and can be quadratic across many tiny process invocations. A future
digest-only resume optimization needs its own trust proof and review; an arbitrary
owner-supplied decoded plan is not itself proof of valid request signatures.
Recipe 1 refuses raw or imported records without exactly one valid retained
signed service request matching the manifest. Such sources must use the separate
legacy import/salvage workflows; no synthetic historical admission is minted.

### Final review decisions for the first profile-3 storage slice

Fresh actual Opus 5.5 at 8244375 approved destination implementation readiness
with follow-ups; the unmodified report is preserved in
`.design/reviews/kan-v2-copy-planner-opus/`. These decisions resolve C-F1, C-F3
and C-F4 before any profile-3 destination write. They are implementation
requirements, not claims that the destination runtime exists.

**One meaning of copied history (C-F1).** Profile 2 is admitted-only. Its audit,
writable opener, verification, backup and rebuild must refuse retained-verified
proofs. Profile 3 is the only recipe-1 copy target and the only profile permitted
to contain a retained-verified prefix. RetryImported targets profile 3 only.
This supersedes the earlier profile-2 allowance for a plan-less upgrade prefix
and its synthetic acceptance fixture. No production profile-2 archive has been
provisioned in this work; there is no silent conversion or deletion. Any existing
experimental file refused by the stricter rule stays untouched. The next storage
slice must implement and independently review this distinction before writing a
profile-3 destination.

**Original membership and deduplication (C-F3).** An original object's CID remains
in upgrade_objects permanently even if a later current-issuer admission uses the
same CID. There is one content-addressed payload, with both original membership
and later occurrence lineage. Audits allow shared CIDs; they never subtract or
re-attribute original membership. No foreign-key cascade may destroy inventory
metadata when a payload becomes unavailable.

**Explicit profile selection and takeover (C-F4).** Owner APIs select profile 3 by
its distinct type; owner CLI lifecycle commands require explicit profile 3 along
with archive/scope/issuer pins. Existing all-or-none pins continue to mean profile
2 unless the new profile option is supplied. No user_version auto-detection
selects trust. Create/resume additionally require the retained exact plan artifact
and external archive pin. Verify/backup/rebuild may read the stored plan only to
check it against the explicit configured profile and pins.

Takeover means the owner stops or fences the old admitting service and configures
one replacement as the sole write destination. Copy, backup, verify and rebuild
never perform that activation or claim to establish cross-host fencing. Their
outputs remain unpromoted. The later service/admin integration must expose the
explicit activation workflow; an ordinary backup is not an independent archive.
The owner-side API assumes its signer/grants come from that trusted configuration.

**Bundle boundary remains a separate required checkpoint (C-F2).** Before any
bundle writer exists, define an encapsulation/publication format that cannot be
selected as a standalone archive member through the product's ordinary writable
configuration. Filling missing blobs inside a bundle must not bypass the retained
observation/resolution history. A privileged owner manually extracting bytes is
outside that product boundary, not something local locks can prevent.
Resolution preserves source-copy completeness independently of payload completeness:
a payload-complete but unfinished profile-3 copy remains unfinished and cannot
admit. Publishing it does not finish migration or authorize a second writer.
Physical encoding, atomic publication and activation tests remain open for the
bundle-specific design review; the copy-only schema approval does not close them.


## Profile-3 destination qualification contract

Fresh review 17c1ce6e (preserved in kan-v2-purpose-gate-opus) approved the
admitted-only prerequisite with follow-ups. Before accepting this destination
slice, establish these named cases under profile 3:

- A complete single-H retained-verified prefix accepts ordinary admission under C,
  continuing the exact proof frontier. Clock regression never changes ordering.
- Backup and rebuild preserve every retained proof byte and purpose; recovery may
  rebuild derived lookups but must never relabel retained evidence as admitted.
- A mixed-H retained prefix refuses for historical issuer mismatch. A retained row
  after the planned prefix refuses for its position, independently of signature
  validity. Admission inside the planned prefix refuses as well.
- Interrupted initialization and every copy transaction boundary resume only with
  the same retained recipe and external archive pin. Existing proof bytes remain
  fixed, including after an acknowledgment is lost.
- The original inventory is immutable, includes staged objects, and permits later
  admission to reference an original CID without reattributing it. Partial copies
  cannot admit. The admission transaction rechecks completeness after staging.
- A private exact plan artifact precedes output creation. Explicit profile-3
  lifecycle CLI calls preserve incomplete-copy status; they never activate a
  writer or claim an independent archive. Invalid pins, lost plans, changed
  sources, unsupported schemas and bad budgets refuse before useful mutation.

The implementation remains a full-scan correctness baseline: batch write counts
and bytes are bounded, but source verification and prefix audits are not a
bounded-latency or large-archive performance claim. Read-only degraded inventory,
recovery bundles, RPC/spool integration, RetryImported, and owner takeover remain
separate required roadmap checkpoints. No live archive is migrated by this work.

## Owner copy storage checkpoint

`evidence_store::copied::{Archive,Recovery}` and `kan-v2 copy-plan` /
`copy-batch` implement the profile-3 owner storage path. This checkpoint does not
add profile 3 to the HTTP service, delivery spool or Library. The existing raw
`read-record` / `read-object` commands remain explicitly profile 1. Approval of
this storage checkpoint cannot stand in for those required integrations.

The source is a healthy profile-1 **service archive**, not an arbitrary v1 kan
repository. Repository discovery/import remains the earlier raw-v1 import path;
this upgrade preserves the service records produced by that path. If derived
source columns are damaged, use the separate profile-1 rebuild first and retain
the damaged original as evidence.

The owner first freezes the source and retains a recipe in a new private file:

```sh
kan-v2 copy-plan SOURCE/archive.sqlite PLAN.cbor \
  --scope SCOPE_HEX --issuer CURRENT_ISSUER_DID \
  --historical-issuer SOURCE_ISSUER_DID --nonce FRESH_32_BYTE_HEX
```

Retain the reported `archive` pin separately from `PLAN.cbor`. Keep the original
source and its backup. The plan binds all objects, including uncommitted staged
bytes, plus exact original manifests and receipts. A later source change makes
confirmation fail even when the manifest frontier is unchanged.

```sh
kan-v2 copy-batch SOURCE/archive.sqlite DESTINATION \
  --plan PLAN.cbor --key CURRENT_ISSUER_PRIVATE_KEY \
  --copy-profile --proof-archive EXTERNAL_ARCHIVE_PIN \
  --proof-scope SCOPE_HEX --proof-issuer CURRENT_ISSUER_DID \
  --objects 128 --records 128 --bytes 16777216
```

Repeat with `--resume` for existing output. Copy batches insert original objects
and their immutable membership first, then exact records and newly signed
retained-verified proofs, atomically. Each batch verifies its existing prefix
against the pinned source. It never rewrites an acknowledged proof. A lost final
acknowledgment is resolved by explicit resume, including an already completed
copy with later admitted records. Counts and bytes limit writes, not audit time.

`copy.source_copy_complete` must be true before the owner API can admit new
records. `objects_written=0, records_written=0` may mean already complete or a
budget that cannot advance the current phase; inspect the explicit status.
Original membership remains fixed even if later admission shares a staged CID.

`verify DATABASE`, `backup ARCHIVE NEW_FILE` and `recover DATABASE NEW_FILE`
accept the same `--copy-profile` and all three proof pins. Stored recipe bytes
must agree with those explicit pins. They report copy completeness separately
from full payload/proof validation; a valid partial backup or rebuild remains
incomplete and cannot admit. Recovery reconstructs derived columns and preserves
all authoritative bytes. Missing or corrupt authoritative evidence refuses and
leaves any failed output for inspection. No command promotes output, activates a
service, fences another host, or certifies an independent backup.

The plan/copy schemas and CLI are being qualified in the dedicated permanent
`kan-v2-copy-destination` worktree. Fresh independent review and CI are required
before treating this checkpoint as accepted. Host power-loss, production-size
throughput, cross-host fencing and live migration are not demonstrated here.

### Owner-copy review follow-ups (2026-10-19)

The cold Opus review of d9b2110 approved this storage checkpoint with follow-ups;
its unmodified report and probes are retained in
`reviews/kan-v2-copy-destination-opus/evidence/REPORT.txt`. No parent acceptance
criterion is closed by that verdict.

Plan custody now uses the same SQLite family and filesystem-alias collision
rules as archive outputs. `retain_plan` takes the verified source, rejects its
main/sidecar names before creating a file, and still retains private exact bytes.
`read_plan_for_copy` checks both source and destination families before the CLI
opens either database. The bare `read_plan` function is only a bounded decoder;
it confers no path-safety guarantee. These checks retain the trusted-filesystem
assumption; they do not fence hostile concurrent filesystem replacement.

Schema-drift tests name the exact refusal at open, file verification, resume,
existing-handle verification and backup. Two additional resume tests use valid
foreign object membership and a valid historical receipt with a current retained
proof: local verification succeeds, but advancing against a different exact
source prefix refuses before writing. The earlier wrong-length test is renamed
to describe the earlier guard it actually exercises. CLI tests attribute explicit
profile/pins, key identity, private plan permissions, byte budget, missing resume
output, initialization path and SQLite-path refusals.

`copied::Archive::create` initializes an empty archive without proving signing-key
possession. API executors requiring no output before that check must verify the
key first; the owner CLI does. Every copying batch verifies the signer.
`copy_batch(issued_at)` takes Unix milliseconds, whereas `admit(now)` uses Unix
seconds for the service expiry contract. Those units are now documented at the
API boundary. Non-private recipe errors name the plan rather than a database.

The original report's claim that copy batches perform per-object NOT INDEXED
reads is inaccurate: `src` is `&source.reader().ledger` and uses indexed
`Ledger::read_object`; `RecoveryReader::read_object` is not called there. The
unmodified review remains intact. Full source/destination audits still run, and
no bounded latency or large-archive performance claim is made.
