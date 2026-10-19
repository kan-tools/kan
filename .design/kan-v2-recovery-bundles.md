# Feature: retained recovery bundles and explicit complete-output publication

## Summary
A recovery bundle preserves a damaged physical copy, its exact authenticated
metadata, bounded retained ciphertext and an append-only record of loss and
recovery observations. It does not become capture-ready when a blob is restored.
This proposal resolves the physical-format/publication question C-F2 left open in
`kan-v2-evidence-availability.md`. It requires independent design review before a
bundle writer is implemented. The owner-copy storage PR does not implement it.

## Requirements
- REQ-1: A bundle has its own owner-pinned copy identity and observer authority, separate from the logical archive/profile/issuer. Ordinary standalone profile-2/3 APIs must refuse the entire bundle, including after every missing payload has been restored.
- REQ-2: Preserve exact canonical manifests, receipts, issuer proofs, profile-3 plan and original-object membership. Preserve every copied bounded object byte even when corrupt; do not turn missing payloads into empty objects or re-sign issuer proofs.
- REQ-3: Append bounded canonical observer-signed creation, unavailable-evidence, restoration and publication observations. Verify sequence/predecessor, observer, bundle identity and configured observation frontier before trusting the history. Retain loss observations after resolution.
- REQ-4: Restoring bytes appends a separately identified verified candidate without overwriting the original corrupt or missing member. A bundle remains a recovery artifact. Only explicit owner resolution can create a separate fully verified standalone output.
- REQ-5: Publication retains the bundle and any failed output, verifies exact output profile/authority/payloads, records what was durably observed, and never auto-activates a writer. An uncertain crash or failed publication must not be reported as completed recovery.
- REQ-6: Bundle-aware backup/rebuild preserves both member evidence and the entire observation/restoration history. Standalone backup/rebuild is never an implicit fallback for a missing bundle ledger.
- REQ-7: Declare all file, schema, observation and restoration surfaces; enforce bounded materialization and owner-configured work/disk budgets. No plaintext content, fetched external resources, implicit erasure, or guessed repairs.
- REQ-8: Qualify envelope bytes with an independent implementation, all publication crash windows, missing-ledger/standalone escapes, source invariance and exact retained history; obtain fresh Opus approval before accepting a bundle implementation.

## Acceptance Criteria
- [ ] AC-1: A bundle containing a complete backfilled logical profile 2 or 3 still refuses standalone open/admission/backup/rebuild. Missing or replaced observer history refuses bundle open rather than selecting standalone mode. (REQ-1, REQ-3, REQ-6)
- [ ] AC-2: Canonical positive and re-signed negative observation fixtures pin field sets, domain/preimage, signatures, identities, predecessor and source/output commitments in an independent implementation. (REQ-2, REQ-3, REQ-8)
- [ ] AC-3: Missing, corrupt and restored candidates retain distinct original evidence and observations; byte-identical issuer proofs and plans survive bundle backup/rebuild and successful output publication. (REQ-2, REQ-4, REQ-6)
- [ ] AC-4: Process death at every creation/restoration/publication boundary leaves a refused incomplete artifact, a valid retained bundle, or an independently verifiable complete output with honest pending/observed history. No automatic activation or false completed result occurs. (REQ-1, REQ-3, REQ-4, REQ-5, REQ-8)
- [ ] AC-5: Wrong external pins, path/sidecar collisions, stale source, unauthorized observer, oversized values, work-budget exhaustion and bad restored bytes refuse without rewriting original source/member evidence. (REQ-1, REQ-2, REQ-5, REQ-7)
- [ ] AC-6: Fresh review distinguishes logical recovery from physical publication, preserves failed probes, and demonstrates compiled controls for ledger omission, history overwrite, early completion and profile downgrade. (REQ-3, REQ-5, REQ-6, REQ-8)

## Architecture

### Encapsulated logical member

Propose a separate SQLite application ID `0x4b4e4231` (KNB1), user_version 1.
This is the physical **bundle** profile. Its member's logical profile remains 2
or 3, recorded explicitly in bundle identity; the member is not a nested
standalone SQLite file that an ordinary path configuration could open directly.
Existing archive application/profile markers never match the bundle. No product
option strips the bundle marker or treats absent observation tables as legacy.
Privileged manual extraction is outside this boundary and is not claimed prevented.

The namespace contains:

| Table | Authority and role |
| --- | --- |
| `bundle_identity` | singleton: bundle ID, observer DID, member logical profile, original archive/scope/issuer pins, initial member commitment and source frontier |
| `member_objects` | exact original object keys and bounded bytes, including corrupt bytes; absent rows remain absent |
| `member_commits` | exact manifest/receipt bytes with reconstructed disposable lookup coordinates |
| `member_attestations` | exact stored proof envelopes; never newly issued |
| `member_upgrade_plan` | exact canonical profile-3 plan, absent for profile 2 |
| `member_upgrade_objects` | exact original membership and lengths, absent for profile 2 |
| `observations` | contiguous observer-signed canonical envelopes; append only |
| `restored_objects` | append-only verified candidates by expected content address, with no updates to member_objects |

All SQL column definitions, constraints, indexes and typed mutations must be
frozen alongside the codec before writing. This table is the design inventory,
not a claim that the physical schema already exists. There is no independently
writable standalone archive member. Normal bundle queries preserve the distinction
between original evidence and restored candidates.

Creation requires a stopped/pinned source and a fully verified metadata chain.
Original payload bytes are copied even if they fail their expected hash or length,
provided they fit the protocol's bounded materialization limit. Unknown schemas,
invalid object keys or oversized corrupt cells refuse this first format; original
media stays retained for a separate forensic workflow. No arbitrary SQLite repair
or implicit omission is claimed. A missing row contributes a loss observation,
never a fabricated object. Staged objects are included in owner recovery inventory,
but are not exposed as authorized browser occurrences without metadata membership.

### Canonical observation protocol proposal

Use canonical DAG-CBOR `{v:1,kind:"recovery-observation",body}` and a closed
`{statement:<exact bytes>,signature:<64 low-S P-256 bytes>}` envelope, max 16 KiB.
Signature preimage is canonical `{domain:"tools.kan.recovery.observation.v1",
statement:<statement CID>}`. Require canonical static observer DID/method and
safe-integer sequence/time. No reuse of service admission signature domains.

Every body commits to bundle ID, logical archive ID/profile/scope/issuer, observer,
positive sequence, previous statement CID (null only at sequence 1), sampled-at
milliseconds, event kind and a closed event-specific payload. Event variants:

- `created`: initial member commitment, source metadata frontier, chosen recipe 1.
- `unavailable`: bounded references with occurrence sequence (or explicit staged
  object designation), expected CID/length and sampled missing/corrupt state.
- `restored`: expected CID/length and verified candidate commitment; this reports
  a checked restoration candidate, not activation or completed archive recovery.
- `publication-intent`: selected member/restoration commitments, target logical
  profile/frontier and owner-selected output attempt ID; no success assertion.
- `publication-observed`: cites that intent and exact verified durable output
  commitment/frontier. It records the observer's completed publication check.
- `publication-failed`: cites intent and bounded failure class, without erasing it
  or certifying that no output exists.

References and encoded size are both bounded; long inventories use multiple
linked records. Timestamps do not establish order. Observer O may be provisioned
on the same host as issuer C but has a distinct declared authority/domain. O's
signature never replaces C's admission proof or a writer's original signature.
Source and output paths are owner-local routing inputs, not trusted executable
instructions from signed observations. No shell command is stored or executed.

The initial member commitment needs a frozen domain/byte-framing recipe over
logical identity/profile, exact plan or explicit absence, canonical original
membership, exact records/proofs in sequence, and all original object key/length/
raw-byte commitments in canonical key order. Unlike a normal object CID check,
it must commit to corrupt retained bytes as observed. Independent fixtures must
cover empty/missing/corrupt/staged cases and profile-3 partial copies. The full
byte recipe is a required codec checkpoint, not an implementer's implicit choice.

### Creation and restoration transactions

Create a new private outer database without a recognized bundle marker. A bounded
owner job copies and verifies member metadata, retains bounded original objects,
and inserts creation/loss observations. Publish the bundle marker only in the
same successful transaction as the complete initial member and initial history;
fsync the file and parent before reporting success. A failed/oversized job retains
an unrecognized output and source. Work budgets are explicit instance/owner
resource limits, not a new fixed repository-size ceiling disguised as a protocol
limit. A resumable multi-transaction creator needs a separate pinned-plan design;
it must not label a partially copied bundle complete.

Restoration validates a candidate's expected CID/length and its membership before
atomically inserting it and an observation. Original member rows and prior loss
observations never change. Repeating exact verified bytes is idempotent and does
not invent new issuer provenance. A different candidate for the same CID refuses.
The bundle's inventory may show a verified restoration candidate alongside the
original missing/corrupt state; it never silently substitutes history.

### Resolution and publication

The owner selects a new output path and exact bundle/history frontier. Verify all
chosen payloads, current writer signatures, issuer proofs, original plan/membership
and structural constraints. Partial profile-3 copies must first be completed by
the reviewed source-copy workflow; restored blobs alone do not invent missing
metadata or satisfy an incomplete source recipe.

Append `publication-intent` before creating an output. Build a new standalone
file using exact original metadata/proofs/plan and verified selected payloads,
rebuilding only derived columns. Keep it unrecognized until full verification
succeeds inside its publication transaction, as the existing rebuild API does.
Durably publish and re-verify the result, then append `publication-observed` and
return a completed job result. Do not automatically switch the service target.
The owner must separately fence the old writer and activate one selected output.

SQLite cannot atomically commit an external file and the bundle observation
ledger. Therefore a crash can leave a fully verified standalone output with an
unresolved intent. This is **uncertain publication**, not completed recovery. The
next explicit resume verifies that exact output and appends the observed outcome,
or records failure and retains all artifacts. It never guesses completion from a
filename or overwrites a different existing output. A completed physical output
can be verified independently even when its acknowledgment was lost; no claim is
made that privileged early manual configuration is cryptographically impossible.
Ordinary job/administration flows activate only an explicitly selected completed
publication result, and never activate on a pending/failed intent.

This distinction is a review point for C-F2: the encapsulated bundle cannot escape
as standalone, while a separate fully verified output may exist before its final
observation acknowledgment. The implementation must not conflate artifact validity,
observed publication, job success and live writer activation.

### Backup, rebuild and grants

A bundle backup is a consistent snapshot of the entire outer database, verified
against owner pins and the selected observation frontier. A bundle rebuild copies
all authoritative member/restoration/observation bytes into a new outer profile
and rebuilds disposable indexes. Missing member payloads remain missing; missing
observation history is a hard integrity failure. No fallback to standalone file
commands or omission of unresolved attempts is allowed.

Bundle IDs name physical recovery copies, not new logical archives. A backup
preserves the bundle identity and history; two copies can have different future
observations. Owner configuration must select a single observation writer or
explicitly provision a new bundle identity for an independent observation branch.
No cross-host anti-equivocation or silent merge of observer histories is claimed.
Browser scope access remains governed by the same current grants as inventory;
owner recovery and publication require separate administrative capabilities.

## Proposed codec checkpoint

`kan-v2-recovery-bundle-codec.md` now specifies the proposed observation schema,
domain-separated signature preimage, M1/R1 byte framing, member table shapes and
publication replay rules. It remains a proposal pending independent review and
independent byte fixtures; no bundle writer exists.

## Open qualification work

Freeze the complete body field names, member commitment framing, observation
reference bounds and physical SQL definitions in a dedicated codec patch. Produce
independent positive/re-signed-negative fixtures and obtain fresh Opus review of
C-F2 before any writer exists. Then implement storage, crash tests and owner job
APIs; only afterward integrate the human recovery workflow. These are required
remaining steps, not completion claims or a reduction of the full frontend scope.
