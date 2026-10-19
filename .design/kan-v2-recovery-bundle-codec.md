# Proposal: KNB1 recovery bundle codec and member commitment

This freezes the proposed byte/schema choices for independent design review of
`kan-v2-recovery-bundles.md`. It is not an implemented format. No writer may use
these bytes as a compatibility promise until the design and independent vectors
are reviewed. The parent bundle requirements and publication distinctions apply.

## Identities and canonical values

The physical database encoding is UTF-8. Creation must set `PRAGMA encoding =
'UTF-8'` before creating tables; opening must verify the existing encoding is
UTF-8 and refuse UTF-16 rather than attempting conversion. This is a proposed
format requirement; no creation/opener exists yet.

The outer SQLite `application_id` is `0x4b4e4231` (KNB1), `user_version=1`.
The logical member is explicitly profile 2 or 3; its ordinary archive/scope/issuer
binding is preserved. An owner supplies an independently retained random 32-byte
bundle ID and observer DID key. Neither is learned as authority from the file.
A bundle backup preserves that ID; a new observation branch needs explicit owner
selection or a new bundle identity, not a silent history merge.

Canonical DAG-CBOR and low-S P-256 signature encoding follow the already reviewed
service-attestation codec, with a separate signature domain and a separate closed
schema. Integers are nonnegative and at most `9007199254740991`. Identifiers use
canonical CID encoding (raw/SHA256 for object bytes; DAG-CBOR/SHA256 for statements)
and validated static `did:key` P-256 authors. Unknown fields, alternate encodings,
unknown versions/events, malformed/non-low-S signatures and trailing bytes refuse.
A rejected record is not skipped while continuing the observation frontier.

The envelope is the canonical DAG-CBOR map `{statement: bytes, signature: bytes}`.
The statement bytes encode exactly:

- `version`: 1.
- `domain`: `tools.kan.recovery.observation.v1`.
- `bundle`: 32 bytes, the external physical-copy pin.
- `profile`: 2 or 3, the logical archive profile.
- `archive`, `scope`: 32 bytes each; `issuer`, `observer`: canonical DID strings.
- `sequence`: positive integer; `previous`: statement CID or null at genesis.
- `sampledAt`: Unix milliseconds, informational rather than ordering authority.
- `event`: one closed event name below; `body`: its closed event map.

Compute the statement CID from its exact canonical bytes. Sign the canonical
DAG-CBOR preimage map `{domain: "tools.kan.recovery.observation.v1", statement:
<statement CID link>}` using the existing P-256 identity signer. This follows the
service proof's domain-separated CID preimage pattern, with a different domain.
The statement's domain field must equal that same literal. The statement CID
hashes statement bytes, not the envelope/signature. Envelope maximum
16 KiB includes both encoded byte strings. Every body repeats the complete pinned
context through the common statement; no observation inherits an unverified
identity from an earlier row.

## Initial member commitment M1

`SHA256` consumes the following byte stream. `F(x)` means an unsigned 64-bit
big-endian byte length followed by x. `N(n)` is unsigned 64-bit big-endian n.
The pure framing layer bounds issuer text to 1..80 UTF-8 bytes; it does not
validate a DID. A full member requires a canonical static P-256 DID (56..80
ASCII bytes), a stricter semantic check. DIDs use UTF-8; CID frames use canonical binary CID bytes; record/envelope frames
use exact original canonical bytes. Empty sections still include their count.

1. ASCII `tools.kan.recovery.member.v1` followed by one zero byte.
2. `N(profile)`, `F(archive)`, `F(scope)`, `F(issuer)`.
3. `F("plan")`, `N(0)` for profile 2. Profile 3 instead has `N(1)`,
   `F(exact original plan envelope)`.
4. `F("original-membership")`, `N(count)`, then canonical object-CID text lexical
   order: `F(binary CID)`, `N(expected length)`. Profile 2 has zero entries.
5. `F("records")`, `N(count)`, then increasing contiguous sequence:
   `N(sequence)`, `F(manifest bytes)`, `F(receipt bytes)`, `F(issuer proof bytes)`.
6. `F("original-objects")`, `N(count)`, then canonical object-CID text lexical
   order: `F(binary CID key)`, `N(actual retained byte length)`, `F(raw bytes)`.

The original object key is retained even when its raw bytes do not hash to it.
Missing objects are absent, not fabricated empty rows. A present zero-length
corrupt object is a present row with length zero and an empty frame. Staged/orphan
objects are included. A valid identifier with corrupted bytes is representable;
a malformed key, duplicate logical key, unreadable SQL cell, unknown schema or
non-BLOB object cell (including TEXT with identical encoded bytes), or
raw object larger than 4 MiB refuses initial creation and retains the source and
failed output. This is a bounded capture format, not arbitrary SQLite forensics.
A later format for oversized forensic fragments needs a separate explicit recipe;
it must not silently truncate a row to fit M1.

M1 intentionally excludes rebuildable indexes/lookup columns, bundle identity,
observations and restoration candidates. Those are bound by their own signed
context/history. Identical member evidence in two physical bundles has the same
M1. The source metadata frontier includes both manifest and issuer-statement CIDs,
not just a high-water sequence. For empty history both are null.

## Event bodies

All digests below are 32 bytes; `member` uses M1, `output` uses O1, and
`restorations` uses R1. O1 has exactly M1 framing with the initial domain replaced
by ASCII `tools.kan.recovery.output.v1` followed by a zero byte. It commits to the
fully verified selected output rather than the original damaged member. All attempt IDs are owner-generated
16-byte values. A `frontier` is a closed map `{through, manifest, attestation}`
with both links null iff `through=0`. Nonempty links have DAG-CBOR/SHA256 codec.

- `created`: `{recipe: 1, member: digest, frontier}`. Exactly sequence 1; no later
  created event. The logical metadata/proof chain must independently verify.
- `unavailable`: `{member: digest, entries: [...]}`. One to 32 entries, each
  `{occurrence, cid, expectedLength, state}`. `occurrence` is a positive member
  sequence or null for a staged/orphan object; `expectedLength` is an expected
  length from authenticated metadata/membership or null only for an unreferenced
  staged/orphan object without an authenticated length, in either profile. `state` is `missing` or
  `corrupt`. No metadata-corruption state pretends a broken proof is trustworthy.
- `restored`: `{member: digest, cid, length, candidate}`. `candidate` is the raw/SHA256 CID of the
  verified candidate and equals `cid`; length is 1..4 MiB. The target must exist
  in member metadata, original membership or original object keys. Any known
  expected lengths must agree; conflicting references refuse. Unknown orphan
  length is established by this verified candidate, not invented historical data.
- `publication-intent`: `{attempt, member: digest, restorations: digest,
  output: digest, frontier}`. `output` is the expected O1 of the deterministic
  selected standalone output, checked before signing intent. Exactly one intent
  per attempt ID. No path/command is trusted as signed executable routing data.
- `publication-observed`: `{attempt, intent, output: digest, frontier}`. `intent`
  cites the exact prior intent statement. `output` is O1 of the fully verified
  standalone output, must equal the cited intent output commitment, using selected valid objects and unchanged original metadata.
  It reports an observed durable output; it never records service activation.
- `publication-failed`: `{attempt, intent, reason}`. Closed reason enum:
  `source-changed`, `invalid-candidate`, `destination-conflict`, `budget`, `io`,
  `verification`. It makes no assertion that an output file does not exist.

The 32-entry limit is subordinate to the 16 KiB envelope bound. Use another
linked observation when encoding would exceed that bound. All created/member
references must equal the independently recomputed original M1. Unavailable
entries must match the sampled original rows and authenticated expected
coordinates; restoration never deletes them. Restore and publication events
must reference the member fixed at creation, not a silently revised member.

R1 is `SHA256(domain || N(count) || items)`, where domain is ASCII
`tools.kan.recovery.restorations.v1` plus zero byte, and items in canonical CID
text lexical order are `F(binary CID) || N(length) || F(candidate bytes)`.
R1 includes every candidate with a matching restored observation strictly before
that intent's sequence. There is no optional unsigned selection list. Each must
verify against its content address and all known expected lengths. A verifier
replays the chain to reconstruct this exact historical set; candidates appended
after the intent never enter its R1. A different candidate set requires a new
attempt and intent. This makes restart verification independent of a lost job
process or an externally remembered subset.

The virtual standalone output contains exactly the union of original object
keys, authenticated record object references and original membership keys.
Every key needs verified bytes of all known expected lengths: use its verified
restoration candidate from this R1 set when present, otherwise its valid original
bytes. A still-missing/corrupt key refuses publication, including staged/orphan
keys. Never drop a corrupt orphan to make verification pass, add an unreferenced
new object, or use a candidate recorded after the intent. Recompute expected
output O1 from this deterministic union and unchanged records/plan/membership; both intent and
publication-observed must equal it and the original metadata frontier. The normal
standalone verifier still independently validates all signatures and profile
completion. A partial profile-3 member has no KNB1 publication operation; it stays
a retained recovery artifact until a separate metadata-extension design exists.

## Exact initial loss coverage

Derive one expected coordinate for each `(occurrence sequence, object CID)` in
member metadata. A shared CID used by two occurrences yields two distinct
coordinates, not a collapsed history. Add a null-occurrence coordinate for each
original membership key or original object key that has no occurrence reference;
never add a second null entry for a CID already represented by occurrences.
All authenticated lengths for a CID must agree or creation refuses. The expected
length is that agreed value, or null only for an unreferenced original object
without an authenticated length.

Sample each coordinate against the original member objects. Missing rows produce
missing entries; wrong length/hash produces corrupt entries; available entries
produce no unavailable event. Non-BLOB cells refuse creation under the M1 rule.
Sort occurrence entries first by ascending numeric sequence then canonical CID
text; sort null entries last by canonical CID text. No duplicate coordinate is
allowed. The concatenation of creation's unavailable events must equal this exact
ordered loss vector: omissions, extra entries, duplicate entries, conflicting
states or altered expected lengths refuse verification.

These events occur immediately after created, before restoration/publication.
Partition greedily into the largest consecutive prefix of at most 32 entries
whose canonical signed envelope fits 16 KiB; signatures have fixed 64-byte width.
No empty event is permitted. Empty loss coverage means created alone. Verifiers
recompute the same vector and partition; an unavailable event after that initial
coverage is invalid. Damage to the physical bundle after creation is an integrity
failure against its fixed M1, not permission to rewrite member bytes or insert a
new claim that retrospectively changes the initial sample. Preserve such media
and recover the bundle from verified backups; arbitrary forensic repair remains
outside KNB1.

## Physical tables

All tables use the exact frozen column order; any extra table/index/trigger/view
refuses normal bundle open. DDL must be generated once by the implementation and
pinned by canonical schema fixtures before a writer is accepted.

- `bundle_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), bundle BLOB,
  observer TEXT, profile INTEGER, archive BLOB, scope BLOB, issuer TEXT)`.
  Byte-width/profile/DID validation is mandatory on read and before writes.
- `member_records(sequence INTEGER PRIMARY KEY, manifest BLOB, receipt BLOB,
  envelope BLOB)`: sequence positive, manifest/receipt each 1..65536 bytes,
  envelope 1..16384 bytes; all NOT NULL. No ordinary `commits` or `attestations`
  table exists in this outer format.
- `member_objects(cid TEXT PRIMARY KEY, bytes BLOB NOT NULL) WITHOUT ROWID`:
  original bytes 0..4194304, key canonical but payload may be corrupt.
- `member_plan(singleton INTEGER PRIMARY KEY CHECK(singleton=1), envelope BLOB
  NOT NULL)`: no rows for profile 2, exactly one 1..4096-byte row for profile 3.
- `member_membership(cid TEXT PRIMARY KEY, length INTEGER NOT NULL) WITHOUT ROWID`:
  profile 3 only, canonical CID and length 1..4194304.
- `observations(sequence INTEGER PRIMARY KEY, envelope BLOB NOT NULL)`:
  canonical contiguous observation chain, envelope 1..16384 bytes.
- `restored_objects(cid TEXT PRIMARY KEY, bytes BLOB NOT NULL) WITHOUT ROWID`:
  bytes 1..4194304 and exact content address. Every row must have one matching
  restoration observation; every restoration observation must have its candidate.

SQL constraints enforce local type/size bounds; the verifier independently
checks all semantic/profile/cardinality/chain conditions. In particular, empty
observation history cannot convert a bundle into a standalone archive.
Publication constructs an entirely separate normal profile; changing a marker
or renaming a table never constitutes publication.

## Required pre-implementation review

Review the event state machine, all cross-file crash outcomes and the ability to
resume or record failure without rewriting history. Freeze actual DDL, canonical
positive/re-signed-negative vectors and an independent Python encoder/verifier
before storage mutations are implemented. Pin M1 and R1 against independently
constructed empty, staged, missing, corrupt, restored and partial-copy fixtures.
Whole-output verification must include ordinary writable schema, original writer
signatures, issuer proof chain and profile-3 completion; M1 alone proves none of
those properties. The observer can report evidence, but cannot grant admission,
erase historical loss or assert a fabricated complete source-copy recipe.

### Publication state and replay rules

An attempt ID has exactly one intent. It may have zero or more failed observations
and at most one observed publication. A failure is evidence of an unsuccessful
check, not a terminal assertion that no valid output exists. Explicit resume may
therefore append observed after failure when it verifies that same attempt's
selected commitment and owner-specified output. No failed or second observed
record may follow observed for that attempt. A changed selection or different
output identity requires a new attempt ID and intent. Independent verifiers must
validate these relationships from the complete observation chain, not a mutable
status column.

Creation's single publication transaction includes a created event plus enough
unavailable events to cover every unavailable expected occurrence, every
missing/corrupt original-membership key (including unreferenced staged objects),
and every corrupt retained orphan row. Missing orphans with no surviving expected
coordinate cannot be invented. Exact repeated restoration is idempotent: return
the prior candidate/observation, without a new row or signature. A candidate
insert without its observation, or observation without its candidate, refuses.

The owner-selected observation frontier is an external checkpoint, comprising
sequence and statement CID under the full bundle/observer binding. Verifiers
must prove that checkpoint belongs to the observed chain and distinguish it from
any later verified extension. A file cannot supply its own rollback-detection
checkpoint. No cross-copy anti-equivocation beyond the explicitly pinned chain
is claimed.

### Checkpoints and multiple completed outputs

Several attempt IDs may each reach publication-observed. Each creates a separate
physical standalone output with the member's logical archive identity; none
activates a service. The owner must select exactly one live writer and fence the
others through the separately authorized activation workflow. The bundle cannot
promise that privileged manual configuration obeyed that workflow.

Every successful mutation/job result returns the verified observation frontier
(sequence plus statement CID and full binding), including a committed failure
observation. The owner verifies and durably retains it outside the bundle before
advancing the recovery UI's independently checkpointed status. On restart the
owner supplies the latest retained checkpoint; valid extensions are reported
separately until retained. A tail truncated after the latest external checkpoint
is not detectable. The online observer key can attribute new statements but does
not itself provide an independent tamper-evidence or non-equivocation witness.
An uncertain response may require explicit inspection and checkpoint advancement;
do not derive the external pin from the bundle being verified.

### Scope-C follow-through before format acceptance

The governing bundle design's "custody and owner-visible limits" section is part
of this codec contract: pre-open path checks cover all participating databases;
partial-copy restart provenance is external job state only; forensic-only source
cells are a named recovery gap; unrecoverable staged/orphan keys explicitly block
publication. None changes the byte recipes or adds a silently unsigned field to
the closed observation schema. Draft SQL and wire fixtures still require their
own independent review before acceptance or any storage writer.

## First implementation checkpoint: observation authentication

`src/evidence_recovery_observation.rs` implements only bounded canonical wire
validation, static P-256 owner pins, observer signature attribution and contiguous
observation predecessor links. `Authenticated` has private construction and
carries no bundle-completeness, member-truth or publication-state authority.
`sign_claim` is a pure signer and round-trip validator; its caller must establish
the permitted operation and semantic truth before using it. There is no storage
consumer, mutation, file routing, checkpoint acceptance or browser API here.

Independent Python fixtures exercise the six event forms, exact statement/CID/
signature bytes, maximum wire shapes and re-signed hostile cases. Their member,
restoration and output digest values deliberately do not establish a valid full
bundle. A wire-valid claim may still be false; complete bundle verification must
reject those false claims. The Rust API does not provide JSON serialization or
accept a caller-constructed predecessor as authenticated history.

The accompanying SQL fixture is a **draft** local-constraint schema, exercised
in memory with no publication markers. The M1/O1/R1 Python oracle is a **draft**
framing oracle, not a signed-record or complete-member verifier; synthetic record
bytes in its framing cases do not qualify any archive. Neither draft is accepted
as a storage compatibility promise by this checkpoint. Before a bundle writer:
implement and independently qualify streaming commitment computation, complete
member/proof validation, exact loss partitioning, candidate/history consistency,
publication replay and external-checkpoint validation; then freeze their complete
cross-implementation vectors and DDL. All recovery writer/job/RPC/UI criteria stay
open until their real operations and crash outcomes are tested and reviewed.

### Second independent review decisions

Observer authority is a separate role and signature domain from archive issuer
authority. The wire codec permits explicitly pinned equal observer/issuer DIDs;
it never treats an observer signature as an archive proof. Distinct-key policy
belongs to owner configuration. Recovery job configuration should default to a
separate observer key and disclose explicit reuse; equality in the wire is not
proof of independent authorities or compromise isolation. This interpretation
of parent REQ-1 is recorded rather than silently requiring a new wire restriction.
The same-key role fixture pins this decision.

Refusal reason strings in the cross-implementation fixtures identify their
single-fault cases. They do not define a total precedence for inputs with several
independent faults: Rust and Python may name different first faults while both
refuse. No authorization or state transition may depend on which diagnostic
string wins. Acceptance and byte identity remain the interoperability contract.

The expanded fixtures now distinguish canonical CID text order from binary order
for unavailable entries, original membership, original objects and R1 candidates.
The draft DDL bounds identifier text by bytes, excludes embedded NUL and requires
printable ASCII; complete canonical DID/CID validation remains a verifier duty.
SQLite's lossless affinity coercion is not a promise about caller bind types:
writers must bind typed values and readers must still check stored types.

An authenticated expected object length above 4 MiB also refuses KNB1 creation
as `forensic-recovery-required`, even when no oversized physical row survives.
Do not truncate the expected length or drop that reference to fit the format.
Retain source and failed output; the generic manifest schema's larger integer
range does not widen this proposed recovery format's representable object size.

## Next checkpoint draft: bounded streaming framing

The draft `evidence_recovery_commitment` module computes M1/O1/R1 incrementally.
Its caller supplies section counts and strictly increasing canonical CID-text
order; it does not allocate an archive-sized sort or payload buffer. Separate
membership/record/object stages enforce counts and contiguous record positions.
Any rejected builder operation poisons the builder, so ignoring an error cannot
produce a digest over fewer records. Empty corrupt originals remain representable;
restoration candidates must be nonempty and match their raw CID.

Owner-selected item, work-byte, time and cancellation limits bound computation;
hashing polls at most every 64 KiB. Work-byte accounting includes framing and,
for restoration, both candidate verification and commitment hashing. It does not
bound prior caller acquisition or arbitrary filesystem stalls. The caller remains
responsible for authorized bounded source reads and complete member semantics.
DID/record/plan truth, candidate membership and full state replay are not supplied
by these framing digests. This draft has no storage consumer. Author qualification passes eight commitment
tests against independent Python vectors and nine compiled controls, with strict
v2 Clippy and formatting. Evidence is in
`.design/reviews/kan-v2-recovery-commitment-author/`. Fresh independent review
remains pending; full member and state verification are separate prerequisites.


### Streaming review follow-through

Actual Opus 5.5 review of a8927a6 found no production defect and returned
APPROVE WITH FOLLOW-UPS; full raw evidence is retained in
`.design/reviews/kan-v2-recovery-commitment-opus/`. RA3/RA4 section/count/size
probes are promoted. Test-only cancellation injection qualifies polling within
hashing without timing sleeps; the original independent timing probe and its
recorded limits remain preserved. These follow-through tests pass author qualification: ten integration functions,
two deterministic polling units and thirteen compiled controls, plus strict
Clippy/format and the independent oracle. Evidence is in
`.design/reviews/kan-v2-recovery-commitment-followups-author/`. Fresh review with
the member-verifier checkpoint remains required.

The 1..80-byte framing issuer bound is explicit above and now shared by the
Python oracle. UTF-8 is pinned for future physical creation and opening. An O1
digest from the framing builder alone still authenticates no output bytes:
full object/writer/profile verification must precede publication. None of these
changes accepts the physical format or closes parent acceptance criteria.

## Next verifier checkpoint: logical member and initial availability

The pure member verifier takes an owner-pinned context and borrowed, ordered
record, membership and original-object slices. Its caller must acquire those
bytes with bounded reads before calling; this is not a SQLite opener. The physical
reader must reject noncanonical original CID text before constructing typed CIDs;
parsing a spelling and silently normalizing it is not source validation. Explicit
item/input-byte/time/cancellation limits bound this invocation. It stores only
bounded metadata coordinates, never copies the whole payload collection. Hashing
polls per 64 KiB; canonical decoding, request verification and signatures are
individually bounded operations with cancellation checks around them.

Independently verify the contiguous issuer chain, admitted versus retained-copy
purpose, static service writer form, per-writer position/predecessor, unique
operation, the service operation-to-slot commitment and consistent slot bindings. Profile 3 additionally binds its plan,
original membership and retained-prefix metadata digest. An unfinished prefix is
reported as incomplete; matching metadata alone does not certify missing writer
signatures or retained bytes. No standalone publication capability is returned.

Every known length must be positive, at most 4 MiB, and agree across references
and original membership. Retain raw corrupt/empty originals in M1. Verify each
present object's hash once and sample every occurrence separately; unreferenced
membership/original keys receive null-occurrence loss coordinates. A hash-valid
request that fails its writer signature or exact manifest binding is invalid
member evidence, not a repairable missing-byte condition. Missing/corrupt requests
remain unavailable, with writer verification still outstanding. Loss output is
strict occurrence/CID-text order, followed by null coordinates in CID-text order.

This checkpoint must be qualified before it can feed full observation replay.
Greedy signed-loss partitioning, historical restoration/output selection, replay,
checkpoints, physical schema and all storage mutations remain separate work.


The logical-member draft passes author qualification: 16 Rust functions,
independent signed Python fixtures, eight semantic controls (one additional
cancellation control survives because framing refuses later), strict Clippy and
formatting. Raw results are in
`.design/reviews/kan-v2-recovery-member-author/`. Fresh independent review is
pending; this is not full bundle acceptance.
