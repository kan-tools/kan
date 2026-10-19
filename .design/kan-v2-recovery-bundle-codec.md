# Proposal: KNB1 recovery bundle codec and member commitment

This freezes the proposed byte/schema choices for independent design review of
`kan-v2-recovery-bundles.md`. It is not an implemented format. No writer may use
these bytes as a compatibility promise until the design and independent vectors
are reviewed. The parent bundle requirements and publication distinctions apply.

## Identities and canonical values

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
DIDs use UTF-8; CID frames use canonical binary CID bytes; record/envelope frames
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

All digests below are 32-byte M1 values. All attempt IDs are owner-generated
16-byte values. A `frontier` is a closed map `{through, manifest, attestation}`
with both links null iff `through=0`. Nonempty links have DAG-CBOR/SHA256 codec.

- `created`: `{recipe: 1, member: digest, frontier}`. Exactly sequence 1; no later
  created event. The logical metadata/proof chain must independently verify.
- `unavailable`: `{member: digest, entries: [...]}`. One to 32 entries, each
  `{occurrence, cid, expectedLength, state}`. `occurrence` is a positive member
  sequence or null for a staged/orphan object; `expectedLength` is an expected
  length from authenticated metadata/membership or null only for a profile-2
  staged/orphan object without an authenticated length. `state` is `missing` or
  `corrupt`. No metadata-corruption state pretends a broken proof is trustworthy.
- `restored`: `{cid, length, candidate}`. `candidate` is the raw/SHA256 CID of the
  verified candidate and equals `cid`; length is 1..4 MiB. The target must exist
  in member metadata, original membership or original object keys. Any known
  expected lengths must agree; conflicting references refuse. Unknown orphan
  length is established by this verified candidate, not invented historical data.
- `publication-intent`: `{attempt, member: digest, restorations: digest,
  frontier}`. The second digest is R1 below. Exactly one unresolved intent per
  attempt ID. No path/command is trusted as signed executable routing data.
- `publication-observed`: `{attempt, intent, output: digest, frontier}`. `intent`
  cites the exact prior intent statement. `output` is M1 of the fully verified
  standalone output, using selected valid objects and unchanged original metadata.
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
Only candidates selected for the publication attempt enter R1. Each must verify
against its content address and all known expected lengths. No unsigned selection
list can substitute a different candidate after the intent is committed.

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
unavailable events to cover every unavailable expected occurrence and every
corrupt retained staged/orphan row. Missing orphans with no surviving expected
coordinate cannot be invented. Exact repeated restoration is idempotent: return
the prior candidate/observation, without a new row or signature. A candidate
insert without its observation, or observation without its candidate, refuses.

The owner-selected observation frontier is an external checkpoint, comprising
sequence and statement CID under the full bundle/observer binding. Verifiers
must prove that checkpoint belongs to the observed chain and distinguish it from
any later verified extension. A file cannot supply its own rollback-detection
checkpoint. No cross-copy anti-equivocation beyond the explicitly pinned chain
is claimed.
