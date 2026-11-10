# V2 record/recall compatibility map

Implementation contract for kan-v2-record-recall-and-extraction.md, approved
2026-11-02. The Nov10 baseline32e2f6c passed service/native CI and a fresh retrieval
exercise, but independent review found missing v1-side parity fixtures and other
gaps. The current correction adds real v1 action/read comparisons; their current
remote outcome must be inspected before any new parity claim. No Day cutover is
implied by this map or by the source-level implementation.

## Canonical representation

Use existing canonical claim codecs and the existing deterministic fold. The
first transport bridge carries explicitly labelled kan-claim-v1 compatibility
records; it does not pretend a storage proof scope is an enrolled governed
ScopeId or fabricate did:kan control history. Native kan-claim-v2 input remains
subject to its existing identity/control checks. Existing original claim bytes,
CIDs and signatures are not rewritten by transport or restoration.

An explicitly selected v2 record collection binds record scope separately from
optional evidence citations. A canonical content-addressed descriptor of that
collection can serve as a Blob anchor; it is not a fabricated Git genesis.
Local subject names are interpreted only in that collection. Per-author claim
signatures, the collection descriptor and outer source admission remain separate.
No cross-collection merging is inferred from matching subject strings. This
first authored bridge creates new canonical compatibility records. Existing
original v1 imports retain their existing signed source/import interfaces and
bytes; they are not silently re-authored into the new collection or folded as
local notes. The separate adapter remains necessary to carry old Day identity,
role, control and JSON contracts across a real cutover.

A new versioned authored publication envelope carries canonical records without
reinterpreting kan-annotation/1. Existing ordinary annotations/publications remain
readable. Persistence uses the already encrypted, signed workspace and immutable
publication path, with the same lifecycle/custody checks. A new envelope must
validate inner signatures and source scope on save, read, publication and restore.
Empty evidence citations never substitute for scope authorization.

## Verb map

| Verb | Required typed behavior | Reused contract |
|---|---|---|
| observe | Observation; optional subject defaults to general | claim::v1::ClaimBody, actions::observe |
| plan | Plan, not Decision or Status | actions::plan |
| decide | Decision, no automatic independent verification | actions::decide |
| result | Result for named subject, no implicit resolution | actions::result |
| block | Blocker plus Blocked status citing that blocker | actions::block |
| resolve | Resolution plus Resolved status citing that resolution | actions::resolve |
| same | Directed SameAs witness; trust determines the merge | fold::identity |
| relate | Typed directed relation; existing relation projections | fold::relations |
| mark | Explicit Status, retaining earlier positions | actions::mark, fold::state |
| retract | Same-author correction, including undo by retracting retraction | fold::identity, actions::retract |
| reject | Other-author suppression under selected trust only | actions::reject, fold::identity |
| show | Stable reference or subject; live/history/source distinctions | fold::fold, json::ClaimJson |
| status | Existing settled/confirmed/contested classification | fold::state |
| issues | Existing open-subject semantics, not every annotation | actions::issues_json |
| context | Existing ranking/token estimator, trust and omissions | context::assemble_reporting |

Narrative status/title/kind options retain their paired-claim semantics. A single
record request persists the complete paired batch, not a half-written blocker or
resolution. An explicit operation receipt makes identical retries idempotent;
recording the same text as a new operation is a new attested claim. Return the
canonical inner claim CIDs, outer authored-declaration reference and durability
state separately.

## Honest compatibility boundaries

- Versioned v2 output may reuse existing v1 rendered types, but must not advertise
  Day JSON compatibility until all required envelopes/fields are tested.
- Explicit supplied Git/file/commit artifacts remain literal typed anchors.
  Missing repository ancestry is unavailable context, not an invented computed
  edge. A context-dependent operation must report the limitation or refuse;
  matching a few simple fixtures is not complete v1 parity.
- Identity/role setup, GitTree publication/restore and live migration keep their
  existing explicit contracts. No record command silently invokes kan-v1,
  discovers a shared-root checkout or creates/migrates credentials.
- Derived model reports remain run outputs. Promotion is a separate attributed
  operation retaining original inputs/model/recipe/report lineage.

## Verification map

Compare canonical bytes, signature checks, kind/body pairs, paired cites,
retraction/rejection, SameAs witnesses, statuses, trust exclusions and context
omissions against the existing pure fold and v1 action fixtures. Test two authors
and two unrelated collections. Negative cases include a caller claiming another
signer, wrong collection, missing scope authority, invalid signature, conflicting
retry intent, unsupported future codec and old publication compatibility.

Service-level tests must cover uncited save/read/restart, cited source revocation,
no read-to-write escalation, publication/delivery state, retained-source restore
and erasure dependencies. The real two-path demo follows synthetic qualification;
its model/credential reference/input and spend envelope are selected separately.
