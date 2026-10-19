# Feature: preserve opaque bytes at the common claim envelope boundary

## Summary
A canonical untagged CBOR byte string must remain bytes even when its payload
happens to parse as a CID. The generic atproto-dasl0.14.5 Ipld visitor guesses
links from payload bytes. The common claim reader then reencodes a tag and
rejects the original canonical record. A tag-aware decoder should preserve
raw evidence without changing released signing domains or weakening verification.

This investigation follows performance run39315201306 failing at synthetic
claim723 with a canonicality refusal. That exact offending record was removed
by the performance script's scratch cleanup. The relationship to that run is
a hypothesis until independently reproduced; this design does not claim its
root cause proved or the performance gate passed.

## Requirements
- REQ-1: Decode byte/link types from actual CBOR headers, including nested values. Only tag42 introduces a CID. Do not guess a link from opaque bytes.
- REQ-2: Preserve strict canonical scalar/map/tag/trailing-byte checks and existing envelope, codec, content, identity and signature checks. Retain existing numeric support and depth bounds; no invalid signature becomes supported content.
- REQ-3: Preserve future envelopes byte-for-byte and keep typed-content encoding from inserting tags into opaque bytes. Existing valid claim encodings and signature domains remain unchanged.
- REQ-4: Reproduce the old boundary failure with deterministic typed-byte fixtures, demonstrate failure after reverting the production correction, qualify normal/v2 affected tests and strict lint, and obtain fresh actual Opus5.5 review.

## Acceptance Criteria
- [ ] AC-1: A future common envelope with CID-shaped signature and nested bytes, alongside genuine links, decodes and reencodes exactly. Reverting the decoder correction fails the assertion. (REQ-1, REQ-3)
- [ ] AC-2: A supported envelope with an invalid CID-shaped signature reaches signature rejection rather than fabricated canonicality refusal or successful verification. Existing valid signed fixtures round-trip. (REQ-2)
- [ ] AC-3: Ordered/duplicate keys, malformed tags, nonminimal scalars, indefinite lengths, non64bit floats, trailing data, depth and allocation bounds remain enforced. Signed/domain encoding does not change. (REQ-2, REQ-3)
- [ ] AC-4: Affected checks and fresh actual Opus review pass with retained failures/controls. The separate CI generation failure is either reproduced with retained input and resolved or remains explicitly open. (REQ-4)

## Architecture
A private claim decoder uses the dependency's strict low-level CBOR scalar
reader and constructs Ipld values by explicit header type. It bounds allocations
by available input and retains the dependency's default nesting ceiling. The
existing common-envelope reencoding equality check remains. The same helper
handles typed content before adding its declared content type. It does not
change claim IDs, signatures, on-disk envelopes or trust rules.

Other generic Ipld consumers, including additive identity/control and nested
claim serde adapters, require a separate inventory. This correction must not be
represented as a repository-wide replacement or a proof that all opaque-byte
boundaries are repaired. V2 evidence already has its own strict type-preserving
parser; do not silently broaden its narrower scalar contract.

## Process
Permanent branchfeat/kan-v2-codec-boundary starts from frozen918318d. Changes are
not made to the separate Content/creation reviewer export. Git-first recording
continues under day#168/kan#197; no live log reads, migrations, key access,
reconstructed excluded claims or invented witnesses. The candidate has now passed author qualification and fresh independent Opus
review at bf3c44e. The report in `reviews/kan-v2-combined-followups-opus/`
identifies remaining regression-test follow-ups; parent acceptance stays open.


## Failure evidence follow-through
The performance generator now optionally retains only its synthetic `repo.car`
and `HEAD`, with sizes and SHA-256 hashes, before deleting its disposable workspace.
The workflow enables this and uploads it with the existing result table even on
failure. The collector is capped at 64 MiB total, reports oversized/absent inputs
explicitly, refuses final-component symlinks and never overwrites an earlier
attempt. It does not export the scratch signing identity or whole workspace.
Three Python checks pass, including driving the actual shell generator with a
failing fake CLI; generation remains failed and retained bytes match. This makes
a future recurrence diagnosable. It does not recover the already-deleted record
from run39315201306 or prove that run's root cause.

`day design check` was attempted in this worktree and refused its missing local
kan workspace under day#168/kan#197. That is unavailable validation, not a passing
check, and no redirect to the main checkout's log was attempted.
