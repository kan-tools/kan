# Recovery observation codec: author checkpoint

Pure wire authentication and signing, no storage consumer. Authenticated records
establish the observer signature and contiguous chain under independently
supplied owner pins; they do not establish member truth, complete loss coverage,
candidate ownership, publication state, external checkpoints or durable storage.
See the governing codec design's first-implementation checkpoint.

Qualification:
- 31 Rust functions pass across observation (6), decoder (15), attestation (7)
  and copy-plan (3).
- Independent Python: 6 chain positives, 3 maximum-shape positives, 56 hostile
  re-signed/malformed wire vectors. Rust matches exact bytes/CIDs/signatures and
  refusal classes. Positive digest claims are deliberately not whole-bundle truth.
- Seven compiled targeted controls fail named assertions: bundle pin, predecessor
  context, predecessor CID, signature, restoration CID equality, loss ordering,
  closed event body. Restored six-function observation suite passes.
- Strict all-target v2 Clippy passes. Final formatting passes after a formatting-
  only correction of the signer comparison.
- Draft commitment oracle passes 7 member and 3 restoration framing cases;
  draft schema passes 5 local-constraint tests in memory. Neither is a complete
  archive verifier, accepted DDL, nor cross-implementation Rust commitment test.

Failed author attempts are retained: a shape-vector Python comparison mistakenly
compared a native Link with fixture notation; fixed to compare native Links.
Clippy caught an unnecessary owned DID comparison; fixed. The subsequent format
check requested collapsing that comparison; formatting corrected without a
semantic change. Initial successful smaller wire suites are retained as history.
No production archive/key/network request, installation, service or live migration.
Fresh actual Opus 5.5 review remains required before claiming this checkpoint
accepted. All bundle writer/job/RPC/UI acceptance and full reconstruction remain
open.
