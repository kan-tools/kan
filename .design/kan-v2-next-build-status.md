# Kan v2 continuation status

This is the execution ledger for the approved remaining roadmap. Permanent
worktree: `.worktrees/kan-v2-build-next`; branch: `feat/kan-v2-build-next`.
It builds on the stacked evidence-availability design, preserving existing drafts
and the root checkout's unrelated edits. No production archive, key, deployment,
installation, live migration or main merge has occurred.

## Library qualification

Commit 4b0ebc1 validates all scope entries before navigation, adds malformed
catalog recovery cases, and requires the contention fixture to observe actual
SQLite wait. Fresh actual Claude Code Opus 5.5 reviewed that exact checkpoint:
APPROVE WITH FOLLOW-UPS. The original report, mutation traces and identity are in
`.design/reviews/kan-v2-library-scope-opus/`. Reviewer boundary/state probe tests
have subsequently been incorporated. Test wrapper spent-return fidelity remains
a small open regression gap, with implementation forwarding it unchanged.

Native browser access remains blocked by a locked Mac. A new in-app browser
attempt displayed the exact 64-byte binary fixture but timed out awaiting the
actual download event. Delivery remains unverified. Tab and fixture were stopped;
see `.design/reviews/kan-v2-library-scope-followup/browser-delivery.txt`.

## Missing-evidence prerequisites

The first protocol review returned BLOCK (weak negative fixtures, issuer ambiguity,
pagination linkage). The correction at b81eb4f received APPROVE WITH FOLLOW-UPS
for design readiness only. Both raw reports are retained. Later follow-ups now
specify current-audience RetryImported confirmation, historical-source audience
checks, archive provisioning, purpose ordering and append-only recovery observations.
Those later rules require runtime implementation and review.

The Rust attestation codec is a separate first implementation slice. It shares
strict bounded canonical decoding, verifies exact issuer/archive/scope/metadata
and chain commitments, signs P-256 low-S proofs and verifies descending rows against
a pinned frontier. It consumes two independent exact-byte signed vectors and sixty
labelled negative vectors. Some vectors intentionally exercise individually valid
proofs in a purpose order that the future store must refuse; they do not model an
admissible upgrade/capture history.

Author validation: 95 integration checks across attestation, canonical codec,
store, service, reader, real CLI and surface conformance; all-target v2 Clippy;
14 compiled semantic mutations fail named assertions, exact source restored;
27 whole-check oracle mutations fail. These bounded mutation sets do not prove
all possible weakenings are detected. Fresh actual Claude Code Opus 5.5 reviewed
2e96685: APPROVE WITH FOLLOW-UPS for the codec only. Its unmodified report and
probes are preserved in `.design/reviews/kan-v2-attestation-codec-opus/`. It independently
passed the 95 integration checks, 50 Node checks, Clippy/fmt and 13,420 hostile
byte variants. Short-issuer and descending error-label regressions are required
before storage integration; detached proof authority, fuller independent source
schemas and independent page vectors remain follow-ups for the consuming slices.

No profile-2 table, admission transaction, copy upgrade, backup/restore extension,
Inventory RPC, cursor MAC, proof-aware spool release or unavailable-evidence UI is
implemented by the codec. All six storage-design acceptance criteria remain open.

## Remaining ordered build

1. Profile-2 authoritative proof storage in permanent worktree
   `.worktrees/kan-v2-proof-storage`, branch `feat/kan-v2-proof-storage`;
   atomic admission/retry and process-death/hostile-append qualification.
2. Owner-copy upgrade and proof-preserving backup/recovery with surface conformance;
   explicit degraded inventory server, descending RPC/cursor framing, source
   authorization and available/missing/corrupt Library rows.
3. Bounded deduplicated collection overview from the existing collection design.
4. Versioned human-readable conversation adapters with source lineage.
5. Authorized search/filters, annotations, saved views, background analysis/day
   integration and owner admin workflows from the full frontend design.

Every substantive build/fix checkpoint receives fresh actual Opus 5.5 review.
Browser delivery, deployment placement and live cutover remain explicit unresolved
operational gates; they do not justify pretending the software roadmap is complete.
Git-first design/review records await backfill while day#168 / kan#197 prevent
worktree-local recording. The existing raw-data-and-projections telos is deliberately
unwitnessed; no witnesses or omitted claim contents were invented.
