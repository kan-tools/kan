# Feature: kan v2 buildout contracts and sequenced delivery

## Summary

Turn the service architecture in `.design/kan-v2-server-first.md` into a bounded implementation sequence: establish evidence and access contracts, build the durable storage core, then add encrypted service access, migration, capture, and operational recovery. Keep the architecture and this buildout plan as separate stacked documentation PRs, followed by small implementation slices whose merge conditions name observable evidence. Work proceeds from versioned files even when the current day recorder cannot establish subject absence.

Status: proposed buildout contract, 2026-10-16. The parent architecture is draft [PR #264](https://github.com/kan-tools/kan/pull/264), branch `design/kan-v2-server-first`. This document starts on `design/kan-v2-buildout`, forked at `fde036b86469f8b1d245bce2a1d8f0c39399ba94`, in the permanent worktree `/Users/m/code/kan-tools/kan/.worktrees/kan-v2-buildout`. No implementation, deployment, or merge is claimed by this document.

## Requirements

- REQ-1: Maintain an explicit PR dependency order with separately reviewable architecture, contract, storage, service, migration, capture, and operational slices. A descendant is reviewed against its parent while stacked and is merged to main only after the parent lands.
- REQ-2: Preserve the parent design's accepted product decisions and identify unresolved decisions by the first slice that needs them. Open key custody or provider choices must not prevent unrelated contract and fixture work.
- REQ-3: Define evidence inventory independently of interpretation: authorized source existence, signature validity, scope admission, and consumer trust cannot collapse into one filtered result. An unrelated excluded claim cannot make every new subject impossible to append.
- REQ-4: Give every logical API operation typed preconditions, visibility boundaries, idempotency rules, and stable failure semantics before exposing it as a service endpoint. Fix exact wire bytes and protocol versions in a separate reviewed contract before production interoperability is claimed.
- REQ-5: Map every authoritative artifact, cache, credential, and operational checkpoint to a persistence owner. No service writer may bypass the surface catalog and the admission/idempotency commit boundary.
- REQ-6: Build the crash-safe ledger with synthetic opaque ciphertext fixtures before coupling it to a real gateway or model provider. Remote durability must be testable without inference traffic or a working query index.
- REQ-7: Separate access capabilities for ingest, raw evidence inventory, plaintext reading, provider forwarding, backup, and administration. Choosing a trust frame never grants content access or append authority.
- REQ-8: Deliver local legacy discovery and preview before bulk upload, then resumable encrypted import through the same service ingest path. Preserve raw source identities and verify imports independently of old display filters or memory limits.
- REQ-9: Pin the first harness/provider integration before claiming capture coverage, while developing generic spooling and forwarding behavior against a fake provider. Exhausted capture continues inference with a visible gap, as selected in the parent design.
- REQ-10: Define backup completion, restore verification, final migration cutover, and erasure behavior before recommending the service as the user's primary archive. Successful append alone is not operational readiness.
- REQ-11: Keep unknown input shapes, failed inspections, pending imports, read exclusions, missing keys, and incomplete capture as explicit states. Preserve these states through CLI/MCP and future query clients rather than translating them into empty success.
- REQ-12: Every implementation slice supplies executable witnesses tied to parent acceptance criteria and checks compatibility at its own boundary. Documentation checks do not substitute for runtime, cryptographic, or recovery evidence; external review and actual CI status must be reported honestly.

## Acceptance Criteria

These criteria are **implementation intent**. The named witnesses are proposed tests or review artifacts, not existing passing checks. They complement the parent design's AC-1 through AC-24.

- [ ] AC-1: Intent; witness `stack_scope_review`: compare each PR to its declared base; only its own slice appears, the dependency links resolve, and no child merges into an unmerged ancestor. (REQ-1)
- [ ] AC-2: Intent; witness `decision_dependency_review`: every open decision has an earliest dependent slice; storage-only fixtures run with no chosen provider and no production encryption profile. (REQ-2, REQ-6)
- [ ] AC-3: Intent; witness `unrelated_exclusion_does_not_block_append`: place two view-excluded claims on another subject, prove an authorized exact existence query for a new subject returns absent at a pinned snapshot, and append to it without changing consumer trust. A genuinely withheld scope returns access-limited rather than absent. (REQ-3)
- [ ] AC-4: Intent; witness `operation_contract_vectors`: each operation in the contract table has successful, duplicate, unauthorized, conflicting, unsupported, and interrupted fixtures where applicable; supported independent decoders agree on canonical identifiers and error classes. (REQ-4, REQ-11)
- [ ] AC-5: Intent; witness `service_writer_inventory`: compare declared persistence owners against actual mutation sites; fail when a new column/file or alternate ingest path lacks a catalog row and capability. (REQ-5)
- [ ] AC-6: Intent; witness `opaque_ledger_fault_matrix`: kill the synthetic ingest service at each staging, manifest, index, and receipt boundary; all acknowledged events remain retrievable, retries are idempotent, and missing cache files trigger bounded recovery or explicit rebuild state. (REQ-6)
- [ ] AC-7: Intent; witness `capability_separation`: an ingest-only principal can submit valid bounded evidence but cannot read history, a backup principal cannot decrypt, and a trusted-but-unadmitted writer cannot mutate the ledger. The gateway cannot unwrap arbitrary historical objects. (REQ-7)
- [ ] AC-8: Intent; witness `migration_stages_end_to_end`: preview performs no network upload or source write; interrupted upload resumes from receipts; byte/CID reconciliation and old subject namespaces survive import and clean-host restore. (REQ-8, REQ-10)
- [ ] AC-9: Intent; witness `capture_profile_qualification`: run the supported adapter coverage matrix, unknown-outcome scenario, and spool-exhaustion case against a fake provider and the selected real integration. A live integration is not called complete on synthetic fixtures alone. (REQ-9)
- [ ] AC-10: Intent; witness `primary_archive_readiness`: restore on a clean host from independent backup, report the uncovered interval, verify selected erasure semantics, and reconcile the final import frontier before client cutover. (REQ-10)
- [ ] AC-11: Intent; witness `state_disclosure_contract`: CLI and MCP expose the same typed absence, withholding, unknown-version, gap, corruption, and pending states; no adapter reduces any of them to an empty collection without disclosure. (REQ-11)
- [ ] AC-12: Intent; witness `slice_release_evidence`: every completed slice names real executable witnesses, their results and supported versions, the exact diff reviewed, and outstanding limitations; no future witness name is marked passed without execution. (REQ-12)

## Architecture

### 1. Continuity and what is already decided

The parent design supplies the product architecture, including centralized cross-project storage, the same local/remote service implementation, blind payload storage, a separately trusted forwarding kernel, indefinite retention until explicit erasure, rich personal-instance operational metadata by default, optional obfuscation, gap-visible inference continuity, a local migration tool, and the later day merger. This plan does not reopen those choices.

The code reference is the same baseline as the parent. `src/claim/codec.rs`, `src/claim/view.rs`, `src/identity.rs`, and `src/uri.rs` supply compatibility and identity semantics to preserve. `src/store/log.rs` is a legacy source/export implementation, not the template for the new all-history-independent hot path. `src/persistence.rs`, `src/surface.rs`, and `tests/fixtures/read-write-surface.tsv` establish the mutation ownership discipline.

Existing normative documents still govern the shipped system: `docs/SPEC.md`, `rfcs/1-identity-system.md`, and `rfcs/2-kan-uri-scheme.md`. Before implementing a changed public contract, the appropriate slice must explicitly amend or extend those documents through the established RFC process. An architecture draft does not silently authorize incompatible identifiers or reinterpret existing signed bytes.

### 2. The PR stack and merge sequence

```text
main
  └─ P0: design/kan-v2-server-first — architecture and migration direction (#264)
       └─ P1: design/kan-v2-buildout — this contract and delivery plan
            └─ later requirement-scoped implementation branches
```

The user explicitly requested a dependent branch/worktree and sequenced merges. That governs this stack instead of the ordinary process atom's default of branching every slice directly from main. P0 targets main; P1 targets P0 while P0 is open. Parent and child PR descriptions identify the dependency and their own validation. Draft status does not mean an architecture or wire format has been accepted.

Merge P0 first after review and relevant checks. Prefer the project's regular merge strategy so its commits remain ancestors of P1. Retarget P1 to main, verify its diff contains only the child delta, and rerun checks against the updated base before merging it. Do not merge P1 into P0 simply to clear the stack. Keep the parent remote branch until child retargeting is complete. If the parent is squash-merged or rewritten, replay only the child's commits onto the accepted base and re-review the resulting diff; do not merge duplicate architecture commits by accident.

Future implementation PRs use this same ordering. Keep the active stack short: only branch from an unmerged predecessor when the dependency is concrete; otherwise branch from the latest accepted main. Creation of this plan does not authorize automatic future merges, cleanup of active worktrees, or release publication.

| Slice | Depends on | Reviewable change | Exit evidence / parent coverage |
|---|---|---|---|
| P0 architecture | Existing main | Product direction and migration requirements | Parent design check and architecture review; open questions remain visible |
| P1 buildout contracts | P0 | This plan, logical operations, authority boundary, failure semantics, merge order | Contract/readiness review and design check; no runtime claims |
| P2 evidence contract and fixtures | P1 | Exact event/manifest/receipt formats, canonical identifiers, inventory/absence contract, exhaustive state tables, independent vectors | This AC-3/4/11; parent AC-4/10/11/18; explicit protocol/RFC amendments |
| P3 opaque storage core | P2 | Chunk staging, append/commit, durable receipts, bounded indexes, recovery and fault harness | This AC-5/6; parent AC-7/8/9/20 |
| P4 encrypted service and clients | P3 and key-profile decision | Admission/capabilities, key wrapping, local/remote API, exact retrieval, explicit annotation client, health | This AC-7; parent AC-1/2/5/10/12/18 |
| P5 local migration | P4 | Discovery/preview, streaming source reader, import mapping, batching, resume, verification; cutover remains disabled pending P7 | This AC-8; parent AC-17/21/22/23 |
| P6 capture and spooling | P4 and integration-profile decision | Fake provider first, then chosen harness/provider, request/stream evidence, bounded queues, visible gaps | This AC-9; parent AC-3/6/20 |
| P7 operational qualification | P5 and P6 | Independent backup, clean-host restore, selected erasure protocol, final delta/cutover, measured capacity | This AC-10/12; parent AC-16/19/24 and full MVP regression |
| P8 extraction and process | P7 plus separate extraction design | Versioned classification/segmentation/summaries, then background day assessment | Parent AC-13/14/15; deferred from storage MVP |

P5 and P6 are independent after P4. They may be implemented separately; merging them in that order keeps release accounting simple. This table is a sequence of reviewable outcomes, not a requirement to produce a large PR for each row: split further when a row cannot be reviewed coherently, preserving the named dependency and evidence.

P2 now has an experimental format slice in `.design/kan-v2-evidence-contract.md` and draft `rfcs/4-evidence-contract.md`, on `feat/kan-v2-evidence-contract`. It supplies a feature-gated pure codec, independent byte/CID vectors and inventory/retry decision tests. It does not complete this document's end-to-end AC-3/4/11: authenticated inventory, durable append and CLI/MCP disclosure require P3/P4. Before issuing real receipts, P3 must extend the draft with the concrete durability and genesis/frontier profile; P4 must settle signature/admission and encryption profiles. These extensions remain reviewed contracts, not undocumented runtime choices.

P2 parent coverage remains partial: parent AC-4 provenance has structural capture fields but no authenticated capture; AC-10 access/trust separation has pure decisions but requires P4 admission; AC-11 snapshot replay requires P3 journal coverage and P4 private projection; AC-18 capture URI semantics require a separate reviewed P4 RFC 2 extension. Existing RFC 1/2 semantics are preserved, not extended by this codec.

### 3. Evidence inventory must not be a trust-filtered fold

The observed v1/day failure supplies a concrete negative fixture. The default bulk read returns two excluded claims without a subject entry. Day therefore cannot distinguish absent from fully excluded subjects and refuses to record an otherwise unrelated new design. A one-off read including both observed authors showed both claims belong to design/rfc-2 and none to the new v2 design subject. No persistent trust policy was changed. This diagnosis explains a contract defect; it does not claim that the current code is fixed.

Separate these questions:

| Question | Authority and result |
|---|---|
| May this caller access the scope's inventory? | Access grant; denied or access-limited is not absence |
| Is this opaque event/object committed? | Blind ledger manifest membership at a named snapshot |
| Does this semantic subject have evidence? | Authorized reader over a complete subject index for the declared scope and frontier |
| Is this record authentic and admitted? | Signature/identity/admission judgments, reported separately |
| Should it influence this user's view? | Explicit consumer trust frame, evaluated after inventory |

The blind store cannot search encrypted subject names. An authorized reader may answer semantic existence after decrypting and indexing the permitted scope. Its index pins both the ledger frontier and processing frontier. If it lags, has unsupported records that may contain the subject, or cannot inspect part of the authorized evidence, it returns incomplete/unknown rather than absent. It need not include excluded content in a user's preferred view to establish inventory within the user's access grant.

Proposed semantic existence results are `present`, `absent-at-snapshot`, `incomplete`, and `access-limited`. Invalid or unsupported inputs retain separate diagnostics. For callers without inventory access, use a non-disclosing access-limited response rather than revealing existence through distinct missing/forbidden errors. Scope-wide absence is only meaningful when coverage and snapshot are explicit. Network-wide absence is not offered.

Appending an authenticated event is unconditional with respect to semantic subject absence: validate its capability, framing, occurrence identity, and quota at the commit owner. Day-style declaration deduplication can use complete inventory, immutable operation IDs, or an explicit conditional operation; it must not block ordinary append merely because a trust-filtered display omitted unrelated evidence. A `create-if-absent` operation, if later offered, must name its serialization and comparison rules; a separate read followed by append is not atomic.

### 4. Logical operation contract

These names describe typed operations. They are neither existing CLI commands nor finalized HTTP paths. P2 fixes transport encodings and versions; P4 exposes them through one shared API consumed by local and remote clients.

| Operation | Preconditions and input | Result and visibility boundary |
|---|---|---|
| Stage encrypted chunk | Scoped ingest capability, ciphertext digest, declared length, bounded stream | Immutable stored-object commitment; no event visibility or durable-event receipt yet |
| Commit event batch | Exact event envelopes, installed object references, occurrence keys and digests, batch operation ID | All-or-nothing batch manifest visibility and signed remote-durable receipt; same operation+content returns prior result; changed content conflicts |
| Read encrypted evidence | Exact opaque ID/snapshot and authorized access | Original ciphertext plus commitment and coverage/error state; never an interpreted summary |
| Enumerate evidence | Authorized routing scope, snapshot, cursor, bounded page limit | Pinned committed members, continuation and completion state; no consumer-trust filter |
| Resolve subject/view | Authorized reader, exact scope set/frontiers, parser version, trust and admission policies | Attributed interpretation with underlying evidence references, exclusions and source coverage |
| Append annotation | Admitted author, encrypted signed annotation, occurrence/operation identity | Ordinary commit receipt; no synchronous analysis or workflow execution |
| Inspect ingest operation | Caller-authorized operation ID | Unknown, staged, committed with receipt, or explicit conflict; lost acknowledgment is not inferred failure |
| Inspect backup checkpoint | Authorized control reader, checkpoint ID | Object closure and verified frontier; distinguishes local durability from backup completion |
| Import snapshot | Import manifest/mapping, pinned source commitment and ordinary scoped batches | Job progress built from durable receipts and exact reconciliation; no source rewrite |

A batch is bounded; a multi-batch import is not one transaction. Its final completion manifest states the verified union of accepted batches and omissions. Retry keys bind destination scope, operation ID, and content commitment. Never use payload content alone to identify an occurrence or silently deduplicate separate inference attempts.

The envelope contract must specify version, signed origin and identity state, occurrence key, encrypted payload commitments, causal/predecessor references, coverage, and authenticated outer routing fields. The receipt contract must specify issuer, committed batch/event identifiers, service position/frontier, durable boundary, and signature domain. P2 must choose canonical bytes, hash/signature domains, supported version behavior, maximum frame lengths, and valid/invalid vectors. No public protocol is considered frozen by this field inventory alone.

Error families include invalid framing, invalid signature, unsupported version, denied capability, conflicting occurrence, missing staged object, quota exhausted, corrupt committed evidence, unavailable medium, and incomplete history. Admission failures are not retries; transient medium failures may be retried with the same operation ID. An unsupported envelope can be retained only through an explicit opaque-evidence path; retention does not mean semantic acceptance. Detailed internal diagnostics must not leak protected content through unauthorized responses.

### 5. Persistence ownership and recovery cuts

| Artifact family | Authority | Writer / validator | Recovery rule |
|---|---|---|---|
| Encrypted chunk | Immutable source bytes | Ingest staging writer / digest and framing validator | Referenced chunks survive; unreferenced staging objects are not committed evidence |
| Ledger frame and commit manifest | Authoritative event membership and ordering of arrival | Single commit owner / signature, capability and object-closure checks | Valid committed prefix is retained; torn tail is isolated; acknowledged entries cannot be discarded |
| Receipt | Service durability assertion | Commit owner / receipt signature verifier | Can be reissued from committed membership without executing provider traffic |
| Scope and grant control history | Authoritative policy evidence | Explicit administration boundary / RFC 1 capability rules | Restore original signed history and report unresolved/contested state |
| Offset and idempotency tables | Rebuildable projections | Indexer from manifests | Recover from checkpoint plus suffix; unavailable index never justifies accepting a conflicting occurrence |
| Semantic subject index | Derived, plaintext-capable reader state | Authorized reader / parser and membership frontier | Recompute from authorized evidence; incomplete rebuild cannot answer absence |
| Encrypted pending spool | Authoritative local pending evidence until receipt | Collector/gateway spool owner | Drain original occurrences; retain or disclose unacknowledged items; never replay inference |
| Import manifest and completion | Authoritative importer observations | Import principal / source commitments and receipt reconciliation | Resume and verify against pinned source; claims preserve original signatures |
| Backup checkpoint | Authoritative backup observation | Backup worker / independent object-closure verification | Restore only claims warranted by verified coverage; expose newer uncovered interval |
| Keys and credential references | Sensitive authoritative configuration | Separate credential/control boundary | Recover from independent package; never rebuild from a disposable index |

All paths into mutation—collector, gateway, annotation client, importer, future worker, restore, administration—must be enumerated. Event writers converge on the same commit boundary. Restored historical artifacts retain their source IDs and signatures and are imported through a verified restoration path; a second convenient writer is not allowed to skip occurrence/admission checks. New capabilities and catalog entries extend `src/persistence.rs` and the surface-conformance tests together.

P3's crash matrix names every cut: before chunk flush, after chunk install, during manifest write, after manifest durability but before index update, after index update but before receipt, and after receipt but before the client persists it. Faults in a cache must not alter the committed history. Verify these with real process termination and restart, not only return-value mocks. Test the persistent format against an independent decoder as required by the storage-conformance precedent.

### 6. Migration and capture contracts

P5 imports evidence, not a trust-filtered view. Its manifest inventories source medium, snapshot commitment, source lineage, record IDs/bytes, public verification history, selected destination mapping, and explicit omissions. Repositories with the same name or Git remote remain distinct until lineage is evidenced. Two local subjects named spine cannot collide across independent legacy stores. Invalid or unsupported records are retained as such; private keys and unrelated files are outside the upload allowlist.

P5 can ship local discovery/preview before the remote writer is complete, provided it advertises that only those operations exist. Resumable upload and verification depend on P4. Cutover depends on P7. Rollback restores client routing but does not magically copy v2-only writes into a legacy store; the report must disclose that remaining history and where to read it.

P6 begins with a deterministic fake provider covering stream chunks, disconnects, non-2xx responses, cancellation, slow reads, and ambiguous final outcomes. Local collector and remote gateway are separate observers. The gateway records its actual route; direct local fallback exists only when credentials and policy explicitly permit it. Captured prompt content cannot choose a new destination or turn an archive retry into a new provider request.

The supported harness/provider profile must enumerate configuration mechanism, hook/API coverage, source event IDs, attachment behavior, and limits. The generic fixture may establish correct transport behavior, but only the selected real profile can support a claim of end-to-end harness coverage. Provider implementation details will be researched against current primary documentation when that profile is selected.

### 7. Open decisions and their first dependent slice

| Decision | Current state | First dependency | Work that can proceed now |
|---|---|---|---|
| Archive key custody, wrapping, recovery and erasure unit | Parent Q4 remains open; separate keys, encryption-only gateway and independent recovery package are proposed | P2 must fix encryption-independent envelope boundaries; production crypto profile is required before P4 | Event/receipt semantics, opaque storage, synthetic crash/retry fixtures |
| First harness/provider and representative corpus | Parent Q5 remains open | Real integration in P6 | Fake provider, generic spool/stream state machine, coverage schema |
| Default trust for extracted decisions/status | Parent Q5 remains open | P8 | All storage, import, and capture work |
| Exact event/receipt wire encoding and URI extensions | Deliberate P2 design work, not yet frozen | P2 completion | Logical operation/state tables and independent-vector planning |
| Optional metadata obfuscation implementation | Non-default future profile | Only a release claiming that profile | Personal-instance MVP with explicit metadata inventory |

Do not expand these into a general platform rewrite before proving the first store. P2 is the next concrete engineering-design slice: choose exact formats and furnish independent vectors, including the trust/inventory negative fixture. It can be developed on a branch from P1 while these documentation PRs are reviewed, but is not evidence that production key handling or capture is already settled.

### 8. Review and completion discipline

Standing operator instruction (2026-10-16): every v2 implementation build point receives a fresh independent review through Claude Code using Opus 5.5, pinned as `claude-opus-5-5`. This includes the contract, storage, migration and subsequent service/capture/operations slices. The operator has authorized these reviews as the standard workflow; do not ask again at each slice. This instruction is scoped to the v2 build, not a global model preference.

Start a new reviewer session with no resumed/forked implementation conversation or author memory. Give it the relevant designs, recorded teloi with read limitations, repository rules and exact base/head commits. The reviewer inspects the implementation and runs its own checks, following the day adversarial-review protocol; it does not implement its findings. Record the actual model, commit range, commands/results, requirement coverage, findings and one hard verdict. Retain the raw report separately from the author's response. A failed or unavailable review, a different-model fallback, or an unverified model identity leaves this gate pending; never silently substitute another model or label an author's self-review independent.

Fixes after BLOCK or REDIRECT receive a new cold review of the corrected commits, with regression evidence and negative controls where applicable. A previous verdict does not cover later material code changes. Reviews gate milestone completion and merge recommendation; drafting a PR and independent work on other slices can continue. This is a development review convention, not a runtime enforcement hook or authorization to merge, deploy, change global Claude settings, or upload private source archives.

Give each worktree its own `CARGO_TARGET_DIR`, including for parallel reviews. Sharing a target directory across these same-name/version branches caused Cargo/Clippy to reuse another worktree's library metadata during the first review round; a passing or failing command under that setup can describe the wrong branch. Recheck affected evidence in isolation, retain the environment limitation in the report, and budget disk space before starting duplicate full builds. A report's verdict and the author's disposition of its findings are separate records; approval of a bounded slice does not mark its broader parent acceptance criteria complete.

The existing `.github/workflows/ci.yml` runs citation checks, Rust build/test/lint, an MSRV build, and other repository checks. For the documentation stack, run the design linter, whitespace checks, and existing citation checker, and report remote CI separately. Do not claim the local Rust suite was run for documentation-only edits.

For implementation slices, preserve and extend `tests/surface_conformance.rs`, the migration fixtures, and URI/identity fixtures. Bind the parent AC's named intent witnesses to actual test symbols when implemented. Include fault cases and independent oracles; a test that only round-trips through the same implementation cannot establish wire conformance. A defect fix includes a negative-control result demonstrating that its test detects the defect.

The current day record failure remains a documentation-tool limitation, not a reason to invent successful claim CIDs or modify the user's trust configuration. The tracked design, its commits, and linked PRs are the current continuation artifacts. Back-fill through day after its read context or inventory contract is corrected; do not assemble a substitute claim chain by hand. The v2 system must make raw inventory and interpretation separate so the same failure does not become a dependency of the new workflow engine.

The work targets the existing raw-data-and-projections, performance-at-scale, and identity/URI continuity goals. No new telos witnesses are declared by this document. The existing day graph nominates generative-build after design; this plan refines what the next build must establish without claiming that an unwitnessed maintenance telos is reached.

### 9. Implementation continuation status — 2026-10-16

This status supplements the original intent table; it does not retroactively mark the parent acceptance criteria complete. Draft stack remains #264 → #265 → #266 → #267 → #268, with permanent worktrees under `.worktrees/`.

| Area | Implemented and reviewed | Remaining delivery boundary |
|---|---|---|
| P2 evidence | Experimental strict codec and independent format vectors | Authenticated inventory/admission and service-visible completeness states |
| P3 storage | Opaque chunks, atomic manifest/receipt commits, retries, snapshot reads, backup, raw recovery/rebuild, explicit initialization resume, SQLite namespace protection and exact writable-schema admission | Bounded normal startup, measured capacity, broader authority and independent backup qualification |
| P4 service | Contracts/design only | Key custody/profile decision, authenticated service/API, wrapping, capabilities and clients |
| P5 migration | Local discovery/preview plus experimental maintenance CLI | Wider discovery and identity-history inventory, encrypted resumable import through P4; no cutover |
| P6 capture | Design/fake-provider contract only | Collector, gateway, encrypted spool and selected real harness/provider qualification |
| P7 operations | Local backups and synthetic recovery evidence | Independent backup destination, clean-host restore and final migration/cutover evidence |

The latest integrated runtime/test snapshot is `70a4348`: 70 targeted tests, Clippy, formatting, seven demonstrated lifecycle/schema negative controls, and fresh actual Opus 5.5 review per implementation/correction point. See `.design/reviews/kan-v2-lifecycle-2026-10-16.md` for exact ranges, verdicts and unresolved findings. A stopped review on an author test fixture error has no completion verdict and is not counted. Existing v1 sources and live routing remain unchanged.

Continue with normal-startup/capacity qualification and migration preflight completeness while settling P4's inherited owner-key profile decision. Do not treat local backup success or an approved storage slice as primary-archive readiness. The legacy migration-matrix seed fixture currently fails before the candidate reader executes; that CI failure remains visible and must be resolved before merge. CLI `verify` currently checks structural evidence, not writable-schema admission; the disclosure follow-up is tracked in the review disposition.

## Resolved Questions

- RQ-1: The user requested a draft architecture PR followed by a new permanent worktree/branch based on the design branch, with merges planned in sequence. P0 and P1 form that stack; neither is merged by this pass.
- RQ-2: Continue documentation toward implementation on the child branch while preserving the architecture proposal as its own reviewable parent. The local-repository migration tool remains part of MVP completion.
- RQ-3: The two claims underlying the current partial-trust refusal were identified by a read including their authors: both concern design/rfc-2 and neither is an existing v2-design record. This diagnosis does not change default trust settings or claim a repair to day.
- RQ-4: Fresh independent Claude Code reviews with Opus 5.5 are standard for v2 build points and subsequent blocking-fix rounds, under standing user authorization.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Inherited key and integration choices

Parent Q4 (key custody/recovery and exact crypto profile) and Q5 (first real harness/provider and later extractor default trust) remain unanswered. They are allocated to their first dependent slices above. Continue contract, synthetic fixture, and opaque storage work without guessing that the operator approved one concrete profile. No new user decision is required to review this delivery sequence.
<!-- /OPEN -->

## Out of Scope

- Implementing the service, importing live repositories, calling inference providers, or deploying infrastructure in this documentation pass.
- Merging PRs, enabling auto-merge, or deleting permanent worktrees as part of setting up the stack.
- Automatically creating GitHub issues or changing day/kan trust settings to unblock recording.
- A second database or local implementation with different evidence semantics.
- Production encryption or complete capture claims based only on synthetic fixtures.

## Continuation checkpoint — 2026-10-17

The permanent draft stack now extends through #269 (signed service) and #270 (recipient encryption). `feat/kan-v2-spool` is a dependent work-in-progress branch. Earlier status tables describe older snapshots; this checkpoint does not mark parent milestones complete.

- Migration discovery/preview now covers publication-only roots and explicitly selected public identity history. Migration harness distinguishes initialized-scope seed fixtures from legacy identity-file fixtures and honestly excludes unused keychain paths. Two actual Opus reviews are recorded in `.design/reviews/kan-v2-migration-completion-2026-10-17.md`.
- Signed append/inventory/read/page API and loopback HTTP/CLI are implemented. Requests retain original signed bytes; replies bind the request and pinned issuer. Timestamp and concurrent-scope defects found by review are corrected. Fresh runtime correction review is pending at this checkpoint; see `.design/reviews/kan-v2-service-2026-10-17.md`.
- Explicit recipient HPKE chunks have published vectors and independent bidirectional interoperability/backup recovery tests. Review found noncanonical recipient encodings could produce unrecoverable output; the parent encryption correction rejects them. Fresh correction review is pending. No production custody or key installation has been selected.
- Durable spool code preserves exact signed requests, serializes a bounded queue, and requires the destination's signed acknowledgment before releasing the head. Seven functional tests passed, including process exits before/after enqueue and acknowledgment publication. Its complete integrated check did not pass: the disk filled during linking/stripping, leaving an unusable test binary and eight downstream surface-test process-launch failures. A prior storage-feature surface suite passed. The final source compiles, but the spool remains unreviewed and is not merge-ready. Disposable spool build output was removed after preserving source; never treat that failed integrated run as green.

Remaining software: spool review and caller/CLI integration; resumable encrypted v1 import with provenance and complete/final-delta witnesses; collector, gateway and provider adapter with streaming/cancellation/visible-gap behavior; retained grant policy and hardened production key/configuration handling; bounded startup; owner erasure semantics; operational packaging and restore/cutover procedures. P8 extraction/day merger remains deferred beyond the raw storage MVP, not silently complete.

Remaining qualification: selected real harness/provider; larger-capacity measurements; independent backup destination and clean-host restore; owner-reviewed migration/cutover. No user data, existing source repository or live traffic has been moved. No PR has been merged to main. Current local disk capacity is a concrete blocker: a compiler reported ENOSPC, and only hundreds of MiB remain even after removing inactive generated build output. The operator has been asked for at least 20 GiB for builds or another permanent volume; 100-GiB storage qualification needs substantially more. Production owner recovery/custody and deployment choices also remain unanswered.

### Validation recovery after the capacity failure

Inactive generated package artifacts from the completed service/encryption review worktrees were removed, leaving source and review evidence intact. The same integrated spool source then passed all 98 targeted tests, including the formerly unlaunchable surface fixtures. Three executed spool mutation controls detect missing acknowledgment verification, removed capacity enforcement and broken frontier enforcement; restored seven-test spool suite passed. All-target Clippy and formatting are checked before the fresh spool review. The full-build capacity request remains necessary: available space is still far below operational/capacity qualification requirements.

Service runtime correction review now has **APPROVE WITH FOLLOW-UPS**, and encryption's fresh correction review has **APPROVE**; exact ranges and limitations are in their review records. These supersede only the earlier pending-review statements, not the remaining software or operational backlog. Spool independent review remains pending at this checkpoint.

### Reviewed spool correction and final checkpoint

The first spool review independently confirmed a reused-operation defect after acknowledgment. Profile 2 retains operation history and distinguishes queued, pending and acknowledged exact retries. The correction passed 102 targeted checks and four runtime negative controls, then received fresh actual Opus 5.5 **APPROVE WITH FOLLOW-UPS** with no medium/blocking finding. See `.design/reviews/kan-v2-spool-2026-10-17.md` for exact evidence and remaining owner-trust, diagnostic and resource limits. The spool build point is reviewed; capture/import integration is still not implemented.

A separate Rust 1.99 Clippy failure was fixed in the service's hex iterator and received its own fresh approval. It is propagated normally through the parent branches; remote CI on the final merged heads is a separate gate and must not be inferred from local checks. The three newest draft PRs are #269 (service), #270 (encryption), #271 (spool). No main merge, live deployment or user-data migration occurred.

Next work remains: bounded startup/service writer coordination and reviewed service follow-ups; usable CLI/caller integration; resumable encrypted migration; collector/gateway/provider forwarding with visible recording-gap behavior; key/grant/configuration operations, erasure, independent backups, clean-host restore and final cutover qualification. Additional disk space/permanent volume and the previously requested operating-profile details remain outstanding. The original checkout's user edits and all v1 sources are preserved.

### Delivery continuation — 2026-10-17

Final parent spool head `de6f9a04bb9e8a39dd65c5561b2d39a39ac4d874` has green GitHub CI, migration matrix and performance jobs (CI runs 39011221517/39011224471, matrix 39011224467, perf 39011224485). Removing three unused elan toolchain versions restored roughly 8 GiB; about 11 GiB was available before this build point. This removes the immediate compiler capacity blocker, not the 100-GiB qualification requirement.

The next permanent branch is `feat/kan-v2-delivery`, in `.worktrees/kan-v2-delivery`, based on that exact spool head. It composes encryption, durable queue admission, bounded exact-byte draining, operation lookup and authenticated offline recovery. Design: `.design/kan-v2-delivery.md`; manual workflow: `docs/V2-DELIVERY.md`. This does not complete source migration, automatic capture or production operations. Fresh review and final validation are recorded separately before this slice is recommended for merge.

Delivery received fresh actual Opus 5.5 **APPROVE WITH FOLLOW-UPS** at `37ea1af1773e52741fd2031c160a890910e86a87`; see `.design/reviews/kan-v2-delivery-2026-10-17.md`. No blocking/medium finding was reported. Documentation now distinguishes outer signer provenance, separately observed operation/status metadata and closed-stdout uncertainty. Low diagnostic/status follow-ups remain explicit. Draft #272 contains the commands; a dependent import build point is being reviewed separately in #273. No live source data or traffic was moved.

### Resumable import continuation — 2026-10-17

`feat/kan-v2-import`, in the permanent `.worktrees/kan-v2-import`, adds a pinned raw-snapshot driver above the delivery branch. `.design/kan-v2-import-driver.md` fixes the source/route commitment, chunk format, deterministic local resume hints and limits. `docs/V2-IMPORT.md` documents explicit planning, bounded queue admission and separate delivery. The importer preserves malformed evidence as encrypted raw bytes with notices; it does not complete trust reconstruction or operational cutover. Independent recovery, production restore, final live-source delta and backups remain required.

### Reviewed import correction and continuation boundary

The initial importer review found two medium defects in the independent Python recovery checker: optimization disabled assertions, and a self-consistent replacement stream could pass without an external expected plan. Both are corrected, demonstrated by full-fix reversion, and freshly reviewed by actual Opus 5.5 with **APPROVE WITH FOLLOW-UPS**, no critical/high/medium finding. The correction head is `29b800e100dd61566993237c93d29d12c45622a7`; exact evidence and remaining low findings are in `.design/reviews/kan-v2-import-2026-10-17.md`. The real importer now has eight tests, including >10-MiB source recovery via service readback and an independent expected-plan decoder. This completes the experimental resumable raw-admission build point, not P5/P7 operational migration.

Remaining software still includes production restore and reconciled completion evidence; final delta/cutover; collector/gateway/provider streaming and visible recording-gap behavior; production key/grant/configuration operations and owner erasure; service writer coordination, indexed scope guards and bounded startup; backup/clean-host restore and scale qualification. Semantic extraction/day merger remains P8 beyond the raw-storage MVP. All work is in permanent worktrees and stacked draft PRs, with no main merge or live-data cutover.

Final integrated source at `f32011b9198509d539f3afa099a7c693b0e73d6c` passed all 114 v2 integration checks across twelve suites, plus all-target Clippy, formatting and diff checks. Its source/scripts/tests/workflow bytes are identical to the freshly reviewed correction head `29b800e100dd61566993237c93d29d12c45622a7`; the normal parent merge brought only review records and documentation. GitHub CI on the final published documentation head remains a separate gate. The newest draft PRs are #272 (delivery) and #273 (resumable raw import). Permanent worktrees and original source evidence are retained.


### Service admission hardening — 2026-10-17

Both delivery #272 (`ac7848e`) and import #273 (`da36f203`) have green tests,
MSRV, migration matrix and performance CI. The permanent child worktree
`.worktrees/kan-v2-service-hardening`, branch `feat/kan-v2-service-hardening`,
starts from import `da36f203ea9e2e5fe7c37d359192db624b188727`.
Its design `.design/kan-v2-service-hardening.md` addresses the service review's
indexed scope guard, hidden malformed suffix and missing-object witness
follow-ups without changing the ledger schema. The remaining production
restore, capture/gateway, custody/erasure and operational qualification gates
above are unchanged. Fresh review and evidence are recorded before recommending
this slice for merge. No main merge or live-data cutover is part of this step.


Service hardening is now in draft #274. Initial head `0ab98e3` and correction
`61ca52065d2b276a3c113c3debedbbe8195047a2` each received fresh actual Opus 5.5
**APPROVE WITH FOLLOW-UPS**. The correction independently closes the initial
review's repeated audit cost, missing read-boundary witnesses and Snapshot tip
regression; 125 targeted checks and Clippy/formatting pass. Review provenance and
remaining nonblocking tooling/error-vocabulary limitations are in
`.design/reviews/kan-v2-service-hardening-2026-10-17.md`. Final documentation-only
commits retain the reviewed source/tests/scripts/workflow exactly.

The indexed scope guard, append coordination and missing-object witness follow-ups
are closed for this experimental profile. Next software work remains verified
import restore/receipt reconciliation and collector/gateway capture with visible
gaps, followed by production key/grant operations, owner erasure, backup/clean-host
restore, final delta/cutover and capacity qualification. Full-history startup is
still unqualified at operational scale. No live sources were migrated, and the
original checkout's uncommitted work remains separate. Two old completed-review
build targets (about 1.5 GiB of generated artifacts) were removed; each new
reviewer also cleaned its own generated target. Reports and ground-truth fixtures
were retained, with about 18 GiB free at the final local check.

## Offline import restore build point — 2026-10-17

The permanent `.worktrees/kan-v2-restore`, branch `feat/kan-v2-restore`, starts
from reviewed service-hardening head `9ae0622fd8791007981e1958abe564a43f12aadf`.
Its `.design/kan-v2-import-restore.md` and `docs/V2-RESTORE.md` define offline
selected-byte recovery into a new private directory. It reconciles the original
externally pinned import plan with authenticated retained requests and raw
manifest/structural receipt bindings; damaged derived lookup fields are ignored.
Unsigned receipts are not presented as service attestation. The selected-byte
report preserves omissions and does not certify all archive history, independent
backup, legacy semantic trust or cutover. Fresh review is required for this slice.

Next software remains collector/gateway/provider streaming with visible recording
gaps, production key/grant/configuration and erasure operations, and final delta
reconciliation. P7 still requires independent-host backup/restore drills and
capacity qualification. The offline tool is a recovery witness, not completion
of those operational gates. No live user-data migration or main merge occurred.


The restore implementation `c07cacc8abea3621119100f9bdc382ddcfc9ee6b` passed all
GitHub CI workflows, including performance. It received fresh Opus 5.5 APPROVE
WITH FOLLOW-UPS. Test-only follow-up `602148285114c26f9ad643511ceee6cd74aa9dca`
retains eleven independent adversarial/oracle probes and adds three regression
mutation controls; a second fresh Opus 5.5 review also approved with nonblocking
follow-ups. The covered suite now totals 140 targeted integration tests plus five
focused units. Source, tests and evidence are in draft PR #275, stacked on #274.
The remaining coordinate-call-site/error-specificity coverage limits and tooling
limits are explicit in `.design/reviews/kan-v2-import-restore-2026-10-17.md`.
No production source changed after the first review. This completes the offline
selected-byte recovery build point, not P7 operational qualification.
