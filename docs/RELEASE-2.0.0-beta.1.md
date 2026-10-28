# Kan 2.0.0-beta.1 release candidate

Updated 2026-10-28. **Qualified candidate; unpublished.** The owner authorized
executing this plan, including the sequenced stack merges and final-main
qualification, on 2026-10-28. Tag push, registry publication, deployment and live
migration remain separately gated. This checklist records release execution
under the existing AGENTS.md SOP; qualification does not publish a release.

## User-facing contract

The crate remains `kan`. Default `kan` is the v2 service/capture/Library CLI;
`kan-v1` is the optional legacy repository CLI. No `kan-v2` alias is installed.
After publication, these are the three supported registry install choices:

```sh
cargo install kan --version 2.0.0-beta.1 --locked
cargo install kan --version 2.0.0-beta.1 --locked --features kan-v1
cargo install kan --version 2.0.0-beta.1 --locked --no-default-features --features kan-v1 --bin kan-v1
```

These are future user instructions, not commands executed during preparation.
Existing v1 scripts, MCP registrations and external day integrations must be
updated to the explicit `kan-v1` path before replacing their old `kan` binary.
That external integration work is not claimed complete here. Existing services
must be deliberately reconfigured; installing the crate does not migrate data,
start a server, deploy a frontend or grant extractor trust.

In a legacy-marked workspace, the v2 command emits tagged, escaped stderr guidance
for humans and agents. Start with read-only `kan preview .`, then follow
[V2-IMPORT](V2-IMPORT.md) and [V2-DEPLOYMENT](V2-DEPLOYMENT.md). Retained originals
and writer fences do not establish cutover status. Machine stderr consumers use
`--no-migration-notice`; JSON/MCP stdout remains the protocol channel. Suppression
records no authorization or migration acknowledgement.

## Evidence and candidate gates

The qualified implementation is `de34a674af08718dea34ba82dd4cec17c682a2bc`.
Collect-all 40621934587, PR CI 40621891588, push CI 40621884275, migration
40621891593, perf 40621891804 and RFC 40621891496 all succeeded. Independent
inspection confirmed 56 checks, 19 browser groups with zero errors/external loads,
four diagnostic jobs and the PR macOS canary, two packaged-source builds, three
installation modes at version 2.0.0-beta.1, eight helper tests and actual-manifest
`kan-v1` selection. All 24 representative migration cells matched their committed
outcomes with cache misses; capability exclusions are not successful keychain
migrations. This is not the full all-writer matrix.

The candidate changes the root version, historical-writer qualification tooling,
and workspace maintenance coordination. The final owned maintenance guard now
explicitly unlocks after SQLite closes and recovery cleanup finishes. All three
new maintenance regressions, the original erasure/reopen regression and persistence
conformance checks passed. Archive admission and storage formats are unchanged.
Earlier failures at `32ebf71` and `20bbf0e` remain retained; the migration bot's
`ea0dac3` measured v1 keychain capability exclusions remain in the ancestry.

The actual Claude Code Opus 5.5 narrow review of `e561330..de34a67` returned
**APPROVE WITH FOLLOW-UPS** (session `6537f35b-1e43-4ae9-a9c3-fc75277cd575`).
R1–R3 and the maintenance repair were accepted with no blockers. This documentation
update closes F1's stale status and freeze-policy wording. F2's broad historical
build-failure classification, F3's exact-error assertions and F4's post-SQLite
error-path test remain nonblocking follow-ups. A pre-existing SQLite descriptor
locking concern was explicitly unverified and remains a triage item, not a
confirmed defect or a claim of repair.

- [x] Record the frozen candidate SHA and inspect all current required runs and
  per-check/browser artifacts, including applicable macOS/keychain coverage.
- [x] Inspect both packaged builds, all three installed executable sets/version
  strings, eight helper tests and real-manifest writer selection.
- [x] Inspect the representative migration cells and distinguish exclusions from
  actual migration outcomes. Helper failures remain hard failures.
- [x] Retain the narrow independent review; do not repeat completed whole-product
  reviews or heavy capacity fixtures.
- [ ] Qualify this documentation-only update with push CI and retain the exact
  diff showing no executable inputs or migration cache inputs changed.
- [ ] Merge the authorized stack in order and verify final-main tree identity.
- [ ] Run and inspect full all-writer migration coverage on final main before
  publication approval, retaining outcomes, exclusions and cached/fresh distinctions.
- [x] Finalize the changelog version heading while retaining explicit unpublished
  status; the publication date remains unset until known. Further documentation
  updates follow the policy below.

### Qualification after documentation-only changes

A delta confined to release notes, checklists and status prose may reuse the
qualified implementation evidence after inspecting the exact path/content diff.
It still requires successful push CI. Source, tests, scripts, manifests, lockfiles,
workflows, migration expectations and all migration cache inputs must be identical;
a change to any of those requires relevant qualification. Record both the qualified
implementation SHA and the documentation SHA. Merge commits alone may reuse that
evidence only after verifying tree identity. Final-main CI and the full all-writer
matrix remain mandatory before publication, even for an identical tree.

The new v2 expectation rows are explicitly PREDICTED. They describe the optional
legacy writer, not the default v2 command, and are not a measurement of a released
v2 tag. An automatic matrix commit converting older predictions to measurements
must be inspected and retained; do not overwrite it. Reconcile its parent/tree
and any changed code before freezing the release commit.

Local evidence: `.local-state/qualification-de34a67/` contains the full logs,
per-check/browser artifacts and `ci-evidence.json`; the independent review is
`.local-state/reviews/release-candidate-de34a67/report.md` with its full result
and execution diagnostics. Prior qualifications and reviews remain retained.
No local Rust builds, tests or installs were used on the shared laptop.

## Merge sequence — authorized 2026-10-28

The 50 draft PRs #264–#313 were verified open, unmerged and chained on 2026-10-27.
The branch was 506 commits ahead of main before this preparation. Recheck current
heads and bases before acting; the table below is a snapshot, not permission.

1. Freeze the qualified top-branch SHA and record each PR's head/base SHA. Check
   for unrelated main changes, required reviews, conflicts and branch protection.
2. After explicit stack-merge approval, mark the first PR ready and merge #264
   into main with a **merge commit**. Do not squash or rebase the history.
3. For each next PR in ascending order, verify its predecessor is an ancestor of
   main, retarget that PR to main, inspect the remaining diff and required checks,
   then merge with a merge commit. Keep predecessor branches until dependents
   have been retargeted. Stop on an unexpected diff, conflict or failed gate.
4. After #313, verify the resulting main tree matches the accepted candidate
   tree except for explicitly reviewed changes. Retain final main CI/matrix
   evidence and package version checks. Any code difference needs qualification.
   Do not infer main success solely from the feature-branch runs.

## Publication sequence — separate approval

1. Present the exact final main commit, `v2.0.0-beta.1` tag, crate version, release
   notes, qualification/review evidence and known limitations to the owner.
   Confirm tag and crate version are unused immediately before publication.
2. Obtain explicit approval to push that exact tag and publish the crate. A tag
   matching `v*.*.*` triggers `.github/workflows/release.yml` and **cargo publish**.
   Do not create/push a tag merely to test release readiness. The workflow's
   crates-io environment is not assumed to provide a human approval pause.
3. Push the approved tag once. Observe release verification and publication;
   confirm registry version and artifact identity. If failure is ambiguous,
   inspect registry/workflow state before any retry; never move a published tag.
4. Publish the approved GitHub prerelease notes with install/upgrade guidance.
   This is a source crate release; no prebuilt binaries are promised.
5. Verify installed versions/entry points in an isolated remote job after release.
   Schedule an explicitly approved pilot migration separately, with independent
   backup verification, writer fencing, reconciliation and rollback plan.

## Disclosed limitations and retained data

- Published 100 GiB evidence covers single-worker indexed opaque storage: 128
  samples, peak 38,992 KiB RSS, 102,432 committed/referenced objects and
  214,874,875,489 committed encoded bytes. Two staged objects were separately
  pinned and verified; remount quick_check and 516 full-file hashes passed.
- The original first-append admission took **79.770901 seconds**. A separate
  10 GiB probe observed asymmetry but did not reproduce or explain that outlier.
  These are not local-SSD comparisons, cache-eviction measurements or a 100 GiB
  encrypted HTTP workload. See the published measurement JSON and deployment doc.
- Staged-object lifecycle (C1), a read-only Library HTTP credential (C3), legacy
  trust presentation and scope-review N1–N4 remain disclosed follow-ups. N1 can
  reject an entire imported CAR view for a malformed sibling inception; imported
  legacy URI authorization is intentionally stricter than native (N2); alias
  semantics for other resource types (N3) and additional negative tests (N4)
  remain recorded in the retained scope review. They are not claimed fixed here.
- The original 100 GiB fixture was deleted only after authorized verification.
  The 10 GiB probe fixture remains retained. Do not reseed or delete volumes as
  part of release preparation; `kan-v2-capacity-results` must remain intact.

## PR stack snapshot

| Order | PR | Head branch | Original base |
|---|---|---|---|
| 1 | [#264](https://github.com/kan-tools/kan/pull/264) | `design/kan-v2-server-first` | `main` |
| 2 | [#265](https://github.com/kan-tools/kan/pull/265) | `design/kan-v2-buildout` | `design/kan-v2-server-first` |
| 3 | [#266](https://github.com/kan-tools/kan/pull/266) | `feat/kan-v2-evidence-contract` | `design/kan-v2-buildout` |
| 4 | [#267](https://github.com/kan-tools/kan/pull/267) | `feat/kan-v2-storage` | `feat/kan-v2-evidence-contract` |
| 5 | [#268](https://github.com/kan-tools/kan/pull/268) | `feat/kan-v2-migration` | `feat/kan-v2-storage` |
| 6 | [#269](https://github.com/kan-tools/kan/pull/269) | `feat/kan-v2-service` | `feat/kan-v2-migration` |
| 7 | [#270](https://github.com/kan-tools/kan/pull/270) | `feat/kan-v2-encryption` | `feat/kan-v2-service` |
| 8 | [#271](https://github.com/kan-tools/kan/pull/271) | `feat/kan-v2-spool` | `feat/kan-v2-encryption` |
| 9 | [#272](https://github.com/kan-tools/kan/pull/272) | `feat/kan-v2-delivery` | `feat/kan-v2-spool` |
| 10 | [#273](https://github.com/kan-tools/kan/pull/273) | `feat/kan-v2-import` | `feat/kan-v2-delivery` |
| 11 | [#274](https://github.com/kan-tools/kan/pull/274) | `feat/kan-v2-service-hardening` | `feat/kan-v2-import` |
| 12 | [#275](https://github.com/kan-tools/kan/pull/275) | `feat/kan-v2-restore` | `feat/kan-v2-service-hardening` |
| 13 | [#276](https://github.com/kan-tools/kan/pull/276) | `feat/kan-v2-capture` | `feat/kan-v2-restore` |
| 14 | [#277](https://github.com/kan-tools/kan/pull/277) | `feat/kan-v2-capture-latency` | `feat/kan-v2-capture` |
| 15 | [#278](https://github.com/kan-tools/kan/pull/278) | `feat/kan-v2-gateway` | `feat/kan-v2-capture-latency` |
| 16 | [#279](https://github.com/kan-tools/kan/pull/279) | `feat/kan-v2-operations` | `feat/kan-v2-gateway` |
| 17 | [#280](https://github.com/kan-tools/kan/pull/280) | `design/kan-v2-operations-polish` | `feat/kan-v2-operations` |
| 18 | [#281](https://github.com/kan-tools/kan/pull/281) | `feat/kan-v2-studio-build` | `design/kan-v2-operations-polish` |
| 19 | [#282](https://github.com/kan-tools/kan/pull/282) | `feat/kan-v2-health-coalescing` | `feat/kan-v2-studio-build` |
| 20 | [#283](https://github.com/kan-tools/kan/pull/283) | `feat/kan-v2-health-reliability` | `feat/kan-v2-health-coalescing` |
| 21 | [#284](https://github.com/kan-tools/kan/pull/284) | `feat/kan-v2-journal-capacity` | `feat/kan-v2-health-reliability` |
| 22 | [#285](https://github.com/kan-tools/kan/pull/285) | `feat/kan-v2-admission-audit` | `feat/kan-v2-journal-capacity` |
| 23 | [#286](https://github.com/kan-tools/kan/pull/286) | `feat/kan-v2-reader-library` | `feat/kan-v2-admission-audit` |
| 24 | [#287](https://github.com/kan-tools/kan/pull/287) | `design/kan-v2-collection-overview` | `feat/kan-v2-reader-library` |
| 25 | [#288](https://github.com/kan-tools/kan/pull/288) | `feat/kan-v2-library-resilience` | `design/kan-v2-collection-overview` |
| 26 | [#289](https://github.com/kan-tools/kan/pull/289) | `design/kan-v2-evidence-availability` | `feat/kan-v2-library-resilience` |
| 27 | [#290](https://github.com/kan-tools/kan/pull/290) | `feat/kan-v2-build-next` | `design/kan-v2-evidence-availability` |
| 28 | [#291](https://github.com/kan-tools/kan/pull/291) | `feat/kan-v2-proof-storage` | `feat/kan-v2-build-next` |
| 29 | [#292](https://github.com/kan-tools/kan/pull/292) | `feat/kan-v2-collection-build` | `feat/kan-v2-proof-storage` |
| 30 | [#293](https://github.com/kan-tools/kan/pull/293) | `feat/kan-v2-proof-lifecycle` | `feat/kan-v2-collection-build` |
| 31 | [#294](https://github.com/kan-tools/kan/pull/294) | `feat/kan-v2-copy-upgrade` | `feat/kan-v2-proof-lifecycle` |
| 32 | [#295](https://github.com/kan-tools/kan/pull/295) | `feat/kan-v2-copy-destination` | `feat/kan-v2-copy-upgrade` |
| 33 | [#296](https://github.com/kan-tools/kan/pull/296) | `feat/kan-v2-degraded-inventory` | `feat/kan-v2-copy-destination` |
| 34 | [#297](https://github.com/kan-tools/kan/pull/297) | `feat/kan-v2-reconstruction` | `feat/kan-v2-degraded-inventory` |
| 35 | [#298](https://github.com/kan-tools/kan/pull/298) | `feat/kan-v2-recovery-bundle-codec` | `feat/kan-v2-reconstruction` |
| 36 | [#299](https://github.com/kan-tools/kan/pull/299) | `feat/kan-v2-recovery-state` | `feat/kan-v2-recovery-bundle-codec` |
| 37 | [#300](https://github.com/kan-tools/kan/pull/300) | `feat/kan-v2-recovery-member` | `feat/kan-v2-recovery-state` |
| 38 | [#301](https://github.com/kan-tools/kan/pull/301) | `feat/kan-v2-recovery-replay` | `feat/kan-v2-recovery-member` |
| 39 | [#302](https://github.com/kan-tools/kan/pull/302) | `feat/kan-v2-recovery-opening` | `feat/kan-v2-recovery-replay` |
| 40 | [#303](https://github.com/kan-tools/kan/pull/303) | `feat/kan-v2-session-assembly` | `feat/kan-v2-recovery-opening` |
| 41 | [#304](https://github.com/kan-tools/kan/pull/304) | `feat/kan-v2-conversation-adapter` | `feat/kan-v2-session-assembly` |
| 42 | [#305](https://github.com/kan-tools/kan/pull/305) | `feat/kan-v2-content-inspection` | `feat/kan-v2-conversation-adapter` |
| 43 | [#306](https://github.com/kan-tools/kan/pull/306) | `feat/kan-v2-recovery-mutations` | `feat/kan-v2-content-inspection` |
| 44 | [#307](https://github.com/kan-tools/kan/pull/307) | `feat/kan-v2-codec-boundary` | `feat/kan-v2-recovery-mutations` |
| 45 | [#308](https://github.com/kan-tools/kan/pull/308) | `feat/kan-v2-recovery-restoration` | `feat/kan-v2-codec-boundary` |
| 46 | [#309](https://github.com/kan-tools/kan/pull/309) | `feat/kan-v2-recovery-publication` | `feat/kan-v2-recovery-restoration` |
| 47 | [#310](https://github.com/kan-tools/kan/pull/310) | `feat/kan-v2-recovery-bundle-copy` | `feat/kan-v2-recovery-publication` |
| 48 | [#311](https://github.com/kan-tools/kan/pull/311) | `feat/kan-v2-proof-reader` | `feat/kan-v2-recovery-bundle-copy` |
| 49 | [#312](https://github.com/kan-tools/kan/pull/312) | `feat/kan-v2-proof-service` | `feat/kan-v2-proof-reader` |
| 50 | [#313](https://github.com/kan-tools/kan/pull/313) | `feat/kan-v2-proof-library` | `feat/kan-v2-proof-service` |
