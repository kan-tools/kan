# Adversarial review — Library resilience checkpoint

**Reviewer:** fresh, independent Claude Code Opus 5.5 (`claude-opus-5-5`), not delegated. I did not write this implementation.
**Target:** frozen export `.local-state/reviews/opus-resilience`. HEAD `e71cdf842a19b4a3f0fee810ea11c16b5310d7fa` ("feat(v2): keep verified Library scopes usable during source failures") against HEAD^ `60f3d36ad6da0c3d49808721f88f299a988e1423`. The range is HEAD^..HEAD, not `main...HEAD`: the brief says to review the actual commits, and this export is a detached snapshot.
**Designs:** `.design/kan-v2-library-resilience.md` (primary), plus the parents `.design/kan-v2-reader-library.md` and `.design/kan-v2-human-frontend.md`. The skill's old one-UI rule is superseded by the owner's explicit full-v2-frontend authorisation (CLAUDE.md, "One surface" bullet).
**Constraints I kept to:**
- No kan/day writes, so Step 7 (record the verdict) was intentionally skipped.
- No production keys or archive, no installation, no main merge, no external network.
- One heavy job at a time, `-j4`, `CARGO_TARGET_DIR` set to this export's `target/` only, no Mathlib/.lake.

## Step 1 — North star (from the supplied `north-star.json`, a read of the main checkout)
`telos/raw-data-and-projections` (live Decision `bafyreied3rkl…`):
> "Raw attested data is retained in full and never collapsed in the store. Every simplification … is a determined projection computed on demand … A field holding a computed value is the failure mode."

- The telos **deliberately declares no witnesses** (Observation `bafyreicakl3r…`). None were invented here.
- `excluded_by_trust: 2`: two claims are withheld from this read. I did not try to resolve them.
- This work serves the telos as the design summary states: "an incomplete check must remain visible and must not erase accessible neighbours or promote unverified metadata to authority."
- The relevant check is that `coverage` is a projection computed per request at `src/evidence_library.rs:78`. It is never stored, and no store or service surface changed (`review-evidence/50-storage-surface-unchanged.txt`, empty diff for `evidence_store.rs`, `evidence_service.rs`, `evidence_http.rs`, `read-write-surface.tsv`, `src/bin/`).
- **Tension:** availability (show healthy neighbours) versus privacy (never identify or count failed scopes). The implementation resolves this toward privacy at the serialized layer. Timing still leaks a coarse lower bound (finding F1).

## Step 3 — Independent verification (raw logs in `review-evidence/`)
| Check | Result | Evidence |
|---|---|---|
| Budget unit tests (`--lib budget_tests`) | 2/2 pass | 10-, 91- |
| `evidence_reader` | 17 pass, 1 ignored (manual browser fixture) | 11-, 91- |
| Real CLI `evidence_library_cli` | 1/1 pass | 11-, 91- |
| `surface_conformance` | 19/19 pass | 11-, 91- |
| Node library/ops/theme | 41/41 pass | 12-, 92- |
| Python adapter (`test_revert_v2.py`, `-I`) | 7/7 OK | 13-, 92- |
| Strict v2 all-target Clippy `-D warnings` | exit 0 | 14-, 92- |
| `cargo fmt --check` | exit 0 | 15-, 92- |
| Trailer replay: `scripts/revert_v2.py --verify HEAD --helper …/day/0.12.0-beta.3/scripts/revert-demo.py` | `DEMONSTRATED; all trailer tests reproduced=True`. Baseline pass, then compiled failures under revert: `catalog_keeps…` panicked at `tests/evidence_reader.rs:952` (`expect` "stalled source must not hold whole catalog past its budget", in-test reqwest TimedOut); `library_body_read_deadline…` panicked at `:1022` (`Elapsed`); `node::library_partial_catalog` failed an AssertionError. All three pass after restore. No compile error, no runner timeout. | 20-, 20-reversion-logs/ |

Note on the replay: under whole-production revert, the catalog test fails at the **budget** `expect` before it ever reaches the coverage assertion. The replay therefore proves the deadline, not partial-flag handling. I demonstrated partial-flag handling separately (R01/R02/R06 below).

## Step 2 — Requirement / acceptance table
| Item | Verdict | Evidence |
|---|---|---|
| REQ-1 healthy scopes kept, explicit coverage, denial omitted, no failed IDs/endpoints/counts | **met** (code); test gaps F2 | `src/evidence_library.rs:59-78`: waves of `chunks(4)`, `Err(Failure::AccessLimited) => {}`, `Err(_) => partial = true`, `"coverage":if partial…`. Probe P1: denial-only gives `coverage:"complete"` and the exact key set `{capabilities,coverage,scopes,unavailable,version}`. Committed test asserts the absence of failed scope hex/endpoints. R01/R02/R06 killed. R03, R08 and R12 **survive the committed suite** and are killed only by my probes (K03/K08/K12). |
| REQ-2 5 s upstream, 4-way catalog within 16, 3 s body, 4/12, 6 s queue, 35 s whole, cancellation drops reads | **met** (code); bound-tightness gaps F3 | `src/evidence_reader.rs:152-157` (5 s → `Unavailable`); `evidence_library.rs:156-163` (3 s → 408); `:248-268` (12/4/6 s/35 s, with the queue inside the 35 s timer); `:193-203` (serve uses `ConnectionBudget::new/admit/run`). Probe P2: 16 stalled scopes return 200 partial in **20.06 s** (< 35 s). Probe P4: after 4 in-flight catalogs are client-dropped, the next GET is served in **1.1 ms**, so disconnect releases the permits. K24 confirms the 35 s deadline includes queue time. R10/R14/R20-23/R25/R30/R32 killed. R11 (6 s), R13 (4 s), R24 and R31 survive the committed suite. |
| REQ-3 persistent partial notice, Retry sources clears pins/rows/plaintext, lock invalidates late replies and clears coverage/capabilities | **met** | `web/library/app.js:106-133`, `:18`, `:21-35`. U06-U10, U12-U14, U23-U27 killed. U03/U04/U05 survive because three epoch guards are redundant; removing all three (U28) is killed (`33-…txt`). |
| REQ-4 API capability arrays pinned; 401/403, Previous, malformed/duplicate capabilities, all directional families; byte-exact UTF-8 | **met** | `tests/evidence_reader.rs:676-690` asserts the exact arrays (R07 killed). U01/U02 (401, 403), U15, U16/U17/U11, U18 and U19-U22b (ALM, LRM/RLM, isolates, embeddings, single RLO) all killed by compiled assertions. |
| REQ-5 real-browser range export, byte compare or retained limitation; reauth; bounded memory | **partial**: limitation branch only | The export path still re-RPCs (`app.js:139-149`). `.design/reviews/resilience-browser/README.md`: "Browser download event again timed out … File delivery is still unverified." **Actual file delivery is NOT verified** and I do not count it. |
| REQ-6 raw storage/admission preserved; fresh Opus review; reversion; follow-ups visible | **met** (this report supplies the review) | 50-storage-surface-unchanged (empty). `.design/kan-v2-followup-status.md` keeps steps 2-5 open, says "Actual download delivery is still unverified in IAB", and says the frontend is not complete. |
| AC-1 synthetic forged/refused/stalled/denied, partial, recovery, indistinguishable denial, no failed IDs, named reversion | **partial** | Behaviour verified: `catalog_keeps_healthy_scopes…` (`tests/evidence_reader.rs:894-990`) plus probes P1/P2. The committed suite does **not** pin "denial alone leaves coverage complete" (R03 survives; `tests/evidence_reader.rs:704-711` checks only `scopes.len()==0`). It also does not pin "no extra count field" (R08) or "timeout is never a denial" (R12). |
| AC-2 4 executing/12 admitted, exact queue/whole deadlines, cancellation release, excess refusal, real fifth socket with latency, later healthy scopes reached | **partial** | Helper tests (paused time) kill the count and deadline mutants R20-R23/R25. Fifth socket ≥ 4 s (R30/R32 killed). Later healthy scope 0x45… reached past the stalled wave 0x25-0x28…. Gaps: the whole deadline is not proven queue-inclusive (R24), and live `serve()` refusal of a 13th socket is unbound (R31: a 4096-socket budget in serve passes everything). |
| AC-3 Node persistent partial, retry recovery, all-failed ≠ complete-empty, no late repaint, API capability arrays | **met** | Node tests 34-41 plus the U-mutants above; R07. |
| AC-4 negative tests; mutants fail assertions, not compilation | **met** | All U kills are TAP `not ok` AssertionErrors; no `could not compile` in any mutant log. |
| AC-5 real-browser desktop/mobile partial plus retry; exact bytes **or** retained limitation; inert markup; lock clears | **met via the explicitly accepted limitation branch** (author evidence; I could not re-execute it) | The screenshots (`desktop-partial.jpg`, `phone-partial-dark.jpg`) show the partial banner, the Retry button, and captured `<script>`/`<img>` rendered as text. Retry and lock are recorded in the README text only, with no screenshot. This fallback is distinct from **parent** reader-library AC-3/AC-6 export **delivery**, which remains **unfulfilled**. |
| AC-6 surfaces unchanged; review/correction evidence; ledger separates checkpoint vs roadmap | **met** | As REQ-6. |

## Targeted mutation results (`review-evidence/mutants/`, every one restored byte-for-byte)
- **Killed by compiled assertion:** R01, R02, R04, R05, R06, R07, R10, R14, R20, R21, R22, R23, R25, R30, R32; U01, U02, U06-U18, U23-U27, U19-U22b, U28; probe-backed K03, K08, K12, K24.
- **Surviving the committed suite:**
  - R03 (signed denial marks partial)
  - R08 (adds `"failed": N`)
  - R11 (upstream 6 s)
  - R12 (timeout treated as denial)
  - R13 (body 4 s)
  - R24 (whole deadline excludes queue)
  - R31 (live serve with 4096 sockets)
  - U03/U04/U05 (individual redundant epoch guards; equivalent while any one guard remains)
- **Invalid runs, preserved with labels:**
  - My first U19-U22 attempt matched 0 occurrences (BAD-MUTANT, editor turned the escapes into literal characters). It was re-run correctly.
  - My first probe run failed at a 31-char token (my harness bug, `40a-`/`41a-`). It is marked INVALID and was re-run with valid tokens.

## Probes (`review-evidence/probes/`, `40-probes.txt`; appended temporarily, then byte-restored)
- **P1** (denial-only catalog): `coverage:"complete"` with the exact key set.
- **P2** (16-scope budget and ordering):
  - All 16 stalled: 200, `partial`, `[]`, 20.06 s.
  - One stall per wave: sorted order preserved, 12 scopes, 20.04 s.
- **P3** (timing): latency per wave containing a stall.
  - No stalls: 0.12 s, complete.
  - Stall `[0]`: 5.10 s.
  - Stall `[0,1]`: 5.10 s.
  - Stall `[0,4]`: 10.02 s.
- **P4** (cancellation): client disconnect frees execution permits; the next GET took 1.1 ms.
- **Budget probe:** the 35 s timer includes a 3 s queue wait.

## Findings
- **F1 (privacy, low): timing reveals a coarse count.** Serialized responses never carry failed IDs, endpoints or counts. Response latency, however, reveals how many 4-scope waves contained a *stalled* check (P3: 5 s vs 10 s), which is a lower bound on the number of stalled sources. It does not identify them, and fast failures (forged, refused) are invisible. The docs' "without identifying or counting them" is accurate only for the serialized wire. Either qualify the wording or bound the catalog to a fixed wall time.
- **F2 (test gap, medium): AC-1 privacy and contract properties are correct in code but not pinned by committed tests.** These are R03 (denial must keep coverage complete, the core of "indistinguishable denial"), R08 (no extra count/identity fields) and R12 ("timeouts … never authenticated grant denials"). My probes P1/P2 kill all three, so each needs only one or two assertions.
- **F3 (test gap, low-medium): AC-2 bounds are not exact in committed tests.**
  - R24: queue-inclusive whole deadline. My budget probe kills it.
  - R31: the live wrapper's socket bound is unbound; tests bind only the helper. The wrapper *does* call `ConnectionBudget::new/admit/run` (`evidence_library.rs:193-203`, R30 killed), but its constants are not exercised live.
  - R11/R13: deadline tightness, ±1 s.
- **F4 (evidence): no independent browser re-execution by me.** AC-5 rests on the author's IAB evidence. Download delivery is still unverified and is not counted as complete. Parent export delivery and the missing-evidence rows remain open.
- **F5 (cosmetic):** after a failed retry, `#catalog-status` keeps the stale `partial` class while it shows "coverage is unknown" (`app.js:40` does not reset `className`). The client also does not shape-check `value.scopes` entries; the server rechecks pins, so this does not escalate authority.

## Step 4 — Scope-narrowing language
- "Actual download delivery is still unverified in IAB" (followup-status): **legitimate**. It was named before review and is not marked done.
- "intentional privacy refinement of the requested per-scope error rows" (design Architecture): **legitimate**. It is recorded, it narrows toward the stronger invariant, and the parent REQ-2 pre-filter authorization contract supports it.
- "Slow healthy services may be reported partial and can be retried": **legitimate**. It is visible as partial, never declared absent.
- Out of Scope (missing-evidence rows, overview, conversations, search, annotations, views, analysis, admin, deployment): **legitimate**. These were named in the ledger before implementation and remain required roadmap items.

## Step 5 — House rules
- The fold, the store and admission are untouched; no subject is destroyed; no computed value is persisted (coverage is a per-request projection).
- No enforcement hooks and no new write authority. The Library stays read-only and separate from administration.
- `cites`/provenance are not involved.
- The v2 frontend is authorised by the owner, so it is not a forbidden second UI.

## Restoration and cleanup
- **Hashes:** pre/post `git ls-files` sha256 lists are identical (`90-hash-compare.txt`: HASHES-IDENTICAL, no tracked diff).
- **Rebuild:** `cargo clean -p kan` (removed 832 files) then a full rebuild. All focused Rust, Node, Python, Clippy and fmt checks green again (91-, 92-).
- **Processes:** no probe or test processes and no reviewer listeners remain (93-). All servers were in-test loopback fixtures and ended with their tests.
- **Left for parent cleanup:** this export's `target/` and `.local-state/reversion/02057c8236bd4d24a5ff4be6a1f98e37`.
- **Untracked review files:** `review-evidence/` and the pre-existing `north-star.json`.
- **Author edits:** none observed in the export during the review.

## Step 6 — Verdict
**APPROVE WITH FOLLOW-UPS**

Every probe I ran, including hostile, timing and cancellation cases, shows the checkpoint's production behaviour is correct:
- Healthy scopes stay browsable beside forged, refused, stalled and denied sources.
- `coverage` is an explicit per-request projection.
- A signed denial stays indistinguishable from an unconfigured scope.
- No failed identifier, endpoint or count is serialized.
- The 5 s / 3 s / 4-of-12 / 6 s / 35 s bounds hold, and the 16-scope worst case returns in about 20 s.
- Client cancellation releases permits.
- The UI keeps partial coverage visible, clears old authority on retry and lock, and fails closed on malformed capabilities.

Storage and admission are unchanged, and the trailer replays as DEMONSTRATED with compiled assertion failures. No invariant is violated.

The gaps are evidentiary, not behavioural. Follow-ups:
1. Pin R03, R08 and R12 with the P1/P2 assertions, especially "denial-only catalog is `complete`" and "timeout is never denial".
2. Add the queue-inclusive 35 s test (R24) and a live 13th-socket refusal or a constant-binding test for `serve()` (R31). Tighten the deadline assertions (R11, R13).
3. Qualify or mitigate the wave-latency count side channel (F1).
4. Reset `#catalog-status` className on retry failure (F5).

Real browser file delivery, missing-evidence rows, the collection overview and the rest of the full-frontend roadmap remain **open**. This approval does not close them.
