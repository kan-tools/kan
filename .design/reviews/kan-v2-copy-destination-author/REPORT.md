# Profile-3 destination author qualification

This is author verification, not independent approval. The fresh Opus review of
2c7c6cb approved the admitted-only prerequisite; its preserved report is under
`../kan-v2-purpose-gate-opus/`. This new destination needs its own cold review.

Implemented: explicit profile-3 owner API, canonical retained plan and original
object inventory, bounded transactional copy/resume with newly issued retained
proofs, exact stored-proof preservation, completed-copy admission, and explicit
owner CLI plan/batch/verify/backup/rebuild. No service activation or production
migration is performed. Existing HTTP/spool/Library profile-3 integration,
RetryImported, degraded inventory/bundles and takeover remain required.

## Executed evidence

- 136 distinct Rust test functions across 10 targets pass: 22 destination,
  10 profile-2 followups, 11 lifecycle, 10 attested store, 3 plan, 10 source,
  6 recovery CLI, 19 surface, 34 legacy store, 11 legacy service. This includes
  subprocess helper tests; counts are not 136 independent acceptance criteria.
- Targeted combined run originally covered 19 destination tests; the final
  storage run adds 3 WAL/rebuild-death cases (22 total). The copied-artifact
  Python oracle assertion was then run explicitly against the completed copy.
- Strict all-target `cargo clippy --features v2-crypto --all-targets -- -D warnings`
  and format pass. `cargo check --features v2-storage --bin kan-v2` passes with
  3 existing dead-code warnings for capture-wait helpers; this is not a clean
  strict-Clippy result for that feature combination.
- Nine compiled negative controls in `scripts/copy_destination_negative_controls.py`
  fail named assertions, not compilation: ignore source digest; omit preflight
  completeness; omit writer-transaction membership recheck; ignore external
  archive pin; ignore historical issuer; ignore retained position; omit Python
  lexical sort; wrong inventory capability; unregistered plan artifact write.
  Restored destination/source/surface suites pass (19+10+19 at that point).
- The Python source oracle deliberately reads a different SQL order before its
  own sort, resolving B-F1's vacuous ordering fixture. Source refusal reasons
  are pinned per schema/profile case (B-F2).
- A-F1 historical positives are named in the governing qualification contract.
  Single-H retained prefix followed by C admission, byte/purpose preservation,
  mixed-H refusal, retained-after-prefix refusal and admitted-inside-prefix
  refusal are tested. H=C isolates the latter from the codec's admitted-issuer
  check. The mixed-H test supplies valid signed proofs and pins the distinct
  historical-issuer error.
- A-F2/A-F3 annotate the old profile-2 purpose tests as generic refusal, pin exact
  reasons, and add verify/backup/recover CLI refusals. A-F4 annotates superseded
  mixed-purpose prose inline.
- Process exit is injected at all 4 initialization, 7 copy transaction and
  4 rebuild boundaries. This demonstrates SQLite transaction recovery on this
  host, not physical power-loss safety.
- Catalog, typed mutations, independent SQLite column inventory, facade digest
  and facade-call controls change together. Raw SQL remains outside the existing
  compiler filesystem-mutation guard; no stronger enforcement is claimed.

## Failed attempts retained

`initial.txt`: a regression removed the existing recovery-source path/context
from one CLI error. Restored that context; the existing lifecycle test passes.
`third.txt`: new test used the wrong service module alias, a compile error; fixed.
`fourth.txt`: a new negative fixture attempted to issue Admitted for H!=C and was
correctly refused by the pure codec. Changed that case to H=C to isolate the
planned-prefix ordering invariant. Failed attempts are not counted as controls.
The first wrapper invocation lacked executable permission; reran it via `sh`.

## Limits

Synthetic data only, one Apple-silicon host, four Cargo jobs and one heavy job at
a time, reused target. No installs, dependencies, live keys, provider traffic,
merge, cutover, archive erasure or background server. The source may require a
separate derived-data rebuild before planning. Copy writes are bounded, while
verification/full-prefix scans remain a correctness baseline, not a latency or
large-archive throughput claim. Incomplete source-copy status cannot prove a
partial prefix against an absent source; resumption verifies the actual source.
Cross-host one-writer fencing remains owner responsibility. No parent roadmap
or full frontend acceptance criterion is closed by this checkpoint.
