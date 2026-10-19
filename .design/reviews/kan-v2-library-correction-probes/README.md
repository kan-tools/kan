# Fresh correction review evidence — df74506..a8cbf21 (Opus 5.5, 2026-10-18)

Range: HEAD df74506 -> 61e2487 -> 22facfa -> a8cbf21 (all real commit objects
in this export). Index and worktree equal a8cbf21 except the extra staged
`review-context.txt`. Env for every Cargo run: CARGO_BUILD_JOBS=4,
CARGO_INCREMENTAL=0, CARGO_PROFILE_{DEV,TEST}_DEBUG=0, target = this export's
`target/`. One heavy job at a time.

| File | Contents |
|---|---|
| 00-pre-hashes.txt / 08-post-hashes.txt | sha256 of all tracked src/web/tests/scripts/Cargo files; identical |
| 00-index-blobs.txt | index blob ids |
| 01-focused-rust.txt | fresh `kan` compile; reader 15 (+1 ignored), CLI 1, surface 19 |
| 02-node.txt | library/operations/theme Node: 34/34 |
| 03-clippy-v2-alltargets.txt | `cargo clippy --features v2-crypto --all-targets -- -D warnings`, exit 0 |
| 04-fmt.txt | `cargo fmt --all -- --check`, exit 0 |
| 05-verify-<commit>.txt | `scripts/revert_v2.py --verify` replay of each actual Demonstrated-by trailer; raw logs under `.local-state/reversion/<uuid>/reversion-logs/` (864d79… 61e2487, df7e17… 22facfa, 7418f0… a8cbf21) |
| 06-mutation-summary.txt, 06-mutation-run-*.txt, mutants/*.txt | 47 mutants via probes/mutate_correction.py (exact single-occurrence replace, run, restore, hash-assert) |
| 07-queue-probes.txt | black-box timing probes (probes/zz_review_queue_probes.rs, copied into tests/ only for the run, then deleted) |
| 09-post-restore-*.txt | `cargo clean -p kan` + fresh rebuild after all mutations: Rust 1/15/19, Node 34 pass |

No kan/day writes, no browser, no network beyond loopback, no production
credentials. Compile failures/timeouts would be labelled and not counted; none occurred.
