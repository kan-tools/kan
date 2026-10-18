# Independent adversarial review evidence: Library reader slice

Reviewer: fresh Claude Opus 5.5 session (claude-opus-5-5). It had no part in writing this code.
Range: `git diff HEAD` in this export (HEAD 2c6fdd9, labelled "Review baseline 9d300b4").
Commits 9d300b4, df74506 and 833bef3 do not exist in this export. Correspondence to df74506 is
the caller's assertion. The current src/web diff matches the author's `reversion/production.patch`
file for file (10-production-diff-vs-author-patch.txt).
Env for every cargo run: CARGO_TARGET_DIR=<export>/target, jobs 4, debug 0, incremental 0.

| File | Content |
|---|---|
| 01-focused-tests.txt | evidence_reader 8 passed and 1 ignored; evidence_library_cli 1 passed; surface_conformance 19 passed |
| 02-node.txt | library/theme/operations UI tests: 29 passed |
| 03-fmt.txt | `cargo fmt --all -- --check` exit 0 (rustfmt leaves some overlong lines unformatted) |
| 04-clippy-v2-alltargets.txt | `cargo clippy --features v2-crypto --all-targets -- -D warnings` exit 0 |
| 05-probes-rust.txt | tampered-signature catalog, unreachable scope, signer==issuer, offline paths, slot exhaustion, Host/Origin |
| 06-probes-missing-object.txt | missing/corrupt object after service start: page and source both Corrupt; Missing only beyond pin |
| 07-probes-ui.txt | stale scope-switch click/Next, 503/404 lock behaviour, bidi text |
| 08-*.txt, 09-*.txt, mutants/ | mutation campaign (raw per-mutant logs). Every original was restored and its hash verified |
| 11-reversion-replay.txt, reversion/ | whole-production reversion via scripts/revert_v2.py: DEMONSTRATED |
| 12-post-restore-tests.txt | clean -p kan, then rerun on restored source: all pass; hashes OK |
| probes/ | probe sources. The Rust probe was copied into tests/ only while it ran and then deleted |

M06 was a compile failure and does not count as a kill. M06b is its semantic replacement.
No kan/day writes, browser, installation, live data or network beyond loopback were used.
