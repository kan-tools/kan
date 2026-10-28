review-evidence/ — independent cold review of frozen 0d048486c0e7c4e9bd2de76f19489b4d173975d4
(feat/kan-v2-conversation-adapter). Reviewer: Claude Code, Opus 5.5 (claude-opus-5-5), no subagents.

REPORT.txt                     full report and verdicts (read this first)
verify_identity.py             export/manifest/commit-tree/source-worktree identity check (sha256 + git blob)
run.sh                         wrapper: every command line, cwd, target dir, full output and exit code -> logs/
controls.py                    concern-driven semantic controls (mutate one guard, run, restore, re-hash)
probes/zz_review_interp_probes.rs   27 independent probes (pass_* assert required behaviour; char_* characterise)
probes/zz_review_interp_alloc.rs    counting-allocator probe: peak heap vs charged budgets
controls/<id>.txt              full log per control incl. classification and restore hash
controls/summary-all.txt       one line per control
logs/00-identity-before.txt    BEFORE identity (PASS)
logs/01-context.txt            repo root, branch, log graph, merge base, main...HEAD stat
logs/02-commit-ranges.txt      per-commit stats; Scope A = e5ebfed..9fe23a3 + 0d04848; Scope B = eb4f471..a65e2a6
logs/10-clean.txt              cargo clean -p kan
logs/11-build.txt              cargo build --features v2-crypto --tests
logs/12-baseline-tests.txt     7 integration targets (81 tests)
logs/13*-units*.txt            lib units: evidence_interpretation::tests, evidence_assembly::tests
logs/14-clippy-v2.txt          strict all-target v2 clippy
logs/15-fmt.txt                cargo fmt --check
logs/16-consumers.txt          consumer / side-effect surface search
logs/20-probes-run1.txt        FAILED METHOD: probe compile error (my untyped vec!) — retained
logs/21-probes-run2.txt        FAILED METHOD: my fuzz alphabet index bug (% 13 on 12 bytes) — retained, not a finding
logs/22-probes-run3.txt        probes: 27/27 pass on unmutated source (char_* output inside)
logs/23-alloc-probe.txt        allocation amplification measurements
logs/30-controls-driver.txt    control driver stdout
logs/40-scope-narrowing-grep.txt
logs/9x-*.txt                  final re-runs and AFTER identity
Temporary copies tests/zz_review_interp_probes.rs and tests/zz_review_interp_alloc.rs were
placed in the export only while running and removed before the final identity check.
Not run, deliberately: kan/day commands (live-log read/write forbidden under day#168/kan#197),
network, installs, replay/lifecycle history (retained results read instead).
