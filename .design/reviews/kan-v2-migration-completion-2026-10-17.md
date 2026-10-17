# Migration inventory and harness review disposition

Public purpose: `.design/kan-v2-migration-inventory.md` and `.design/kan-v2-migration-harness.md`. Private teloi were unavailable to external reviewers, not absent. Both reviews used fresh actual Claude Code `claude-opus-5-5` sessions, public source only and synthetic fixtures.

| Review | Exact runtime range | Session | Raw-report SHA-256 | Verdict |
|---|---|---|---|---|
| Initial | 256871b09ed76ca84bed504394fddc4dcc705370..b9859a00f9c55a4aa6ca81f8673f026c07869ff0 | a6064673-20c2-4075-8b46-b991c0bee312 | 53a16603499e2a6fc0c3d0f95b334256fb39133b863d5e3c8685871b7ebda593 | BLOCK |
| Correction | b9859a00f9c55a4aa6ca81f8673f026c07869ff0..d953afca0d71bb38dec58627235184b437162aa8 | 870e202b-878f-4a15-ab0f-3628e38166d9 | ce353c75e7aca898233d017a7a42ee8be2745bf67bc0ca2e612ece00b62f5211 | APPROVE WITH FOLLOW-UPS |

Raw reports and streams are retained privately under `.local-state/reviews/`; this file is the author's disposition, not a replacement reviewer report.

The first reviewer found that explicit scope initialization could falsely label file-backed system credentials as keychain coverage, and that unknown public-ledger entries were called harmless exclusions. Corrections return `keychain-unused` before any credential action for that writer profile; retain older keychain routes; mark unknown and empty public-history selections incomplete; and preserve a genuine CI measurement while correcting its description. Claim-loss checks now precede principal comparison.

The second reviewer independently ran 38 targeted tests, build, Clippy and formatting. Scratch probes recorded exactly the two help calls in excluded keychain cells, preserved old-writer routing, checked the local keychain guard, injected lost claims and changed principals, and tested unknown files, temporary entries, symlinks and empty selections. It approved with follow-ups.

Post-review follow-ups add actual branch assertions and fake-writer call logs, correct “complete author” to “principal” (the CLI projection omits method/state), label unmeasured keychain rows PREDICTED, and use the appropriate notice text for log-directory exclusions. These test/documentation/diagnostic changes are author-validated and are not represented as a third independent review. The controlled negative tests reproduced missing initialization as `unwritable` and unknown-ledger exclusion as a runtime assertion failure, then restored passing source. The initial signature of the mutation did not match formatting and was corrected before any mutation; no failed-to-run control is counted as demonstrated.

CI migration matrix [run 39006999615](https://github.com/kan-tools/kan/actions/runs/39006999615) passed at b9859a0, including the released v1.0.0-beta.1 seed writer. This proves the corrected initialization route, not final-head CI or macOS keychain execution. No real keychain mode was run locally. Final-head CI remains a separate merge condition.

Remaining boundaries: previews are file-level observations, not atomic snapshots, signature/graph verification or completed imports. Public identity selection is explicit and excludes credentials. A concurrent path-to-FIFO replacement can still block the preexisting read-only inspector; no adversarial-filesystem race qualification is claimed. Negative-control scripts temporarily edit tracked source and must run in an idle author worktree; interruption by SIGKILL needs manual restoration from Git. Encrypted resumable import, operational backups and cutover remain later work.
