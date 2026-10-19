# Lifecycle correction qualification

Source:9aca45d (including ca53c1d), tested in the dependent copy-upgrade
worktree. 36 targeted checks pass across lifecycle, legacy recovery CLI and
surface conformance; strict all-target v2 Clippy passes. Ten compiled semantic
mutations fail named assertions; restored lifecycle/store/surface checks pass.

B-F1: corrupt proofs must fail before a profile marker/schema commits.
B-F2: standalone verify and backup reject undeclared tables and indexes.
B-F3: verify/recover labels pin purpose dependence and unknown history.
B-F4: legacy and proof recovery failures again include the source path.
B-F5: backup/recovery surface rows explicitly name profile-selected validators.
The existing profile2 schema, proof format and runtime admission behavior are
unchanged. This is author qualification; fresh correction review is pending.
