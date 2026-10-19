# Copy-plan/source author qualification

Source: da12652, including lifecycle regression additions from ca53c1d.
Seven integration targets pass 94 checks: 3 plan, 8 source, 11 lifecycle,
10 attested store, 9 attested follow-ups, 34 legacy store, 19 surface.
Strict all-target v2 Clippy and rustfmt pass. Independent plan vectors match
5 exact positives and 33 labelled negative examples. The source digest also
matches an independent Python byte/CID oracle on a synthetic archive.

Nine compiled plan/source mutations fail named assertions; restored plan/source
checks pass. Seven compiled lifecycle mutations likewise fail named assertions,
including the review's formerly surviving exact-schema and pre-commit-audit
removals; restored lifecycle/store/surface checks pass. Raw outputs are retained.

The source planner is read-only. Tests cover later admission with a pinned old
snapshot, same-frontier receipt replacement, wrong scope/H/pin, absent payloads,
staged objects, exact database/WAL preservation, separate derived recovery, and
structurally healthy archives with invalid signatures or divergent manifests.
No destination writer, profile-3 schema, live migration or cutover is implemented.
The governing design has further proposed bundle/custody refinements that need
fresh independent review. This is author qualification, not that verdict.
