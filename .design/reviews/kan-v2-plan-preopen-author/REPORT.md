# copy-plan pre-open custody correction

Addresses F-A1 in the fresh independent inventory review (session
 d161a685-6c85-46cb-8cd6-fc627216e19f, frozen 2f6a309; preserved in PR #296).
The filesystem-only output/source-family check now precedes PlannedCopy::open.
The retention-time check remains. Existing owner files at plain, Unicode and
case-alias reserved sidecar names are preserved before any SQLite connection.
The shared alias helper now states its APFS qualification and filesystem/race
limits next to the implementation.

Qualification: evidence_copy_destination 33, evidence_copy_source 10 and
surface_conformance 19 (62 functions) pass; strict v2 all-target Clippy and fmt
pass. Whole-production reversion of all three changed source files makes the
new named regression fail, and baseline/restoration pass. The earlier two-file
reversion before the comment-only filesystem disclosure and the final three-file
reversion are both retained. No production archive was opened.

A new independent correction review is still required; this is author evidence.
