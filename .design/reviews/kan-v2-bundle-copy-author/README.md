# Bundle copying author qualification — CI passed, review pending

Initial remote MSRV compile at8f2bcb6 exposed an internal visibility error:
copy.rs called create::destination_path while it was private to create.rs.
The helper is now pub(super), available only inside the bundle module, without
changing its validation behavior. The failure excerpt is retained here.

Local compilation waits for the independent publication review to release the
shared Cargo target. Full CI qualification has now passed as recorded below;
independent review and compiled semantic controls remain pending.
Additional prepared probes distinguish exact signature bytes from statement
identity, exercise a second physical copy step on a 1MiB synthetic orphan,
check a real logical COMMIT error, and distinguish cancellation before the first
copy step from an uncertain attempted copy. All fixtures are synthetic.

Corrected537a309 passed MSRV and canary in CI39334311418. The complete v2
test run and local qualification are still pending; this is not full acceptance.

CI39334311418 then caught the omitted registration of the new catalog rule
`checkpointed-bundle-copy`. The rule is now linked to the concrete copy test
module in the independent rule inventory. This was a conformance declaration
error, not a passing test run; its failure excerpt is retained.

At ac4e528, CI39335149369 passed all three jobs (test, canary, MSRV). The test
job passed the full v2 integration set, including46 bundle-creation/copy tests
with4 deliberate crash-child helpers ignored by the direct runner,18 inventory
tests, and19 surface-contract tests. The parent tests invoke the crash helpers
explicitly. Both strict Clippy variants and formatting passed. Exact per-target
results and the locally retained full-log hash are in `ci-qualification.json`.
This remote run replaces a duplicate author baseline locally; the next actual
Opus5.5 review still must execute focused adversarial probes and semantic controls.
