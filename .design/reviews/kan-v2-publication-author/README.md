# Publication author qualification

The publication candidate has passed 142 targeted integration checks (37 bundle
creation/restoration/publication, 14 claim codec, 25 operations, 47 recovery
protocol, 19 persistence surface), four decoder unit checks, 52 Node checks,
strict all-target v2 Clippy and formatting. Three bundle subprocess entry points
and one manual operations fixture are intentionally ignored by the normal run;
the crash parents invoke their corresponding children explicitly.

Both complete profiles, 18 abrupt-death boundaries, historical resume after
failure/later restoration, actual intent/observed COMMIT errors, ordinary output
verification, exact O1 and retained failed outputs are exercised. The Python
oracle reads actual SQLite rows and independently checks signed history/output.
No live archives, keys or deployment were used. Power loss and indefinitely
blocked filesystem calls remain unqualified. Fresh independent review is pending.

Initial CI39330364567 at c4928af failed two synthetic fixture assumptions:
foreign keys stopped simulated object/record loss, and stopped the conflicting
writer before it reached the intended lock failure. Fixtures now explicitly
simulate physical loss and the lock probe performs a constraint-valid no-op
update. Local attempt1 found the second incomplete-copy setup needed the same
explicit loss simulation. Failure excerpts and local full logs are retained.

Ten publication/cancellation controls were compiled and caught at assertions:
intent/observed COMMIT classification, exact physical O1, ordinary profile audit,
historical selection, held output snapshot, output page ceiling, both output
capabilities, and premature concurrent worker admission. The first page-limit
control survived because the test accepted a later size refusal. The test now
requires a real SQLite capacity error and an output within the ceiling. A first
strengthening misclassified the nested Store(Sql) error; its failing restored
run is retained. The corrected test catches the control and passes production.

Parent6df024b passed CI39328129264 and performance39328130190. Duplicate
CI39328130214 failed older operations PO8 at its final next-job assertion.
Published cancellation precedes thread return; admission correctly uses
JoinHandle::is_finished. PO8 now waits for admission to advance, retaining its
blocked-worker no-overlap assertion. A compound early-admission/detached-worker
control fails that assertion. No operations production behavior changed.

Prior cold bf3c44e review probes are promoted as ordinary tests for D-F1/D-F2,
C-F1/C-F2 and A-F1, plus malformed response references after valid request
rendering. The typed-digest probe drops the reviewer's raw tag-byte substring
heuristic: random signature bytes can contain that pair. Actual decoding and
exact typed claim equality establish the intended boundary.

Raw reviewer sessions and exports are not published here. The prior report is
in `../kan-v2-combined-followups-opus/`; its approval covers bf3c44e only.
Full frontend, backup/rebuild, availability, search/views, annotations, jobs/day
and human administration remain open parent work. No main merge or activation.

All six promoted regression controls now fail at the intended assertion. The
first restored bundle run from that control driver omitted the configured crypto
oracle Python environment, so seven oracle tests failed on a missing import.
The driver environment is corrected; that harness failure remains retained.
Final restored qualification passes all 142 integrations, four decoder units,
52 Node checks, strict lint and format using the configured oracle environment.
