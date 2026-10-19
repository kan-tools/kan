# Bundle copying author qualification — pending

Initial remote MSRV compile at8f2bcb6 exposed an internal visibility error:
copy.rs called create::destination_path while it was private to create.rs.
The helper is now pub(super), available only inside the bundle module, without
changing its validation behavior. The failure excerpt is retained here.

Local compilation waits for the independent publication review to release the
shared Cargo target. No passing qualification or review claim is made yet.
Additional prepared probes distinguish exact signature bytes from statement
identity, exercise a second physical copy step on a 1MiB synthetic orphan,
check a real logical COMMIT error, and distinguish cancellation before the first
copy step from an uncertain attempted copy. All fixtures are synthetic.
