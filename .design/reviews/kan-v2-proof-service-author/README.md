# Proof-service and Reader author qualification

The focused local run passed82 integration tests:34 inventory/proof-service/Reader,
1 transport,27 legacy Reader,1 Library CLI, and19 surface-contract checks. Two
legacy Reader fixture helpers remain directly ignored. Strict all-target v2
Clippy and formatting passed. All data and signing/decryption keys were synthetic.

The first attempt passed33 of34 inventory tests. Its only failure was the new
empty-copy fixture requesting a1MiB budget below the existing copy API minimum;
the fixture now uses16MiB. Production budget checks were not weakened. The next
attempt stopped at the15GiB disk guard without building. Six retired Cargo caches
from this task were removed only after verifying no active locks or open users;
source, logs, review evidence and archives were preserved. The final run then
passed. Full logs and the cleanup record remain in ignored local state.

qualification.json binds the exact tested file hashes to the subsequent fixture
commit and records retained log hashes. This is author qualification, not an
independent verdict. Fresh actual Opus5.5 review is pending. Human Library/config/
CLI integration, actual browser delivery, deployment and cutover are not claimed.
