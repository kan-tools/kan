# Physical bundle reader: author qualification before replay follow-through merge

This qualifies the read-only inspection draft based on b52aa48. It is not an
independent verdict. Replay's A-F1/A-F2/A-F3 follow-through must be merged and
checked before the next combined independent review. No bundle creator,
restorer, publisher, job, RPC or frontend acceptance is implied.

The reader pins a SQLite transaction, verifies UTF-8 / KNB1 / version / exact
schema and caller identity, independently checks cell classes, bounds and
canonical keys, budgets acquisition before Rust copies, and invokes pure replay.
It refuses missing history, standalone fallback and foreign checkpoints. Original
corrupt/empty BLOBs remain exact retained evidence. Pre-open custody checks cover
the main file and existing sidecars, including symlink/inode aliases; the source
byte budget is a pre-open observation, not a hostile namespace/growth fence.
SQLite coordination files may be initialized by read-only open. No source record
is rewritten. Work/byte metrics are not exact RSS or preemption of filesystem I/O.

Python SQLite constructs physical fixtures from the 45 independently signed
replay cases. The reader reproduces all 13 accepted / 32 refused histories and
checks main-file byte preservation. The SQL fixture is the previously proposed
DDL, with an exact runtime-copy check; this is not a second semantic-schema oracle.
Seven Python schema tests pass.

117 affected integration functions pass: 11 attested lifecycle, 33 copy destination,
10 bundle reader, 10 replay, 34 store, 19 surface conformance. The first surface
run failed two checks for omitted surface declarations and the changed capability
enum digest; these were corrected explicitly, with original failures retained.
Two additional units prove pinned WAL snapshot isolation and cancellation after
identity acquisition. Integration coverage includes malformed schema/cells,
source/item/byte budgets, all standalone-reader refusal, source permissions,
sidecar aliases, busy source and a real hot rollback journal. That hot-journal
inspection refuses without changing either main file or retained journal.
Strict all-target v2 Clippy and formatting pass.

Seven selected reader controls compile and demonstrate incorrect acceptance or
snapshot mixing: schema, identity, observation coordinate, acquisition bytes,
items, external checkpoint and pinned transaction. An eighth control supplies the
wrong persistence capability and fails the independent call inventory; all 19
surface checks pass after restoration. Canonical text guard removal SURVIVES:
the typed CID parser already rejects the tested uppercase representation. This is
recorded as a redundant defense, never a semantic kill. Initial runner failure
and the classified continuation are both retained. Restored reader and snapshot
suites pass. This is selected mutation evidence, not an exhaustive score.

No .lake, separate Cargo target, live archive, key, deployment or main merge.
The actual Library browser download remains unverified because the Mac is locked.
