# Logical member verifier: author qualification

Sixteen Rust test functions pass, including real writer requests in both profiles,
empty and complete members, an admitted suffix after a copied prefix, partial
copy status, exact occurrence/orphan losses, conflicting lengths, issuer-resigned
false copy digests, missing membership, writer predecessor/operation/slot checks,
hash-valid invalid writer signatures and exact manifest substitution. Limits
cover item/input-byte caps, initial cancellation, a tiny elapsed-time allowance
and oversized physical/expected lengths. Strict v2 all-target Clippy and format
pass.

The independent Python generator constructs 16 cases (7 positive, 9 hostile),
with real canonical signed requests, receipts and P-256 issuer proofs, using
only public test scalars. Its separate attestation verifier checks constructed
chains; its M1 and loss oracle match Rust. It is explicitly not a complete second
member-semantic verifier. The byte-identical fixtures regenerate and check.

Eight compiled guard removals fail named assertions: item/input budgets, source
digest, expected-length agreement, duplicate operations, original payload hash,
orphan loss preservation and invocation of retained-writer verification.
Restored tests pass. The early cancellation guard mutation SURVIVES: later
commitment framing still refuses cancellation. This does not cover prompt
interruption of earlier metadata/hash work. The initial runner stopped on that
survivor; its raw failure is retained alongside the final run with the survivor
explicitly reported, rather than relabelled as a kill.

This is pure verification of caller-acquired bounded inputs. Original corrupt
bytes are retained in M1. A missing/corrupt request is not a verified writer
request. The result grants no observation-history, physical-format, publication
or durability authority. Full loss-event partitioning, restoration/output/state
replay, checkpoints, schema reads, writer/crash jobs, RPC and UI remain required.
Fresh actual Opus 5.5 review is pending. No production archive/key was read.
