# Bounded recovery commitment framing: author verification

This checkpoint adds incremental M1/O1/R1 framing, explicit section/count/order
checks and caller-selected work limits. A rejected operation poisons the builder.
Original corrupt or empty bytes remain representable; restoration bytes must
match their CID. These digests confer no member, state or publication authority.

The final baseline passes 32 Rust test functions: 8 commitment, 7 observation,
15 decoder and 2 promoted independent decoder regressions. Nine member/output
and four restoration fixtures match the independent Python framing oracle.
Strict v2 all-target Clippy and formatting pass. Initial baseline used the older
8/4 fixture set; final baseline uses the inherited expanded 9/4 set.

Eight initial compiled controls and the subsequently added binary-CID-order
control fail named assertions, with restored commitment tests passing. Controls
exercise poisoning, record position, domain separation, original object keys,
candidate content addressing, duplicate ordering, byte budgets and cancellation.
The additional CID-order control uses the independently expanded distinguishing
fixture. These are author checks, not a fresh independent review.

Complete member/proof validation, exact unavailable partitions, historical
candidate selection, publication replay, checkpoint verification, SQLite reads,
writer/crash jobs, RPC and UI remain unimplemented by this module. No live
archive, key or deployment was used. Fresh actual Opus 5.5 review is pending.
