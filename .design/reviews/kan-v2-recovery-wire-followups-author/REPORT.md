# Recovery wire and draft-format review follow-through

Addresses B-F1..B-F4 and C-F1/C-F2/C-F4 from actual cold Opus session
b934ebe8-1095-4d8a-b70a-603ab61d4ba4, frozen 1833ee5. The unmodified report and
all failed/corrected reviewer methods are retained in ../kan-v2-recovery-wire-opus.
A-F1/A-F2 are handled by the inherited promoted decoder regression commit ede35ec.

Observation fixtures now distinguish canonical text ordering from binary CID
ordering: 6 chain positives, 4 shape positives, a separately pinned same-key-role
positive, and 57 hostile vectors. Seven observation functions and the 17 decoder
functions (24 total) pass; the new binary-order compiled control fails a named
assertion by admitting the hostile order, then the restored suite passes. The
prior seven author controls were not rerun. Strict v2 all-target Clippy/fmt pass.

M1/O1/R1 now have 9 member and 4 candidate framing cases, including distinguishing
CID orders in membership, originals and restorations. They remain framing-only;
Rust commitment computation and complete member/state truth are not claimed here.

The draft SQL identifier constraints now use byte bounds, printable ASCII and a
length equality check that rejects embedded NUL. Six in-memory schema tests pass.
Reverting all five SQL correction hunks makes the new named Python test fail;
baseline/restoration pass. The day reversion adapter has an explicit alias for
that schema test. Replay this mixed-language trailer with `scripts/revert_v2.py
--verify COMMIT --helper /absolute/path/to/day/scripts/revert-demo.py --production
.design/fixtures/recovery-bundle-v1-schema.sql`: the explicit production path is
required because the Python schema test is deliberately under .design/tools,
not the helper's default tests/ exclusion. The retained production.patch is the
unfiltered worktree diff; the runner's report records the exact five SQL hunks
selected. This is draft-schema correction evidence, not storage-writer acceptance.

Recorded decisions: role/domain separation does not require different DIDs at the
wire layer; owner jobs default to distinct keys and disclose explicit reuse.
Refusal labels pin single-fault cases, not a total multi-fault precedence. Named
range/signer errors and the redundant DID canonical comparison are not claimed as
independent security boundaries. Authenticated expected lengths above 4 MiB
require explicit forensic-recovery refusal, preserving source and failed output.
No Rust production codec change or consumer was added. Fresh review of this
follow-through and the next streaming component remains required.
