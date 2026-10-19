# Replay review follow-through: author qualification

This corrects A-F1/A-F2/A-F3 from the cold review of b52aa48 retained at 7a04798.
It is not a new independent verdict. The next cold review will cover this with
the physical reader. Original review reports, generator and expectations remain
unaltered in their retained directory.

A-F1 chooses immediate refusal: issuer-referenced candidates now verify their
writer signature and exact manifest/receipt binding before any history is
accepted. Unreferenced keys acquire no invented writer attribution. Scan bytes
include the additional manifest/receipt/request pass. Publication still performs
its complete output re-audit. P01's original accepted expectation deliberately
changes to refusal; P21 adds a valid signature with the wrong manifest binding.

A-F2 promotes the 20 design-derived reviewer cases and adds three author cases,
for 23 normal regression fixtures. P03/P04/P05/P20 retain their reviewer inputs;
the stricter A-F1 check adds a backstop to request-hash/length cases. Foreign checkpoints now run on untruncated history, including observer, issuer,
profile, scope and archive mismatches. P22 isolates candidate hashing on an
original-only object; P23 isolates authenticated length on complete-copy staged
membership without a writer request. The initial P21 constructor failed the
independent receipt-binding check because its changed operation was absent from
the receipt; correcting that receipt produces internally coherent signed metadata.
This constructor failure is reported here as an attempt note, not a Rust failure.

Six single-guard controls compile and admit hostile evidence: candidate hash,
candidate length, output losses, checkpoint context, candidate writer, and
original writer. The partial-copy record-length override alone now gives a
DIAGNOSTIC-ONLY failure: exact writer/manifest binding still refuses P20. Removing
both that override and candidate writer verification admits P20. The combined
control is explicitly not counted as a single-guard kill. Old virtual-output-writer
control is now named original-writer and uses P02; earlier control evidence remains
unaltered. Original/candidate request checks can backstop one another; no survivor
or diagnostic-only failure is disguised as semantic evidence.

A-F3 pins a conservative 3,816-byte upper bound for 32 unavailable entries with
80-byte DID strings, and independently verifies a maximal valid signed shape.
This keeps fixed 32-entry oracle partitioning tied to the 16-KiB wire ceiling.
The promoted budget test retains its monotonic acceptance/projection assertions;
log-only extra probes and an unused temporary value were omitted. No assertions
from the promoted core corpus, checkpoint or budget tests were weakened.

Qualification: all 16 replay/regression functions pass, including both immediate
writer-refusal regressions; strict all-target v2 Clippy and formatting pass.
Both Python fixtures regenerate exactly (45 original cases, 23 promoted/extended
cases). The controls restore both source files and all 16 functions pass again.
Whole-production-file reversion removes all 8/8 runtime hunks: both writer-refusal
regressions compile and fail semantically, then pass after restoration. The helper
output, actual Demonstrated-by trailer and six raw test logs are retained.

No physical writer, durability, job, RPC or UI completion is implied. No parent
recovery/frontend acceptance criterion is closed; fresh independent review remains.
