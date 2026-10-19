# Owner-copy follow-up author qualification

This is author evidence, not independent approval. It addresses F1-F7 in the
unmodified `../kan-v2-copy-destination-opus/evidence/REPORT.txt`.

F1: the private plan cannot occupy the verified source SQLite family, including
case/alias sidecars. The CLI checks both SQLite families before opening either
database. Existing source/artifact bytes are retained on refusal. Bare decoding
and the trusted-filesystem assumption are explicit; hostile path races are not
fenced by this patch.
F2: exact schema refusals cover extra index, trigger, view and table through open,
verify_file, resume, existing-handle verify and backup.
F3: valid foreign object/inventory and a valid H receipt with valid C proof pass
local audit but refuse exact source-prefix comparison before more proofs exist.
The old wrong-length test now names its actual earlier guard.
F4: CLI explicit-profile/pins/key/privacy/budget/resume/init/path preconditions
refuse with named reasons and without new output.
F5-F7: empty API initialization does not prove key possession; batch timestamps
are milliseconds, admission timestamps seconds; plan privacy errors name plans.

Executed: 28 destination + 10 source + 19 surface test functions pass after
restoration, including three subprocess helper functions. Six compiled controls
in `scripts/copy_destination_followup_controls.py` fail named assertions:
remove custody guards; bypass CLI path checks; omit full-audit schema guard;
skip object prefix; skip record prefix; omit explicit CLI profile. They are
selected guard removals, not a claim that the whole API-changing patch reverted
and still compiled. Strict all-target v2-crypto Clippy and fmt pass.

Retained failed attempts: first.txt is a fixture compile error (usize SQL value,
fixed with i64); controls-attempt1.txt stopped after two valid controls because a
schema pattern matched twice. Its narrowed full-audit pattern then reproduced.
Neither failed attempt is counted as a demonstrated regression.

The original reviewer report's per-object quadratic-read assertion is inaccurate:
copy_batch uses indexed Ledger::read_object, not RecoveryReader::read_object.
The unmodified report is preserved, and full audits remain an explicit cost.

Synthetic local fixtures only, shared target, four Cargo jobs, no server,
production archive/key use, activation, install or merge. No parent AC closed.
Fresh independent actual Opus review is still required for this correction.
