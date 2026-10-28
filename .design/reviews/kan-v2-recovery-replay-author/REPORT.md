# Pure recovery replay: author qualification

Frozen production implementation descends from 0e1eac0 and incorporates the
5edb505 member consumer follow-through. This report is author evidence, not an
independent verdict. No physical writer, durability, job, RPC or frontend
acceptance is implied.

The pure replay verifier authenticates the whole observation chain, checks the
original M1/frontier and exact initial loss partition, verifies candidate bytes
against existing member keys and authenticated expected lengths, and requires
one restored observation per candidate. Every restoration retains its derived
membership basis, including already-available keys without an initial loss.
Historical intents use only their then-selected candidates for R1 and a fully
re-audited virtual output for O1. Attempts retain their distinct intent/failure/
observed state. Optional independently retained checkpoints detect rollback only
through the pinned prefix; later unpinned truncation is not detectable.

Qualification after the member follow-through merge: 68 integration functions
(16 member, 23 promoted member, two member corrections, eight framing, two
framing regressions, seven observation codec, ten replay) passed. Two deterministic
framing cancellation unit checks passed. The final ten replay tests passed after
a test-helper type alias resolved Clippy's type_complexity finding. Strict
all-target v2 Clippy and formatting passed. The initial lint failure is retained.

The independent Python state constructor regenerates 45 cases: 13 positive and
32 hostile. It computes state, selected-output writer checks and commitments
independently over constructed valid source members; it is not a general second
source-member validator. Member fixture regeneration matches 25 cases.

Eleven compiled selected controls fail semantic assertions, and the restored
suite passes: M1, frontier, loss partition, historical R1, O1, intent citation,
terminal attempt, external checkpoint, partial candidate length, restoration
basis, and virtual-output writer verification. Raw per-control logs are retained.
This bounded set is not an exhaustive mutation score or a whole-file reversion.

Files 02 and 04 retain earlier 43-case and 45-case qualification respectively;
07 is the combined final implementation suite. Files 08 and 09 retain the lint
failure and corrected pass. Files 11-14 capture final polling/replay/oracle checks.
Independent actual Claude Code Opus 5.5 review is the next gate, with a separate
scope for the final member follow-through. Full parent acceptance remains open.
