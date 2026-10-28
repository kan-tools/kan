# Copy planner review follow-ups

Author verification, 2026-10-19. Fresh independent review of these follow-up edits
remains required; the preceding unmodified review is in
`../kan-v2-copy-planner-opus/` (session 943a06d3-b949-4cbe-9e03-08bda409c91e).

A-F1 now isolates a wrong external pin on an unchanged source and a sibling
recipe, independently of source-change refusal. A-F2 covers extra index, trigger,
view and table plus wrong version/application markers, preserving source bytes.
Both new compiled weakenings fail named assertions.

A-F3 adds expected canonical/schema class and exact intended reason to every
negative vector, plus four deliberately noncanonical encodings. The independent
Python generator reproduces five positives and 37 negatives. A-F4 sorts objects
in Python independently of SQL ordering and exercises 27 differently sized
objects (one request plus 26 staged objects).

B-R1 names both Ledger and attested Archive in the three live database/WAL/SHM
catalog rows with the profile-selected lifecycle rule. B-R2 pins legacy verify
labels, including structural closure and unverified cryptographic admission.
Two additional CLI label mutants fail the named owner lifecycle assertion.

49 targeted Rust checks passed (11 lifecycle, 3 plan, 10 source, 6 recovery CLI,
19 surface). Strict all-target v2 Clippy and formatting passed. All eleven
plan/source controls and twelve lifecycle controls failed named assertions;
restored affected suites passed. Production codec, planner and lifecycle code
are unchanged by these follow-up edits.

The governing design records C-F1/C-F3/C-F4 decisions for the next destination
slice. Profile-2 admitted-only enforcement, profile-3 destination writes, bundle
format, RPC, degraded browsing and the full frontend remain separate work.
No parent acceptance criterion is closed here.
