# Inventory follow-up correction qualification

Addresses F-B1/F-B2 and the profile-2 item-budget gap in the fresh frozen 2f6a309
Opus review. The original report and failed probes remain unchanged under
kan-v2-inventory-opus. The parent migration F-A1 fix is merged from 69277b7.

A SQL CASE checks typeof(bytes) before evaluating length or reading payloads.
Non-BLOB cells become a local Corrupt state. It never casts TEXT into a valid
payload and never converts general SQLite errors into missing/corrupt states.

Regressions cover both archive profiles and tip/middle damage, fresh source after
a previously available selection, healthy neighbors, and a single-bit SQLite
serial-type flip. The 96 MiB child-memory fixture now includes TEXT as well as
BLOB and oversized manifest rows. Raw measured output is in raw/09-memory.txt.

70 targeted integration functions pass: copy destination 33, inventory 18 and
surface conformance 19. Two VM tests pass, including a real Inventory::page call
with a test-only in-memory unyielding view after ordinary startup. Its three-
second watchdog is asserted NOT to cause successful interruption; the handle
remains reusable. This avoids a huge on-disk workload and does not modify main
records. Strict v2 all-target Clippy and formatting pass.

Complete production-fix reversion (both production hunks; the new test-only hunk
is retained by the day engine) makes both type-damage regressions fail. Baseline
and restoration pass. Four compiled controls fail named assertions: SQL type
guard, page VM setup, startup record budget, and indexed oversized-row lookup.
The restored 18 integration and two VM functions pass. The earlier independent
review already reproduced the ten unchanged controls; this correction does not
claim to rerun all thirteen controls.

The design records WAL retention from long-lived inventory handles and requires
adapter lifetime/expiry plus mapping both typed cancellation and SQL interrupted.
Recovery design responses C-1..C-8 are in DESIGN-RESPONSES.md. Actual day validation
output retains primary-checkout path and withheld-claim warnings. No log writes,
maintenance witnesses, parent frontend completion, or codec/writer approval are
claimed. Fresh correction review remains pending.
