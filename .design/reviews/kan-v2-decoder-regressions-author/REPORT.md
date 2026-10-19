# Promoted independent decoder regressions

Promotes PA1/PA2 from actual cold Opus session
b934ebe8-1095-4d8a-b70a-603ab61d4ba4 (frozen 1833ee5, scope A APPROVE WITH
FOLLOW-UPS). Raw review source/report is retained in the stacked recovery codec
PR #298. Logging was made test-local, unused imports removed, and the accepted
corpus has a nonvacuity assertion. Production decoder bytes did not change.

The mutation corpus checks that every recognized Capture preserves the parsed
JSON value after serializing its Header. Timestamp cases include unknown
version/observer/event/outcome precedence. Both promoted tests pass; moving the
clock check before unknown classification fails PA2, and removing unit-variant
extra-field refusal fails PA1. Restoration, strict all-target v2 Clippy and format
pass. These close author-side A-F1/A-F2 follow-through before consumers. They do
not close full reconstruction or browser acceptance. CI includes the new target.
