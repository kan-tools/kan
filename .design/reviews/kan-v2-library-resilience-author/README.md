# Library resilience author evidence

Baseline 60f3d36. Private target COW-copied from the Library worktree and kan
cleaned before compilation; four build jobs, no parallel heavy jobs. Budget
units2, reader16+1ignored, real CLI1 and surface19 passed, then new body-deadline
case passed separately (total reader17). Node41, Python adapter7, strict v2
all-target Clippy and fmt passed. Initial unit/Node wrapper used zsh's read-only
status variable after success; raw test logs show success, wrapper exit was not
counted as passing. Subsequent commands use task_result correctly.

Whole-production reversion compiled and failed three named assertions; baseline
and restoration pass. Includes all changed production, Cargo config, adapter,
UI and docs; tests retained. No compiler error or external runner timeout is a
semantic kill. This proves those behaviors, not every connection/privacy branch.
Browser evidence and file-delivery limitation are retained separately.
