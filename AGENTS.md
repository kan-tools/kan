# Kan development SOP

Follow the owner-approved development flow and completion checklist in
[.design/kan-v2-next-build-status.md](.design/kan-v2-next-build-status.md),
section “Active development flow”. It is the standing SOP for this v2 build.

Build the complete approved product through continuous implementation and
integration, with targeted engineering checks, then conduct a thorough independent
review of the integrated result. This supersedes older per-checkpoint review,
mutation-matrix and reversion requirements in historical plans and process skills.
Do not reduce feature scope to a demonstration or restart interrupted reviews
merely to satisfy the superseded process. Read CLAUDE.md for artifact invariants.

The canonical SOP is recorded Git-first while day#168 / kan#197 prevent safe
worktree-local process recording. Do not redirect process writes into the root
checkout or reconstruct excluded claims. Backfill the SOP when the shared
workspace mechanism is available; do not maintain a second competing policy.
