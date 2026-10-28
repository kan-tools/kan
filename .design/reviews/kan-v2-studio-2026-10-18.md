# Studio theme and worker history review — 2026-10-18

Author-maintained disposition; the adjacent `.txt` is the exact independent
report. Reviewed implementation: `75fea76..c2f1017dafd4e5c196bc8990981d693db384ecfb`.
Claude Code initialized as `claude-opus-5-5`, session
`3227b193-bdb0-410d-a10e-b46460f0f3cf`, in an isolated source export.
Verdict: **APPROVE WITH FOLLOW-UPS**. Raw report SHA-256:
`174d9536b77123b8e5111f683c0723a04f4aeff65d1a6dcb22108b7741418904`.

The reviewer independently passed workspace build/tests, focused v2 gateway (17
plus one ignored), operations (13), surface (19), operations units (2), Node (10),
both Clippy modes and format. Whole worker-file reversion failed both named
history regressions and restoration passed. Watermark, successor, acknowledgment
merge and timestamp-pairing mutants were killed. Three lineage/frontier mutants
and the reporter future-clock mutant survived; these are test gaps, not claimed
kills. The reviewer reproduced a SQLite busy-read flake in older polling tests
under concurrent fsync load; repeated runs did not establish its cause. Full raw
logs/probes remain in the permanent build worktree's ignored review export.

The author subsequently promoted lazy reporter binding/absence and worker binding
probes, added regressed-frontier/different-head/unacknowledged-position cases, and
made the two older polling tests retry only DatabaseBusy/DatabaseLocked within
their existing deadlines. Other read failures still panic. This changes tests,
not the reviewed production behavior. The expanded operations suite is recorded
separately from the reviewer's 13-test run. Badge/future-reporter follow-ups are
assigned to the next child build and require its own fresh review.

The author's exact-head Linux CI completed after the reviewer's last CI knowledge:
[CI run 39156515326](https://github.com/kan-tools/kan/actions/runs/39156515326),
all jobs green at c2f1017. Its global-cap negative control passed baseline, failed
on the specific connection-33 refusal assertion with the cap removed, and passed
restored. The extracted raw control log is retained alongside this report. This
closes the earlier macOS survivor's platform evidence gap; the reviewer correctly
reported that it did not execute Linux itself.

Browser verification belongs to the author: System default, Dark/Light switching,
reload persistence, System reset, dark desktop Library, all nine Studio mobile
areas at 390px, dark dialog/Escape, and production dashboard login. No browser
errors/warnings were reported. The preview is still synthetic; no full reader,
search, annotations or admin integration is claimed.

Open engineering work remains: capacity/counter certainty and preserved-history
rotation; cumulative health coalescing (next child); current source identity versus
historical unclosed sessions; stricter browser persistence ownership checks; and
the complete reader/API/frontend matrix. A lineage refusal remains conservatively
stale rather than exposing a diagnostic reason. Legacy kan/day backfill is still
pending under the known two-withheld-claims limitation, and no witnesses/CIDs are
fabricated. The owned reviewer target was removed after exit. Draft #281 is stacked
on #280; no merge, deployment or live migration occurred.
