# Author disposition of the cold review

The unmodified actual Claude Code Opus 5.5 report is `evidence/REPORT.txt`;
session e750ec23-bdfd-4ea6-9d4e-5fbe19cf8a14. Its three separate verdicts are
APPROVE WITH FOLLOW-UPS: overview correction at262cad3, profile-2 lifecycle
at7ab1afa, and profile-3 design readiness only. Required design C1/C3/C4 must
be resolved before destination implementation. The broader roadmap is open.

The original export remains unchanged. An independent author check against the
original export identity verifies all1621 recorded paths with zero differences
(`author-export-recheck.json`); the review prose's1323 count is preserved verbatim,
not substituted for that check. Raw review logs include its own failed probe
attempts and surviving mutants; none are relabelled as passing production tests.

A-F2 restart rendering has a separately committed correction, nine incorporated
abort-aware probes, 36 passing Node checks and three demonstrated UI controls.
Fresh independent review of that correction is separate and pending. The full
author browser matrix recorded after the frozen export is in
`../kan-v2-overview-browser-followup/`; it does not enlarge this review's scope.
A-F1 sustained-writer refresh starvation, A-F4 practical capacity, and remaining
A-F3 backend regression seams are open. Never attribute writer progress solely
to the64-page step size: releasing the live lock before parsing is decisive.

B-F1/B-F2 now have regressions at ca53c1d; the copy-plan branch's author run
passed them and demonstrated both previously surviving mutations. B-F3 honesty
labels, B-F4 legacy source-path errors and B-F5 catalog precision are being
corrected separately. Linux CI and whole-device/power-loss claims remain distinct.
No parent missing-evidence acceptance criterion is closed by this review.

C1-C6 dispositions are proposed in the copy-upgrade branch's governing design:
exact externally retained plan bytes; one active writer per recipe; explicit
plan/identity matching; copy-local recovery bundles separate from logical archive
schemas; exact framed digest and disclosed repeated-audit cost; raw non-service
sources refused. These later refinements were not in this frozen review.
