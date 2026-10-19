# Proof lifecycle author qualification

81 Rust checks pass: 9 lifecycle, 9 storage follow-ups (including historical H != C),
10 attested storage, 34 legacy storage, and 19 surface-conformance checks. Strict
all-target v2 Clippy passes. Five compiled mutations fail named assertions; restored
lifecycle/store/surface suites pass. All 21 CI checks passed at f9285c2 before the
additional nonempty source-WAL assertion and overview merge. The merged checkpoint
requires its own CI and fresh actual Claude Code Opus 5.5 review.

Tests preserve exact proof/manifest/receipt bytes, reject missing/corrupt/extra
proofs and payloads, repair disposable lookups, pin a read snapshot before later
admission, preserve retained nonempty WAL frames, refuse wrong owner/profile and
exercise the real CLI. Abrupt process exits cover four initialization and four
rebuild boundaries; these are not physical power-loss simulations. Successful
local backup does not claim independent-host backup or historical completeness.

No production archive, key, service or live migration was used. All parent
missing-evidence criteria remain open. Profile 3 is a design proposal only.
