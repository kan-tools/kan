# Library browser verification — 2026-10-18

The images show the production Library assets served by
`tests/evidence_reader.rs::library_browser_fixture` against a real synthetic
signed/encrypted service. They do not show the user's archive or a deployment.

- `desktop-light.jpg`: 1440 × 1000, inventory and source inspector.
- `tablet-light.jpg`: 768 × 1024, responsive layout.
- `phone-dark.jpg`: 390 × 844, dark theme and narrow layout.

Observed: pagination 1–20 → 21–25 → 1–20, two-scope switching, exact binary hex,
source/provenance controls, text-only script/image canaries, no active attachment
elements and no console errors. DOM viewport and scroll widths matched at all
three widths. Lock cleared rows, source, provenance and scopes and focused the
token input. Theme was reset to System and temporary viewport overrides removed.

Limits: these screenshots do not establish complete browser accessibility or
coverage of all empty/denied/stale/failure states; those have API/Node tests.
External network tracing was unavailable. A real download was attempted before
and after the attached-anchor/delayed-URL-release correction; both in-app browser
waitForEvent(download) calls timed out after 15 seconds without console errors.
No delivered local file was verified. API byte ranges and Blob construction are
verified separately and must not be substituted for browser file delivery.
All temporary browser tabs and fixture servers were closed after testing.
