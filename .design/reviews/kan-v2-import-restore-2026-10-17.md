# Offline import restore review — 2026-10-17

## Initial independent review

Fresh actual Claude Code `claude-opus-5-5`, launcher-confirmed session
`0920b4a3-f348-48a2-988d-d544917d4836`, reviewed
`9ae0622fd8791007981e1958abe564a43f12aadf..c07cacc8abea3621119100f9bdc382ddcfc9ee6b`.
Final report SHA-256 (UTF-8 with no added newline):
`feb72f41f2badf354aec1ecb2e47852d1638aeb468882b83a025f40d1e5b0165`.
Verdict: **APPROVE WITH FOLLOW-UPS**, no correctness blocker. No other agents,
provider calls, external posts or live day/kan mutations were used.

The reviewer independently passed all 129 targeted integration tests and five
focused units, both v2 and default-feature all-target Clippy, formatting, and
11 additional probes. It did not run default-feature `cargo test --workspace`
locally because disk space was close to the machine's 15-GiB floor; GitHub CI
runs that broader suite. The review used a separate source export, cloned build
dependencies and a rebuilt package. All 443 committed files matched HEAD after
mutations, and the permanent checkout remained unchanged.

The independent probes include a separate Python archive oracle: P-256 request
signature verification, RFC 9180 HPKE opening via OpenSSL-backed cryptography,
three-part inventory reconstruction and exact selected-byte comparison. The
oracle rejected a flipped restored byte. Additional probes cover an authorized
second writer reusing the same operation IDs, coherent receipt/manifest rewrites,
noncanonical pinned plans, malformed headers, sequence holes and record-limit
boundaries, destination edge cases, filesystem case/normalization aliases and an
actual importer exact-chunk-multiple file. This is synthetic test evidence, not a
production backup drill or all-history/unsigned-receipt attestation.

The review reproduced the six author mutation kills and caught removed completion
and file/directory-prefix checks. Its new probes killed bypassed retained-request
verification, removed receipt-issuer validation, removed canonical-plan validation
and removed frame-coordinate checks. Wrong persistence capability, extra writes
and missing annotations failed surface checks; raw mkdir was rejected by Clippy,
not the text-only surface test. Removing directory sync survived process-level
tests; physical power-loss durability remains untested and is not claimed.

Scratch `/tmp/kan-restore-review-iPvtSt` retains public source, probes and logs
(about 6.4 MiB); its generated target was removed. Reviewer processes were stopped.
Existing kan/day MCP processes predated the review and were left alone. Raw session
logs remain private; hidden reasoning is not published. Day design/review claim
backfill remains pending due to the legacy partial-trust limitation, not because
there are no recorded teloi.

## Follow-up disposition

1. **Retained-request verification coverage:** the original restore tests did not
   catch bypassing `verify_retained_request`. The review's coherent receipt-issuer
   rewrite probe did. Retain this probe in the repository and require its mutation
   to fail at runtime.
2. **Canonical plan coverage:** the original suite did not catch removal of the
   canonical serialization check. Retain the externally pinned noncanonical-plan
   probe and its mutation control.
3. **Multipart coordinates coverage:** the original suite used one-part inventory.
   Retain the three-part positive/oracle case and coordinate/body tampering cases,
   plus the coordinate-check mutation. These close coverage gaps without changing
   production behavior.
4. **Remaining nonblocking ergonomics:** filesystem aliases fail closed with a
   generic I/O error and partial plaintext output; errors lack operation context;
   the library-only observation hook could be hidden from generated API docs.
   These do not weaken selected-byte verification. Better diagnostics can follow.
5. **Operational gates unchanged:** object lookup may produce quadratic I/O;
   maximum inventory/chunk allocations, power loss, independent-host backup,
   key custody/erasure, final delta and cutover still need qualification.

The coverage follow-up retains all 11 reviewer probes as
`tests/evidence_restore_adversarial.rs` and their synthetic archive oracle as
`scripts/verify_restored_archive.py`. The oracle is explicitly test-only: it does
not authenticate commits/receipts or bound arbitrary inputs. The same pinned
cryptography interpreter convention used by existing crypto tests is used here.
The isolated mutation script gains the three missing controls. A fresh focused
review must validate this test-only addition; the initial verdict applies to the
initial implementation head, not unreviewed later edits.

Author validation of the coverage addition: 9 original restore tests and 11
retained adversarial probes pass; all-target v2 Clippy and formatting pass. In a
new isolated export, removing retained-request verification, canonical-plan
validation and frame-coordinate checks each caused its named test to fail at
runtime and pass after restoration. The export target was removed. The earlier
six controls remain independently demonstrated on unchanged production source.
No production fix was made, so there is no production-fix reversion trailer to
claim; the evidence here is the newly enforced runtime mutant rejection.
