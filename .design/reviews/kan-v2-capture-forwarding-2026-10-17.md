# Capture forwarding review evidence — 2026-10-17

## Initial independent review

Cold Claude Code runtime `claude-opus-5-5`, session
`b08ad49a-cb6e-4f60-a043-fe502b6978f2` (verified from launcher init; the reviewer
could not see its session ID). Reviewed range:
`2531f915cbaf977bb0509c84e41c9d52a763870a..c78f6a1878ae681027fed1c1e8fe05eb442899de`.
Final report UTF-8 bytes, no added newline, SHA-256:
`07db562140bc318cc47465bb680c9a793b138b06bc45685c0887898fc01f215e`.
Verdict **APPROVE WITH FOLLOW-UPS**. This verdict covers the initial KANC1
implementation, not the subsequent correction.

The reviewer independently ran 14 capture tests, 34 affected delivery/spool/surface
tests, one spool unit, v2 all-target Clippy and formatting. Citation self-tests
passed in its source export; the full citation check required Git and passed from
the author checkout. Full workspace/default-feature local builds were not run.
Eleven independent probes exercised the CLI, encrypted spool decryption through
the OpenSSL-backed HPKE oracle, route/HTTP behavior and interruption. The oracle
reconstructed a 200,003-byte request and 300,007-byte response from 16 encrypted
frames, pinned route/status/operation IDs, and preserved a body labeled gzip
without automatic decompression. Six retained mutation controls failed at runtime
and passed after restoration. Reviewer mutants also killed method changes,
missing cumulative gaps, removed Drop finalization, unbounded stdout shutdown
and recording after output release.

| Finding | Initial evidence | Correction disposition |
|---|---|---|
| F1 writer mismatch | CLI forwarded once, queued no records, exposed gaps | Reject known mismatch against readable spool before network; regression retained |
| F2 observer header | Hard-coded gateway header survived original suite | Collector and gateway field assertions plus targeted mutant |
| F3 actual route | Forged route survived original suite, independent oracle rejected it | Retain encrypted oracle with actual route pin and mutant |
| F4 proxy bypass | Removing no_proxy survived original suite, reviewer proxy probe rejected it | Retain proxy probe and mutant |
| F5 hidden pre-wire resend | Hyper-util defaults to retry of canceled reused connections; not reproduced as resend | Disable idle connection pooling and test two fresh connections against a keep-alive server |
| F6 capture time | First draft omitted parent capture-time requirement | KANC2 adds self-reported nullable UTC and monotonic elapsed microseconds; clock tests and mutants |
| F7 blocked stderr | Synchronous callback may exceed deadline; declared | Remains explicit experimental limitation |
| F8 oracle coverage | Author decoder previously saw plaintext memory frames only | Retain encrypted CLI-spool oracle in CI |

The review source export was `/tmp/kan-capture-review-ULK7`; its build target was
removed and public source/probes/22 logs retained. No review-owned processes
remained. The initial source/author checkout stayed unchanged. The author also
ran six controls from committed source `c78f6a1`; scratch source/logs remain at
`kan-capture-controls-brypfb3f` under the host temporary directory, target removed.

## Correction and limits

The new frame profile is explicitly KANC2/header v2. Earlier draft KANC1 bytes
remain raw evidence; no retrospective timing is invented. Clock values describe
recorder observations, not harness creation or globally trusted time. UTC can
move backward or be unavailable; elapsed time is local to an attempt. Library
recorders remain caller-responsible for truthful event semantics.

The independent probes are retained in `tests/evidence_capture_adversarial.rs`;
diagnostic-only checks were replaced with assertions. The independent encrypted
fixture oracle is `scripts/verify_encrypted_capture.py`, using the existing
OpenSSL-backed HPKE schedule and RFC vectors. It is a synthetic test utility,
not a production archive reader or an independent outer-signature verifier.
`SignedRequest::decode` authenticates the outer request before the test exports
ciphertexts. The oracle deliberately does not certify receipt/history placement.

The full production correction was reverted in an isolated source export with
all new tests retained, using the day revert-demo helper (feature-selection
wrapper only). Writer mismatch, observer/clocks and nonpooled route tests each
failed at runtime under complete reversion and passed after restoration. All
one CLI hunk and eight recorder/transport hunks were reversed; the demonstrated
patch was byte-compared with the final production diff. Scratch
`kan-capture-fix-revert-qcsroan5` retains source/patch with its target removed.
A second fresh Opus verdict is still required before closure. Day design validation reports five
requirements/four criteria, with main-checkout path warnings and two withheld
legacy claims. Claim/bridge backfill remains pending; no CIDs or completeness
claims were fabricated. The visible graph reports design → generative-build.

Production gates remain: authenticated collector↔gateway transport, real
harness/provider coverage, key custody/grants/erasure, independent-host restore,
final-delta cutover and capacity qualification. No live user data or provider
credentials were used. HTTPS/TLS, OS proxy settings, physical ENOSPC/power loss
and simultaneous capture/drain lock contention are not qualified by these tests.
