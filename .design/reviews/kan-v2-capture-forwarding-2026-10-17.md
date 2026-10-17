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
The second fresh Opus verdict below covers this correction. Day design validation reports five
requirements/four criteria, with main-checkout path warnings and two withheld
legacy claims. Claim/bridge backfill remains pending; no CIDs or completeness
claims were fabricated. The visible graph reports design → generative-build.

Production gates remain: authenticated collector↔gateway transport, real
harness/provider coverage, key custody/grants/erasure, independent-host restore,
final-delta cutover and capacity qualification. No live user data or provider
credentials were used. HTTPS/TLS, OS proxy settings, physical ENOSPC/power loss
and simultaneous capture/drain lock contention are not qualified by these tests.


## Second independent review

Fresh Claude Code `claude-opus-5-5`, session
`731dc589-c483-41bf-bb46-48825ca42388`, verified by launcher init. Exact range
`c78f6a1878ae681027fed1c1e8fe05eb442899de..c1368928dac1dc433427d3c14f723b8f53cc1d78`.
Final UTF-8 report SHA-256, no added newline:
`1f6a9f377148e9c6488c094a0a5d2775651207a0b084c7ae6ab8962a218e2996`.
Verdict **APPROVE WITH FOLLOW-UPS**, independently closing initial F1–F6/F8.

The reviewer ran all 166 v2 integration tests (26 capture, 140 existing), Clippy,
formatting, citation checks with a disposable Git index, five new probes and all
seven correction mutation controls. It independently reversed the complete
production fix: twelve tests failed, including the three named witnesses and the
encrypted oracle, then all 26 passed after byte-identical restoration. Four of
six new mutants failed; constant wall time and removed reqwest retry policy
survived. Default workspace checks, focused lib units and plain-python oracle
fallback were not rerun locally. Scratch `/tmp/kan-capture-review2-i1Nc` and
`/tmp/kan-capture-review2-scripts` retain probes/logs, targets removed.

The review additionally reproduced a pre-existing deadline bug: with a matching
spool write lock, the CLI delivered `ok`, reported every event unconfirmed, then
exited 1 as outcome-unknown after roughly 32.8 seconds. This conflicts with the
visible-gap continuation promise even though lock-contention performance was
unqualified. The next correction excludes own admission time from the cumulative
I/O budget and retains this actual CLI/SQLite-lock regression. The wall-time test
also now checks that ordinary-host wall samples advance between observations.

Remaining nonblocking coverage/reader limits: HTTP/2 can be enabled transitively,
and the explicit reqwest retry policy lacks a TLS/HTTP2 runtime mutant witness;
HTTPS qualification remains open. Public Header serde decoding is a structure,
not an admission decoder: it does not validate version or distinguish a missing
optional clock field from explicit null. A future production capture reader must
validate magic/version/required fields before interpreting evidence. Synchronous
stderr callbacks can still stall. These are not claims of production readiness.
The new deadline correction requires its own reversion evidence and fresh review.


### Deadline correction evidence before fresh review

All 29 capture tests passed, including an actual matching-spool SQLite write lock
held throughout the CLI invocation. Complete body `ok` now returns success with
all admissions explicitly unconfirmed. Slow output still exhausts a cumulative
I/O budget. A full reversion of all seven production hunks reproduced the CLI
failure; restoration passed. The day helper emitted the commit's trailer from
this named runtime failure. Scratch `kan-capture-budget-revert-0kv8h94m` retains
source/patch; target removed, and final source diff matched the demonstrated patch.
The first in-memory slow-sink witness survived reversion because its Vec output
could complete without yielding; it was not credited in the trailer. That test
now uses a one-byte duplex output to force an asynchronous boundary. Clippy,
formatting and citation checks pass. The third fresh review below covers this correction.


## Third independent review — final implementation

Fresh Claude Code `claude-opus-5-5`, session
`797d4a70-f2e1-4220-aa22-ef553656ce02`, verified from launcher init (the reviewer
could not see the ID). Range
`c1368928dac1dc433427d3c14f723b8f53cc1d78..8c00a28ecd6a8f098d16302ece98306c177f039f`.
Final report UTF-8 SHA-256, no added newline:
`7e1733f48f34fae11968d4aa4fc5f447ff8ef2e2d8241653d394d72f5ab42b23`.
Verdict **APPROVE WITH FOLLOW-UPS**: no correctness, safety or invariant violation
found in the deadline correction. No implementation changes followed this review.

The reviewer independently passed all 29 capture tests, the encrypted oracle,
v2 all-target Clippy, formatting and citation/self-tests. Seven additional probes
verified aggregate slow-provider reads, ample-budget exact output, slow failed
admission, overlapping admission/provider latency, CLI partial output and locked
spool scaling. Both latest author controls failed for the expected runtime
assertions and passed after restoration. Full source reversion was caught by both
the strengthened duplex slow-sink test and the real locked-spool CLI test.
Removing aggregate subtraction was caught; removing the send budget was caught.
Removing the read budget survived the 29 CI tests but was caught by three review
probes. Removing the zero-budget guard was caught only by the reviewer's blocking
output probe. Subtracting elapsed time only on success was behaviorally equivalent
because any failure terminates the attempt.

The review's public probe source is retained verbatim in
`.design/reviews/kan-v2-capture-deadline-probes.rs.txt`. It is an evidence artifact,
not a Cargo test target; promote the response-read timeout witness into CI in the
next capture build point. This preserves it beyond temporary-directory cleanup
without claiming that it currently provides CI regression coverage.

### Concrete continuation priorities

1. Bound capture-admission latency before operational streaming use. With a held
   SQLite write lock, the reviewer measured roughly 5.5 seconds per observation:
   6 observations took 32.8 seconds; 9 took 49.5 seconds. Outcome and visible gaps
   are now correct, but synchronous retry on each chunk is not latency-qualified.
2. Promote the retained provider-body stall/drip probes and zero-budget boundary
   into CI; describe cumulative I/O budget directly in CLI option help.
3. Continue authenticated collector↔gateway transport and the selected real
   harness/provider profile. TLS/H2 retry-policy runtime coverage, production
   capture-header admission decoding and bounded health reporting remain gates.
4. Production custody/grants/erasure, independent-host restore, final-delta cutover
   and capacity qualification remain the parent roadmap's separate requirements.

Synchronous output implementations may overrun a timeout while being polled;
when their completed await exhausts the budget, the following flush is not
attempted and the conservative result is unknown. Only awaited intervals consume
the budget: provider delay overlapping admission is excluded by design. The
budget uses std Instant while tokio schedules timeouts; paused-tokio-clock tests
are not supported by this profile. A host wall-clock step can invalidate the
ordinary-host clock timing test; runtime clocks remain supplementary observations.

Scratch `/tmp/kan-review3-dsIe` retains source/probes/logs; its target and the
control runner target were removed, with no reviewer processes remaining.
Author deadline controls from exact commit 8c00a28 retain logs in
`kan-capture-controls-9lye5nbf` under the host temporary directory, target removed.
Previous implementations c78f6a1 and c136892 passed all CI workflows including
performance. Final implementation 8c00a28 has green CI tests, migration matrix and
performance CI. The final checkpoint changes documentation/evidence artifacts only. Full workspace/default-feature local checks and
real provider calls were not performed by the third reviewer.
