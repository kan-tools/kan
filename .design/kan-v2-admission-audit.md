# Feature: Close reliability correction evidence and timeout follow-ups

## Summary
Address R1–R5 of the fresh 68acb0e review without expanding raw-capture authority.
This follows the capacity checkpoint and serves `telos/raw-data-and-projections`.
The parent review is APPROVE WITH FOLLOW-UPS, not a hidden BLOCK.

## Requirements
- REQ-1: Deterministically exercise real shard WouldBlock handling followed by release and successful admission, without relying on scheduler luck. Preserve finite nonblocking production work.
- REQ-2: Demonstrate the finite CAS reservation retry budget, spurious failures, capacity refusal and no leaked count; disclose exhaustion as a possible telemetry loss, not an uncounted guarantee.
- REQ-3: Bound post-kill pipe cleanup even if a descendant detaches while retaining stdout/stderr. Terminate the owned process group; do not claim control over deliberately detached processes.
- REQ-4: Test runner failures under an independent watchdog with cleanup of every owned probe. Distinguish named assertions, errors, skips and timeouts; retain real bundled-day reversion evidence for the production cleanup correction.
- REQ-6: Refuse unsupported WAL-mode journal headers before SQLite can create undeclared sidecars or adoption can publish unreadable sealed history. Preserve source bytes and directory entries.
- REQ-5: Preserve the approved storage/UI behavior and align diagnostic language with telemetry-loss units. Fresh Opus 5.5 review is required before calling this checkpoint reviewed.

- REQ-7: Session exhaustion must preserve writable attempt recording and its control reserve, with a sticky coverage warning. Later attempt/page exhaustion must seal recording, release reserve, and supersede that warning. Accept older v2 session markers without rewriting them.
- REQ-8: Repeated unchanged refusals must not cause durable writes. Exercise committed-only freshness, real worker SQLite-full handling, active-generation ordering and UI focus/notice/future-clock behavior.

## Acceptance Criteria
- [ ] AC-1: Mutating actual WouldBlock admission to immediate refusal fails the named test at its assertion; restoration passes. No thread timing or generous workload threshold substitutes for this evidence. (REQ-1)
- [ ] AC-2: CAS retry budget reduced to one fails a deterministic spurious-failure test; 64 failed attempts stop without count change; capacity 256 prevents reservation. (REQ-2)
- [ ] AC-3: Normal descendants stop writing on timeout. A deliberately detached pipe holder cannot hang runner cleanup; the test cleans its own detached probe. Whole-production reversion produces a named watchdog assertion failure and restored code passes. (REQ-3, REQ-4)
- [ ] AC-4: Python assertion-result parsing supports exact unittest output while errors/skips/mismatches fail closed. Rust/Node aliases retain prior semantics; all focused suites/lint/format and fresh review are recorded. (REQ-4, REQ-5)

- [ ] AC-5: Both v1 and v2 WAL-header fixtures are refused before adoption publication or sidecar creation; whole-production reversion fails the named refusal assertion and restored code passes. (REQ-6)

- [ ] AC-6: Session-limited reporters start, writable attempts persist, and the reserve survives; later attempt exhaustion promotes the reason and frees reserve. Twenty sealed refusals leave journal bytes unchanged. (REQ-7, REQ-8)
- [ ] AC-7: Failed transactions never advance freshness; worker SQLite-full failures set a sticky marker and permit a smaller recovery checkpoint. Valid-shaped older active IDs are refused, unchanged notices are not rewritten, and modal focus survives polling. (REQ-8)

## Architecture
Production admission calls one generic helper with a no-op contention observer.
Its deterministic test holds the actual shard mutex and releases it after the
third real WouldBlock. The test is inside the production branch's implementation,
not a separate simulation of mutex behavior. Reservation similarly accepts a
compare operation; production uses the atomic's weak compare-exchange, while the
test injects known spurious failures before a real strong atomic reservation.
Neither hook adds storage, blocking locks, sleeps or unbounded callback work.

The runner sends SIGKILL to its own process group, gives pipe draining one second,
then closes its pipe handles and bounds reaping the direct child. Deliberately
detached descendants remain outside that group. Tests own the exact probe PIDs
and clean them in finally blocks under an independent thread watchdog. A mutant
must fail promptly, not leave a hanging test mistaken for a semantic kill.

The mixed-language adapter adds one explicit Python alias and parses real
unittest verbose output. A named FAIL is an assertion; ERROR is not accepted as
semantic evidence. New unit-helper symbols cannot compile under whole Rust
reversion, so their Rust mutation evidence is reported separately. Integration tests using
existing APIs join the Python test in the whole-production reversion run.

## Open Questions
None for this correction. The separate frontend reader deployment question
remains unrelated and unresolved.

## Out of Scope
Universal termination of deliberately detached subprocesses, zero-loss callback
claims under arbitrary scheduling, new capture storage or frontend permissions,
and completion claims for the remaining collection overview/full frontend.

## Additional adoption finding
An author CLI probe of 67e3414 switched a synthetic journal to WAL mode and
closed it cleanly. Adoption reported success, but ops-history then refused the
sealed generation; SQLite had created WAL/SHM sidecars not owned by this profile.
The correction validates the main-file read/write format bytes before SQLite
access. No conversion or silent repair is performed. This finding applies even
if the initial independent capacity review does not reproduce it, and requires
the correction's own review before the stack can be considered ready.

The header check follows SQLite's published [database file format](https://www.sqlite.org/fileformat.html): offsets 18 and 19 identify rollback versus WAL read/write format. Both are required to be 1 in this profile; no unknown-format repair is attempted.

## Author validation checkpoint
13 operations units, 22 operations integrations, 9 collection tests, 19 surface
checks, 20 Node UI/theme tests, 7 Python runner tests and strict all-target v2
Clippy pass. The surface scanner initially treated a test name containing its
reserved facade token as an alias; the test was renamed, without weakening the
scanner. Both real WouldBlock refusal and single-try CAS mutants fail named
assertions and restored units pass.

The bundled day engine reverted all three changed production files together.
Four named tests failed assertions under reversion and passed before/after:
bounded detached-pipe cleanup, WAL refusal, session-limit recording continuity,
and byte-stable sealed refusals. Raw logs and the generated trailer are retained
in `.design/reviews/kan-v2-admission-audit-reversion/`; helper-only unit symbols
are deliberately excluded from that reversion claim. No compile failure or
runner timeout is counted as a semantic kill. Fresh independent review pending.

Whole-device ENOSPC, actual power loss, malicious same-owner path swapping and
universal scheduling/losslessness remain unproven. No live service is changed.
