# Restoration author qualification — pending

CI run39319089696 at9c50083 passed the all-feature MSRV build, normal suite,
and15 of16 targeted creation/restoration checks. The abrupt-death test failed
because the new CandidateVerified phase was declared but never called. The
corrected callback is in3058330; a forged older-checkpoint retry assertion was
added there too. The failed run excerpt/hash is retained here; the full synthetic
log remains local. This is not a passing crash check or independent acceptance.

The current candidate also includes direct writer-signature/manifest-binding and
budget/alias checks, the separately prepared claim byte decoder, and the parent
Content clock-test correction. Local qualification, semantic controls and fresh
actual Claude Code Opus5.5 review remain required. Shared target ownership is
currently reserved for the independent frozen parent review.


CI39320463688 at6a09d6e passed17 of18 creation/restoration tests, including
all eight abrupt-death phases. The new direct writer/binding test stopped at
its fixture identity assertion: it used scalar3 from the wire-only fixture,
while the replay corpus is signed by public fixture scalar6. The test now loads
scalar6, still asserting the exact expected DID before invoking restoration.
The failed excerpt/hash are retained. No production identity verification or
candidate assertion was relaxed; rerun remains required.


## Combined follow-up qualification at6df024b

The baseline2b911f0 passed both CI runs39322496892/39322490170,
Migration matrix39322497153 and unchanged Perf grid39322496789.
After integrating Content citation sharing and creation review regressions,
author qualification passes103 targeted integrations (including24 physical
creation/restoration tests),3 codec units,9 Content units, strict all-target
v2 Clippy and formatting. The first new real COMMIT-error test reached the
correct Uncertain result but compared the canonical output path to macOS’s
/var alias. Its expected path is now canonicalized; production behavior is
unchanged and the original failure excerpt is retained here.

Six creation controls now fail the intended assertions: removed snapshot BEGIN,
skipped source schema, skipped reservation recheck, attempted flag set after
COMMIT, ignored destination sidecars and ignored proof coordinates. Restored
creation/restoration tests pass. Both codec/clock controls and all eight restoration controls also fail
the intended assertions. All restored suites pass. Three Python performance
failure-retention checks pass. Fresh independent Opus review is required.

A disk guard stopped one attempted validation before any build because free
space dropped below15GiB. Only this task’s disposable release cache (670MiB)
and retired reviewer compiled executables (199MiB) were removed. Review source,
raw logs, failures, working trees and user files remain intact.

The16 new backend controls cover creation6, codec/clock2 and restoration8. They require actual compiled assertion failures, preserve every local log, and restore exact source bytes. The new Content branch separately demonstrated8 controls. No raw reviewer session data is included in this author record.
