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
