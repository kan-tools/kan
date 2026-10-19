# Profile-2 purpose gate

Author verification of production correction 648c8d7, qualified on merge 7e956e8.
The governing decision resolves fresh copy-planner review C-F1: profile 2 is
admitted-only; retained-verified copy history requires the separately planned
profile 3. No production archive was converted, erased or deployed.

62 targeted Rust checks passed: 9 storage follow-ups, 11 lifecycle, 10 proof
storage, 3 plan, 10 source planning and 19 surface checks. Strict all-target v2
Clippy and formatting passed. Reverting the entire production change to the
77eaac7 attested.rs bytes caused each of three named assertions to fail: purpose
validation on an existing handle, a real single-historical-issuer prefix opened
for admission, and standalone verification/rebuild refusal. No compile failure
was counted. Restoring exact production bytes restored all 30 proof storage,
follow-up and lifecycle checks.

The earlier positive plan-less upgrade fixtures now require refusal. Positive
historical-prefix copying, exact proof preservation and later current-issuer
admission must be re-established in profile-3 destination tests, not dropped
from the roadmap. Source records/proofs remain untouched on refusal; failed
rebuild publishes no profile marker. Existing signed admitted-only histories
continue to pass.

Fresh actual Opus 5.5 review of this correction is required. Profile-3 destination
schema, writes, owner artifact CLI and lifecycle support are not implemented by
this gate. No parent missing-evidence acceptance criterion is closed.
