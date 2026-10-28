# Member review correction qualification

Author-run evidence after the independent review of 5e54513, preserved at
8ddefda. This is not an independent verdict or full bundle acceptance.

A-F1: a matching content address with a contradictory authenticated length
refuses as invalid metadata. Service-request references cannot exceed
MAX_REQUEST. A-F2: retain incomplete-copy membership verbatim in M1, expose
UnverifiedMembership on its membership-only losses, and withhold authenticated
expected length. Such a claim cannot classify valid bytes as corrupt or constrain
a future restoration candidate. A-F3: distinct service occurrences cannot share
one request CID, even when all bytes are missing. General framing stays unchanged.

Seventeen deterministic reviewer probes are promoted; RP02/03/14 now pin the
corrected contracts, and loss comparisons include Basis. Three author extensions
pin authenticated orphan-length contradictions, exact membership-byte charging
and corrupt orphan preservation. Timing probes remain in the original report;
no deterministic unit is presented as a wall-clock latency test. B-F1's Rust
multibyte edge and B-F3's stale provenance header are corrected.

Final qualification (`13`–`17`): 55 integration functions (16 member, 20 promoted
and extended probes, two API-compatible correction probes, eight commitment,
two framing regressions, seven observation), two polling units, strict all-target
v2 Clippy and formatting. Independent Python regeneration checks 22 member cases
(nine positive, thirteen hostile) and unchanged 9 M1/O1 + 4 R1 framing vectors.
The Python projection oracle itself refuses the four new contradiction cases;
it remains explicitly narrower than a full second member validator.

All eight selected compiled controls fail semantic assertions (`controls/`):
authenticated length, partial length, partial basis, shared request CID, request
bound, membership byte accounting, orphan hash and UTF-8 framing length. They
produce incorrect acceptance or an incorrect loss/authority projection, not
merely another refusal label. Restoring exact source passes all 40 affected
integration functions. These controls are reproducible via
`scripts/recovery_member_followup_controls.py` with the shared target/four-job
environment.

The complete production-file reversion removes all eight changed member hunks,
including the new API fields, while the API-compatible correction tests still
compile. Both named tests fail on the old behaviour and pass when restored.
`11-whole-reversion.txt` and `whole-reversion-logs/` retain the helper's raw output
and generated Demonstrated-by trailer. No tests were weakened to obtain it.

Preserved failed attempt: `04-clippy.txt` caught a single-match lint in the
promoted reviewer source. The source was changed to equivalent if-let syntax;
`15-final-clippy.txt` passes. Earlier logs and original reviewer files remain
unaltered. Tests used synthetic fixtures/public scalar keys only. No persistent
archive, credentials, deployment or main merge was involved.

Fresh actual Opus 5.5 correction review remains required before replay consumes
this component. The consumer must derive loss basis from the immutable member
and must not use unauthenticated membership lengths as candidate constraints.
