# Authenticated overview browser follow-up

Author-run real in-app browser against the production Operations service and
embedded web assets compiled from the merged 7ab1afa source. This adds browser
evidence after the independent review export was frozen; it is not a reviewer
verdict. Only synthetic fixtures were used.

Observed through actual UI actions and authenticated requests:

- Load last sample on a new service: `Overview unavailable`, no fabricated totals.
- Build overview: `Overview building`; then completed with one distinct attempt,
  three observations, two locally queued, one unconfirmed, one retained gap, one
  reporter, eight dropped telemetry observations, zero unclosed sessions.
- Completed cache: `Cached sample` and increasing age; selected source frontier
  remained the original three generations.
- Synthetic membership advanced by cloning an active journal and publishing a
  valid four-generation fixture manifest: current health named the new generation;
  the old sample displayed `Superseded by active generation ... Build a new overview`.
  This fixture transition is not qualification of a human admin rotation control.
- A wrong sealed SHA-256: `Overview failed · source invalid or unavailable`, with
  the original totals and `Prior sample retained; this refresh has not replaced it`.
- 104 generations with repeated identities (77,529,088 SQLite bytes): Build then
  Cancel produced `cancelling` then `cancelled`, retaining the original sample.
- The same bounded fixture with 100,000 distinct sealed identities: actual build
  produced `capacity-limited · memory bound reached`, retaining the original
  complete totals instead of publishing partial counts.
- Light and dark desktop screenshots inspected. Dark mobile at390×844: long state
  labels wrap, controls remain visible; body scrollWidth390 equals innerWidth390.
- Lock clears all health/overview metadata, restores the token field and focus.

The cancellation/capacity fixtures were constructed by explicit synthetic SQLite
row and manifest changes, not by modifying server responses or executing page code.
No production collection was used. State coverage now includes unavailable,building,
completed,failed,cancelling,cancelled,capacity-limited and client-derived superseded.
The real CLI contract remains separately covered by integration tests; it does not
expose asynchronous job-state controls. Full frontend/admin matrix remains separate.

Cleanup: System theme restored, viewport override reset, owned browser tab13 closed.
Exact fixture PID37754 received SIGINT; ignored test exited0 and TempDir cleanup
removed the synthetic journals. Existing user Studio tab4 was untouched.
Native Mac remains locked; Library download delivery remains unverified.
