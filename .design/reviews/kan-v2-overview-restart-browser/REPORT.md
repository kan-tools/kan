# Restart browser follow-up

2026-10-19. Author verification, not an independent review.

An isolated loopback dashboard rendered one distinct attempt, then rendered two
attempts / three observed after a 28 ms server restart and refresh. Both server
samples used job 1 and the same collection manifest hash. The tab was not
reloaded. `fixture.jsonl` retains the exact samples and executable/asset hashes;
`restarted.png` shows the real browser result.

The served app.js bytes were compared exactly to commit 7126848. A frozen copy
of the existing shared-target binary was used throughout this successful run,
while the independent source-planner reviewer continued using the Cargo cache.
The binary came from that review build environment; this is verification of the
served production JavaScript behavior, not qualification of a release executable
or a claim that every Rust byte matches an unmodified checkout. No request
interception, page-state injection or synthetic DOM was used. The fixture
mutates only its own synthetic health database while the server is stopped.

Browser polling was not instrumented to establish whether it missed every
intermediate unavailable response. Deterministic RP regression tests establish
the missed-null collision; this run separately verifies visible totals against
a real restarting server. Library download delivery remains unverified.

After verification, Lock removed the data and focused the empty token field.
Theme remained System, the owned tab was closed, the fixture server stopped,
and its temporary data/executable directory was removed. No production evidence,
keys or user browser tabs were touched.
