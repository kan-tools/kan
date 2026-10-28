# Capacity review disposition

Fresh actual Claude Code claude-opus-5-5, session
6217df36-4733-4653-9cbb-ce749369f18f, reviewed 67e3414 against a04f288.
Verdict APPROVE WITH FOLLOW-UPS. Exact report SHA-256:
d171685bf831a2c6d7e3a05e6c955a4e0aaf2707fa8e7d95608f548872f24df0.

Independent build, 9 units, operations 20/20, collection 8/8, surface 19/19,
delivery 5/5, gateway 17 passed/1 ignored, admission 1/1, Node 16/16, strict
lint/default+v2 and format passed. Nineteen Rust and seven UI mutants were
restored. Surviving variants and unrun power-loss/multiprocess/browser limits are
preserved in the exact report; they are not silently promoted to proof.

The reviewer reproduced session-exhaustion whole-production reversion. It caught
its own stale restored build caused by preserved mtimes and rebuilt before
claiming restoration. Tests using source exports need fresh package compilation.

Owner engineering decision: session capacity will remain a sticky coverage
warning but will no longer seal otherwise writable attempt recording. Actual
attempt/page exhaustion still stops attempt writes until rotation. The child
correction will add capacity warnings for session and attempt limits, idempotent
exhaustion persistence, missing timestamp/manifest tests and the separately
reproduced WAL-header adoption refusal. These changes require fresh review.

Adoption intentionally preserves the original without a mutation/tombstone;
reconfiguration and stopping old clients remain explicit owner obligations.
Owner-directory path swap races and syscall-level power-loss qualification remain
limits. No safe shutdown/installation of live processes is implied by this review.
The owned reviewer target was removed after the CLI exited; logs remain here.
