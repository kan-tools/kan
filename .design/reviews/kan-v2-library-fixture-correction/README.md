# Author fixture correction after the BLOCK

The first background writer window is established by a rendezvous from the first
capture Sink call, after spool open. Its measured start/end must fall within the
active capture interval. Subsequent attempts remain periodic; lock acquisition
contention skips a window. The wrapper delegates both production Sink methods,
including the caller wait budget and returned spent-wait duration. We still assert
at least one window and every observed event queued. This establishes a brief
writer window during active capture; it does not promise a specific duty cycle
or prove that every SQLite acquisition collided.

Reader18 (+1 ignored fixture), contention6 and twenty repeated P4 runs pass.
The final socket-boundary assertion also passes; strict v2 all-target Clippy and
fmt passed before that final assertion wording. A fresh reviewer will check the
complete final diff, including lower-bound socket mutations. These are test-only
Rust changes; no fabricated whole-production reversion trailer is attached to
them. The actual production retry-style fix retains its earlier generated trailer
and two independent assertion-based replays.
