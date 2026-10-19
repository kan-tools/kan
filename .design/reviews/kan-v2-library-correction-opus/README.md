# Fresh correction review — BLOCK retained

Actual Claude Code `claude-opus-5-5`, session
`35a1ffe4-685b-4c96-91e5-eddf10a9fa9c`, independently reviewed a95f28f against
e71cdf8. Exact returned text is `result.txt`; the full raw report is
`evidence/REPORT.txt` (extension changed only to keep shorthand citations out
of Markdown link lint). All 1118 tracked export hashes matched after restoration;
the completed target was removed. Raw probes, failures and scripts remain.

Verdict **BLOCK**, limited to the synthetic P4 contention helper: the zero-wait
background writer got no lock window in 6/35 runs. All five boundary pins, the
retry-styling fix, wording update and generated reversion passed independently.
The review also found missing CI coverage and an untested lower socket bound.
This verdict is not relabelled as approval because author fixes now exist.

Author response: coordinate the first writer window at the first admission,
record its timestamps inside the active capture span, keep subsequent windows
periodic, preserve both Sink methods and spent-wait values, clean up before
propagating a failed capture, and remove the false ~9% duty claim. A 20-run author
stress check passes with all observations queued. The live socket test now also
requires all twelve earlier sockets to remain open. CI wiring was corrected in
f367399. REQ-1 explicitly names the response-body boundary and disclaims timing
hiding; the owner's earlier default-rich-metadata/non-default-obfuscation choice
is recorded, not treated as an implemented obfuscation feature. Fresh review of
these corrections remains required. Production Rust logic is unchanged.
