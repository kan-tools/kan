# Claim byte-boundary qualification — in progress

The full unchanged performance grid passed in run39320438739 on source
8cfd267b35174165d0fab2b751d84119092659e0. The downloaded result table and exact
run identity are retained here. It generated all three production grid points
and passed the original scaling gate. This is one successful run, not proof of
the exact cause of the earlier failure39315201306 whose offending bytes were
removed. The new bounded failure collector will preserve synthetic CAR/HEAD
bytes if a future generation fails; it does not restore that old record.

The broad CI integration stage on8cfd267 passed. That CI run39320430131 later
failed at the separate Content test's eight-record rendering unwrap, after its
byte-cutoff assertion passed. The test isolation correctionb6edf2f is included
in the current candidate; it now passes the Content author checks and the combined restoration CI baseline at2b911f0. The later citation changes are a separate candidate.

Three Python failure-retention checks and shell syntax checks pass. The newest
codec fixtures add fixed synthetic hostile bytes, tag/depth/container bounds
and avoid using the affected generic decoder to prepare the future envelope.
Local Rust qualification, compiled fault controls, strict lint and fresh actual
Claude Code Opus5.5 review remain required. No full-frontend or deployment
acceptance is claimed by this record.

Combined restoration source2b911f009c79850053fa875785ed6bfa79fab0d6 also passed CI39322496892 and39322490170, Migration matrix39322497153 and unchanged Perf grid39322496789. These results predate the new citation-sharing and creation-probe follow-ups.
