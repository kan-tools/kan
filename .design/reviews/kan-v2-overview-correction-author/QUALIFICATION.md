# Overview correction qualification

Author verification, not an independent verdict. The corrected source passes
74 Rust checks (22 operations,9 collection,14 overview,10 incorporated independent
probes,19 surface),26 Operations Node checks and strict all-target v2 Clippy.
Thirteen semantic mutants fail named assertions; restored overview/UI suites pass.
The original cold Opus report is preserved unchanged in the sibling overview-opus
directory. Fresh review of this correction round is still required.

The active-source mutant removes the whole memory-copy path and restores a live
read transaction through row parsing; the health-writer regression then fails.
The post-read hash, historical-worker, sealed-sidecar and invalid unique-row
mutants isolate the four previously weak regression targets. The connection-bound
mutant admits16 instead of8 incomplete requests and fails the ninth-slot assertion.
The action race test explicitly asserts dispatch before reading the pending request.
An initial driver run exposed an incidental TypeError in that assertion; the final
run below uses the corrected assertion and all thirteen controls were rerun.

Original real browser coverage remains completed/lock in light,dark,mobile. New
state labels/races were exercised in Node; full authenticated browser state matrix
remains open. Native Mac checked again and remains locked. Library display bytes
are verified but a delivered browser download is not. No production data used.
