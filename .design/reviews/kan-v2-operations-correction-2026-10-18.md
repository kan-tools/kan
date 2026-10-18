# Operations correction review — 2026-10-18

Author-maintained disposition. The adjacent `.txt` preserves the exact independent
report, including its qualifications and wording. Reviewed range:
`d55f82128e37b474ce7d22f6c96b04b116711cbb..e95a3ec249180d6764cf3ce00b44aa03d1802cf5`.
Actual initialization identified `claude-opus-5-5`, session
`eb803c24-89fd-422d-b911-8da1364b6f15`. Verdict: **APPROVE WITH FOLLOW-UPS**.
Raw report SHA-256:
`e35581848ed11321673fe8cb35ef9bf35350f38a0d45105956986569f4866616`.

The cold reviewer independently reproduced all five named runtime failures after
reverting the complete correction's production files, plus the Node absent-reporter
failure. Restoring the files passed. Focused operations (11), gateway (17 with one
ignored real harness), operations/admission units (2), surface contract (19), Node
(4), Clippy, format and both supervisor argv checks passed. Six additional hostile
probes exercised full, mismatched, missing and locked journals. No live data was
used. The reviewer removed its own target and stopped its own processes.

The retained mutation log is the precise count: 15 earlier mutants were rerun,
14 killed and the global-cap mutant survived on macOS. Of 13 new correction
mutants, five were killed and **eight** survived (the raw prose says seven, but
lists eight). Reviewer probes then killed the lazy reporter binding and absent-
journal loss-counter mutants. Probe files are retained here as audit evidence;
they are not installed as mandatory regression tests. Timeout/compile failures
were not treated as kills.

The author separately verified corrected-head Linux CI, including the named
`distinct_peer_can_authenticate_while_other_peer_saturates_pending_slots` and
`global_pending_cap_is_32_across_distinct_peers` tests. Both passed. This closes
the platform baseline evidence gap; a Linux run of the global-cap mutant remains
unperformed. The reviewer did not claim CI or browser verification. The author
checked the actual browser with synthetic data: login, filtering, lock, stale and
disconnected state, and 390px layout. Temporary preview processes/tabs were stopped.

All these runs passed at the exact implementation head e95a3ec:
- [Push CI](https://github.com/kan-tools/kan/actions/runs/39146238279)
- [PR CI](https://github.com/kan-tools/kan/actions/runs/39146356470)
- [Migration matrix](https://github.com/kan-tools/kan/actions/runs/39146356505)
- [Performance grid](https://github.com/kan-tools/kan/actions/runs/39146356428)

## Open follow-ups

1. Promote `reporter_at` mismatch, absent/locked-journal recovery and session-loss
   probes into regression tests. Add worker binding/history and worker-failure UI
   assertions. C7 may be near-equivalent because save_worker checks queue binding
   again; do not call its survival a demonstrated wrong write.
2. Make exhausted health capacity explicit and provide an owner-controlled
   rotation/erasure path or a durable counter reserve. The full-journal probe
   recorded only 88 sessions / 1,760 dropped updates despite 6,000 lost updates.
   Warnings remain visible, but the count is a lower bound and persistent fullness
   prevents recovery. No retained records should be silently deleted.
3. Preserve earlier worker history when the journal returns after startup.
   Currently last-ack fields can become null and telemetry_failures can decrease
   (probe: 7 to 3); this is not lifetime-monotone history. Raw archive acknowledgment
   state is unaffected.
4. Distinguish a fresh active reporter from an unclean historical session so the
   healthy UI state is reachable. Current warnings are conservative and noisy.
5. Coalesce cumulative snapshots under bursts. FIFO overflow is counted globally
   where possible, but can lose an attempt's latest counters.
6. Demonstrate the global-cap mutant fails in the Linux fixture.

These are accepted nonblocking follow-ups, not claimed fixes. AC-2 remains partial.
The production gates for bounded capture/startup audit, custody/grants/erasure,
independent-host restore, migration rehearsal and explicit cutover remain open.
This branch adds operational features; it does not declare all v2 work complete.

Legacy kan/day claim and verdict backfill remains pending under the known
partial-trust limitation (two withheld claims). No fabricated CIDs or witness
completion. `day next adversarial-review` names pull-request, with negative
verdicts returning to generative-build. Draft #279 is stacked on #278; neither
merge nor deployment happened.
