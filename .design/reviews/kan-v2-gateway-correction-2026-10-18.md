# Gateway correction: fresh independent review

Author-maintained summary and disposition. Fresh actual `claude-opus-5-5`,
session `78623bb3-41e7-4229-ab89-16da291ec650`.
Range: `e3749b8cf151ed1c7dc5b6f964a814b5a2f9e8b0..4be3f28efdd245e3050fd433e4ec825cdeebaf2d`.
Verdict: **APPROVE WITH FOLLOW-UPS**.

[Exact original report](kan-v2-gateway-correction-2026-10-18.txt), UTF-8 SHA-256
`5056dedfa0f266a24ee0f06322d73ec847adfdcf62e826645b82882ff54e6be6`.
[Public additional probes](kan-v2-gateway-correction-probes.rs) are retained.
The report gives a shortened root path for the probes; their actual retained
source was under the review export's `probes/` directory.

The reviewer independently passed 15 gateway tests, 43 capture tests, the actual
Claude Code 2.1.300 two-hop smoke with Python readback of both spools, Clippy and
formatting. Whole production reversion caused four runtime failures. Thirteen
mutants were killed; four survived. The reviewer removed its target and reported
no remaining processes. No full workspace/capacity or production-provider run
was claimed.

## Author follow-up disposition

- Document connection-churn eviction precisely: around 32 arrivals per handshake
  can evict a legitimate remote collector. In a simulated 50 ms round-trip
  probe, about 1000 new TCP connections/s caused 20/20 requests to fail before
  reaching the provider. Private network/source access controls are required
  until admission fairness is qualified for untrusted exposure.
- Outgoing metadata covers the built request before reqwest defaults, including
  its later default Accept header. Document this boundary rather than presenting
  it as complete wire-header evidence. Provider-key omission is directly tested.
- Mark implementation-agent narrative as author additions; exact reviewer text
  remains separately preserved and hashed.
- Retain the mutual-TLS eight-slot probe and strengthen token-admission, exact
  slot-capacity and body-timeout lower-bound assertions for the four survivors.
- CI exposed that P3's all-retained assertion mixed a frontier invariant with a
  100 ms scheduling/throughput assumption. Its full-retention version now uses
  the normal offline wait policy; production bounded-wait/recovery tests remain
  unchanged, as does the synchronized 80-admission/raw-SQL recovery witness.
  The pre-atomic-preparation control failed at runtime against revised P3 and
  passed after restoration.

These follow-ups change tests/documentation only; production remains the exact
reviewed commit. Generated-admission crash hooks, durable/harness-visible health,
source-event adapters, key custody/erasure, capacity, backups and cutover remain
explicitly open. Request-build failures conservatively retain unknown outcome.

## Final test-only validation

The four original survivors M6, M7, M8 and M17 each failed their named runtime
test after the added assertions; the restored gateway suite passed all 16 tests.
P3 passed, failed with `src/evidence_delivery.rs` restored to pre-atomic commit
6f1011431b594239ca217e3f58941dc898ec1a06, and passed again restored. These controls
ran in a source export with an independent target, which was removed.
[Retained control summary](kan-v2-gateway-final-controls.txt).
