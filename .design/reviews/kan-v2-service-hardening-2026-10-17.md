# Service admission hardening review — 2026-10-17

## Initial fresh review

Actual Claude Code `claude-opus-5-5`, launcher-observed session
`0fa064d9-52f0-4507-b9d6-5f8aea07bb8b`, reviewed
`da36f203ea9e2e5fe7c37d359192db624b188727..0ab98e31189cf6b991b2e76a7d1ce559f58acba6`.
Final report SHA-256 (UTF-8, no added newline):
`d68506928575b84198e0afa61cb45812d0144cf5fb404320b54ee24339873c0e`.
Verdict **APPROVE WITH FOLLOW-UPS**, no blocker. The model reported that its own
environment did not expose its session ID; the ID above comes from the launcher's
initialization record. This was an independent cold session, not a fork.

The reviewer independently reproduced all 121 targeted checks, all-target
v2-crypto Clippy and formatting. Two concurrent instances admitted 120 records
with 100 transient conflicts resolved by exact-byte retries, no unavailable
responses, and identical original receipts. Five raw-writer races never admitted
or certified a prefix covering the invalid record. The same probes against the
base reproduced the original defect. The three author mutation controls failed
at runtime and passed after restoration. Additional controls killed skipped
per-dispatch audit, premature publication of an unchecked frontier, and a fence
that compared only sequence rather than sequence plus CID.

An initial full reversion with both integration targets failed to compile because
the store tests use the new API; this was not counted as a killed mutant. The
reviewer then ran the service target alone against both reverted production
files, reproducing the hidden-suffix runtime failure. The long retry loop in one
deliberately broken variant finished on its own; no external interruption or
source coaching occurred. All mutations ran in a synthetic scratch source copy,
not the permanent review checkout. The reviewer removed its generated 1.3-GB
scratch target and kept reports/drivers/fixtures. The source checkout stayed clean.

## Findings and correction disposition

1. **Low-medium, repeated audit cost:** a failure at the end of 400 valid records
   revalidated that prefix on every subsequent request (about one second in the
   reviewer's debug build). The correction retains each fully verified contiguous
   prefix in memory. An invalid record never enters that prefix; every later
   authorized request still fails on it. A page that fails structural decoding
   before yielding records may be reread, bounded by the 128-record page limit.
   No durable cache or availability certificate is introduced.
2. **Low, missing read/pin witnesses:** Page and Read pin bypasses, contiguity and
   prior-pin check removals survived the original tests. A private execution
   phase now lets unit tests schedule a raw append exactly after audit, before
   execution. Page/Read cannot cross that pin and Snapshot remains at the pin.
   Owner-SQL synthetic damage tests cover sequence holes, prior-pin replacement,
   retreat and same-height changes. These are defense-in-depth checks, not a
   claim to detect arbitrary owner rewrites. An additional unit witness checks
   that exact retries retain audit progress. The same-height explicit check is
   partly redundant with the prior-pin recheck; survival of that single redundant
   mutant is not evidence that the invariant is untested.
3. **Low, Snapshot narrowing:** removing the old selected-tip read allowed a
   Snapshot response after owner deletion of its object, although Read/startup
   failed. The correction restores the tip read against the audited snapshot;
   the missing-object regression now requires Snapshot to fail corrupt too.
4. **Informational, conflict ambiguity:** the existing wire code still covers
   both a transient audit-frontier race and permanent operation/writer-frontier
   conflicts. Delivery preserves the original head and stops. Exact retries are
   safe, but automatic progress is not promised. Finer error vocabulary and
   client retry policy remain a subsequent protocol/operations decision.

The correction requires a new fresh review; the initial verdict does not approve
its new source bytes. Raw reports remain private and hidden reasoning is not
published. Live day/telos reads remain incomplete, not absent; claim backfill is
pending. This document records the explicit user-authorized v2 design review.

Author correction evidence: 125 targeted checks pass (120 integration, five unit),
as do all-target v2-crypto Clippy, formatting and diff checks. Seven executed
runtime controls now cover each corrected cache/read guard; the cache control
reinstates the full previous all-or-nothing cache policy. The day revert-demo
algorithm reverted the correction's production source while retaining the named
`evidence_service::missing_committed_object_is_corrupt_on_read_and_startup`
integration test: runtime failure, byte-exact restoration, then pass. This is the
commit's demonstrated witness for the restored Snapshot behavior; it is separate
from the cache-policy control. Fresh review is still required.

## Fresh correction review

Actual Claude Code `claude-opus-5-5`, launcher-observed session
`2f0af6a7-cf72-45ec-82f9-09c5d5718373`, independently reviewed
`0ab98e31189cf6b991b2e76a7d1ce559f58acba6..61ca52065d2b276a3c113c3debedbbe8195047a2`.
Final report SHA-256 (UTF-8, no added newline):
`49234169aa6ea2733101d412ea85ad9a704620fa99fc6e70927242b7157a4e9c`.
Verdict **APPROVE WITH FOLLOW-UPS**, no blocker. Findings 1–3 above are independently
closed. This was another fresh session, not a continuation of the first reviewer.

The reviewer reproduced all 125 checks, both v2-crypto and default workspace
all-target Clippy, formatting and diff checks. All seven correction controls
failed at runtime with baseline/restored passes. Five additional reviewer
mutations across seven runs also failed at runtime: unchecked frontier advance,
swallowed record failure, ignored audit error, Snapshot from the live tip, and
skipped tip authentication. Full service-source reversion kept the named
integration test and failed at its new Snapshot assertion; source restoration was
byte-exact. No compilation failure, timeout or zero-test run was credited as a
runtime kill in this round.

Three bounded concurrent raw-writer probes appended 260 records with an invalid
signature at sequence 201. The frontier remained below that record; after the
writer finished, repeated authorized requests still returned corrupt and retained
audit progress through exactly 200. No successful response covered sequence 201
or later. These busy-writer probes produced only conflicts for fenced appends,
so they demonstrate refusal, not successful interleaved admission; the existing
multi-instance tests and first review provide the latter evidence. The reviewer
also inspected the private post-audit method's sole production caller and
confirmed signature, routing, grants, expiry and successful audit precede it.

Remaining nonblocking findings:

- **Low, test tooling:** `scripts/service_audit_negative_controls.py:46` writes
  mutations into its invoking idle checkout and restores in `finally`. SIGKILL
  or power loss can bypass restoration, and its baseline/restoration commands
  lack timeouts. Both independent reviews ran mutations in separate scratch
  exports. Follow up by making the script itself own an isolated scratch copy
  and target; do not treat it as safe for an active/shared author checkout.
- **Informational, owner rewrite window:** replacing the pinned CID with SQL
  between audit and execution can return invalid for that request, then corrupt
  on the next normal dispatch. Arbitrary owner rewrites remain outside this
  append-coordination profile.
- **Informational, liveness:** a continuously advancing raw writer can repeatedly
  win the frontier race. Clients retain exact bytes and stop on conflict; automatic
  progress/fairness is not promised by this slice.

The permanent checkout stayed clean throughout review. The reviewer removed its
1.3-GB generated scratch target and retained reports/probes/source fixtures under
`/tmp/kan-svc-hardening-review-61ca520/`. No reviewer-started servers remain.
Documentation-only finalization does not change the reviewed source, tests,
scripts or workflow bytes. Production restore/capture/custody/erasure and capacity
qualification remain separate gates; this verdict is not live-cutover approval.
