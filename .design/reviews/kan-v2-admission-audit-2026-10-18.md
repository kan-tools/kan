# Admission/capacity correction review disposition

Actual fresh Claude Code `claude-opus-5-5`, session
41f831f9-6c46-4a7f-a455-e889e9d3b216. Verdict APPROVE WITH FOLLOW-UPS.
Baseline 771341e; production/test sources reviewed as a885565 are identical to
published eb41111. Exact report SHA-256: 5a5b0bf8fd992b665d361f3f34ce5853f95a6ddb2120bc0215704f113cfc6280.

Independent restored checks: 13 operations units, 22 operations integrations,
9 collection tests, 19 surface tests, Node20, Python7, strict default/v2 lint and
format. Five whole-production reversion tests failed named assertions and passed
before/after; no compilation failure or runner timeout is counted as a kill.
The reviewer also retained explicit mutation survivors and independent probes.

Follow-ups remain visible: production wrapper bypass mutants can escape helper
unit coverage; sticky first-reason guard needs a committed focused test; modal
focus assertion needs activeElement, and threshold/alias checks need boundary
cases. These are evidence gaps, not claims that all review findings are closed.
The review is approval with follow-ups, not full acceptance of AC-7.

Compatibility decision: older v2 session-limited journals whose reserve was
already released are writable for attempt summaries under this correction.
This intentionally keeps recording available; reserve remains visibly zero and
is not silently recreated. Existing sticky exhaustion and lower-bound coverage
remain visible, and owner rotation is still the recovery path. An older binary
would continue refusing those attempts; never mix versions against one journal.

Freshness decision: retain the conservative five-second display threshold for
now. A slow worker call may legitimately exceed it (the worker permits longer
I/O); the UI then reports unknown/stale, never healthy from an old sample. A
separate worker/capture freshness presentation remains a frontend refinement.

Evidence hygiene: GitHub refused a 127MiB byte-comparison assertion dump. The
unpublished commit was amended only to retain a lossless gzip plus digest/summary.
The author also updated those evidence files inside the running review export;
the reviewer correctly disclosed that this broke full export isolation. All
126 production-source hashes were unchanged and the gzip hash matches the raw
staged evidence. Future review exports must remain immutable until review exit.
The parent commit/trailer was not rewritten after publication. Raw original
logs remain in the permanent author export; reviewer logs are retained here.

The reviewer process exited normally and its owned build target was removed.
No live installation, raw archive change, main merge, or full frontend completion
is claimed. Whole-device ENOSPC, physical power loss, malicious same-owner path
races, multiprocess lock races and full-workspace execution remain unproven.
