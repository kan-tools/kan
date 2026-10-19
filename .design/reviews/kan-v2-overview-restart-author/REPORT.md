# Overview restart render correction

The ongoing independent Opus review of 7ab1afa found UPb: service restart can
reuse job1 with an unchanged manifest. A new sample then updated the age label
but left the prior totals/source list because the browser keyed rendering only
by job and manifest. This author correction keys the complete immutable sample.

27 Operations UI tests pass. Reverting the entire production behavior change
restores the old key and fails the new named restart assertion; restored tests
pass again. The test also checks sample-time replacement with identical rows and
that an identical cached sample does not rewrite totals. No Rust/runtime schema
changed. The original reviewer probe/report will be preserved unchanged when the
review finishes; fresh review of this correction remains required.
