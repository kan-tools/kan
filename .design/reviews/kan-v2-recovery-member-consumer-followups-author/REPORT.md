# Member-to-replay follow-through

Author qualification after the b11cbf4 review retained in cd0a9ff. This is not
a new independent verdict. Fresh review will cover this together with replay.

C-F1: restored/R1/output constraints explicitly use member-derived authenticated
lengths, and every restoration exposes recomputed basis even when the key had
no initial loss. Unverified retained membership does not gain source authority.
C-F2/C-F3: the independent Python fixture now includes missing issuer occurrences
in an incomplete copy and the exact MAX_REQUEST acceptance edge. CP01 and CP11
are promoted with their helpers. C-F4: an empty service-request CID refuses
whether or not bytes are present; Rust and the projection oracle agree. Empty
unreferenced originals remain retained corrupt evidence. C-F5: promoted comments
are complete and accurate, and the vacuous immutable-input comparison is removed.

Qualification: 43 affected integration functions (16 member, 23 promoted/extended,
two API-compatible corrections, two framing regressions), strict all-target v2
Clippy and format. The independent fixture regenerates 25 cases (11 positive,
14 hostile). Three compiled controls demonstrate empty-request refusal,
authenticated issuer-length retention in partial copies and the exact request
bound. Restored suites pass. Raw output is retained here.

Whole-production-file reversion removes the single new runtime guard. The named
empty-request regression compiles, fails semantically under reversion, and passes
when restored. The helper's original output/trailer and raw logs are retained.
No physical format, storage writer, observation producer, job, RPC or UI is added;
no parent recovery/frontend acceptance criterion is closed.
