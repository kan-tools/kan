# Streaming audit follow-through: author qualification

A-F1: promote the independent RA3 and RA4 section/count/boundary probes from
Opus session 180a36ed-b817-449d-a1aa-4175bf9f5ce2. Ten integration functions
(eight original plus two promoted) pass. Add two unit probes using test-only
cancellation injection at a charged-byte threshold. They drive the actual
original-object and restoration operations, refuse before the remaining payload
is charged and leave poisoned builders. These have no sleeps, host-speed skip
or production-build hook. The original timing-based independent probe remains
unmodified in the raw review record.

Thirteen compiled controls drawn from that review now fail assertions: the ten
section/count/size edge guards plus unchunked commitment hashing, unchunked
candidate verification and removal of spend-time polling. All restored tests
pass. Strict v2 all-target Clippy and formatting pass; the initial unused import
in the promoted test and its failed Clippy output are preserved.

A-F2: explicitly document the framing-level issuer bound as 1..80 UTF-8 bytes.
The Python framing oracle uses the same local bound, with empty, overlong and
multibyte checks. Full canonical static P-256 DID validation is a stricter member
rule, and the DDL is a physical storage constraint. The original nine member and
four restoration fixtures remain byte-identical and pass.

B-N1: the proposed physical format now explicitly requires UTF-8 on create/open;
UTF-16 must refuse rather than convert. No physical opener/writer exists, so this
is a design pin, not a verified runtime encoding gate. A-F3 remains binding: an
O1 framing digest alone is not proof of verified output.

No non-test Rust runtime change was made. Fresh independent review of these
follow-through changes is required with the logical-member checkpoint. No parent
bundle or frontend acceptance criterion is claimed complete.
