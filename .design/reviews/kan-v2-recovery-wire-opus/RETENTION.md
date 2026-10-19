# Independent recovery observation checkpoint review

Actual Claude Code `claude-opus-5-5`, cold session
`b934ebe8-1095-4d8a-b70a-603ab61d4ba4`, exit 0. Frozen
`1833ee5c2b78e7b786854dc0f41b07f27b8e4ad9`, all 2702 tracked hashes and exact
Git tree/blob identity verified again after completion. Parent was clean and
unchanged. Raw report, transcript, probes, controls, failed reviewer attempts
and corrected methods are preserved without rewriting.

A/B/C and overall verdict: APPROVE WITH FOLLOW-UPS. Scope A resolves the decoder
strictness findings, with unknown-variant precedence and round-trip regression
follow-ups. Scope B accepts only wire authentication, with distinguishing CID
order fixtures and identity/error-label decisions remaining. Scope C accepts only
draft direction, with ordering vectors, SQL byte bounds and over-limit expected
length refusal needing follow-through. No writer, bundle format or frontend AC
is accepted. Full details and explicit untested limits are in evidence/REPORT.txt.

The reviewer distinguished semantic-acceptance controls from error-label-only
controls, retained one mis-shaped mutation, and explained a surviving redundant
DID re-format check. The next author round must preserve those distinctions.

Author reading note: PA3's cases labelled escaped key/value are plain JSON in the
retained probe source; those labels do not establish additional independent
escape coverage. The author decoder suite already exercises real escaped keys.
Only the actual executed source is evidence. PA1/PA2 are the probes promoted for
the new follow-ups; the raw report is not edited to conceal the PA3 discrepancy.
