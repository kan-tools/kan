# Decoder correction qualification

Addresses F-D1 and the two explicit format decisions in the fresh independent
7b44429 review, session f4340dd8-27d1-4af5-9a11-982f98a676d0, preserved unchanged
in ../kan-v2-reconstruction-opus/evidence/REPORT.txt.

Recognized forwarding-intent refuses extra fields rather than relying on the
Serde unit-variant visitor. Every one of the ten current event forms is tested
against extra scalar/object/null fields. Recognized headers require an explicit
clock field; null remains accepted, absence refuses. Unknown KANC-family inputs
are size-checked before classification; oversized non-capture input stays opaque
without parsing. These decisions are recorded in the governing design.

15 decoder functions pass, strict v2 all-target Clippy and format pass. The whole
production correction reversion makes both new strictness regressions fail;
baseline/restoration pass. Three compiled selected controls (extra-field check,
required clock field and total-family size bound) each fail their named assertion,
then the restored 15-function suite passes. The size-bound control had survived
the original suite; its new regression now observes the chosen precedence.
No production change followed these checks. No storage, API or browser consumer
is introduced. Full reconstruction acceptance remains open.

This is author evidence. Fresh actual Opus 5.5 correction review is required.
