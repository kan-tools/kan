# Recipient encryption review disposition — 2026-10-17

Fresh actual Claude Code `claude-opus-5-5`, session `31231aa3-8d16-4b14-8a22-e4aa356b6936`, reviewed `39a0214a908c469763c78180e31f70f6e7ffc7f7..807054e494d8a52a51bf471f6750289fe2ca9e79`. Final report SHA-256 `bf1c4abbc2cff6d1bda9b09057934d7c238caa1bb1a4084741e12a3a5eddf349`; verdict **APPROVE WITH FOLLOW-UPS**, with a medium defect required before caller wiring. Private day/teloi were unavailable, not absent. Raw report is retained privately, separately from this author disposition; hidden reasoning is not published.

Independent evidence: full 89-test targeted suite, build, feature all-target Clippy, formatting. Scratch probes verified independent Python sender to Rust receiver at five sizes through the maximum; 199 receiver/mutation cases; 14 low-order encodings; maximum service append; 1,000 distinct encapsulations; independent vector derivation. A registry-shell permission refusal prevented direct verification of the full upstream-vector-file hash; read access still confirmed the selected vectors. That hash claim is not upgraded to reviewer-verified.

F1: HPKE accepted noncanonical recipient public encodings that could encrypt but not decrypt with the owner's re-derived canonical key. The author now rejects all encodings at or above 2^255-19, including the high bit, before sealing. Regression cases include an equivalent high-bit key and all nineteen canonical-width values above the field bound. A runtime negative control removes this guard and must fail the regression.

F2/F3: RFC 4 now describes the experimental crypto profile and remaining custody/operational exclusions. Permanent tests now exercise an independent public-key-only Python sender and maximum-size bidirectional interoperability, plus header-field tampering through the independent receiver. The backing store remains unable to validate encryption; the unsalted recipient public-key hash exposes cross-scope linkage under the personal metadata profile.

Fresh correction review remains required for these material changes. No live keys or data were installed or imported.

## Fresh correction review

Actual `claude-opus-5-5`, session `655733a4-6c91-428d-ac67-cf95e994c3bc`, range `807054e494d8a52a51bf471f6750289fe2ca9e79..5f7c9377ecd2eda105c24572847a0a482896dfbf`. Final report SHA-256 `a2fd7850772c5c738d71b84fae8bd9a96aaa737fa98dda36fe74cedc44f782ac`; verdict **APPROVE**. Independently ran all six crypto tests, feature all-target Clippy and formatting. Verified the little-endian field bound against ten edge values and 200,000 random values; independently reproduced the old alias failure and checked the Python sender rejects noncanonical recipients. No command failed or was denied. This correction review is targeted evidence, not a new full-suite run.

Author execution also confirmed three runtime negative controls (recipient canonicality, scope binding and header authentication), followed by all six restored tests passing. The full integrated child-spool snapshot later passed 98 targeted tests after inactive generated artifacts were removed to recover disk space. The earlier ENOSPC failure remains recorded rather than relabeled as a pass. These results establish an experimental explicit-key encryption primitive, not production custody, capture, migration or operational readiness.
