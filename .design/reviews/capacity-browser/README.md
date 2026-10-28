# Capacity and inspector browser checks — 2026-10-18

Actual production HTML/CSS/JS served by an owned loopback-only synthetic API
fixture. No real journal, token, provider, user traffic or deployment was used.
This verifies client behavior/layout, not the Rust HTTP boundary (covered by its
separate integration suite). Screenshots contain synthetic values only.

Verified in Codex in-app browser:
- Exhaustion remains prominent alongside current retrying delivery and retained gaps.
- Search by observer and gaps filter operate on the recent sample, visibly bounded.
- Enter opens the metadata dialog; full identifier and observer/cumulative counts
  are present. Copy reports success; Escape restores the corresponding row after
  polling replaces its DOM element. The fallback is the search field if absent.
- Light desktop at 1440px, light tablet at 768px and dark phone at 390px:
  document scroll width equals viewport; the long table scrolls internally.
  Phone dialog is 356px wide inside a 390px viewport.
- Lock closes inspector, empties identifiers/metadata/coverage text, hides data,
  and focuses the token field. Error/warning console logs were empty.
- Viewport override reset; temporary browser tab closed after validation.

The fixture does not replace source/security regression tests or a full
accessibility/contrast audit. Remaining broader frontend workflows stay open.
