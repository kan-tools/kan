# Library resilience browser checks

2026-10-18. Real production assets and real signed/encrypted synthetic service
fixtures, in the Codex in-app browser. No production keys, archive or provider.

- Partial catalog exposes two healthy scopes while a third fixture forges its
  signature. Failed identity is absent from the picker. Source bytes remain readable.
- Partial coverage survives inspection and pagination to occurrences 21–25.
- Desktop 1440×1000 light/system and phone 390×844 dark: scroll width equals client
  width, captured script/image stay text, no img/iframe/object/video nodes.
- Restoring the fixture and clicking Retry sources shows complete coverage and
  three scopes. This is a real service retry, not mocked browser fetch state.
- Lock leaves zero rows/scopes/capability items, empty source/coverage and token
  focus. Temporary theme override reset to System, viewport reset and tab closed.
- Browser download event again timed out after 15 seconds; no console warnings
  or errors. No delivered file was exposed for byte comparison. Available browser
  inventory only offered IAB; native Mac surfaces were locked. File delivery is
  still unverified and must not be inferred from Blob/API byte equality.
- No complete browser external-request trace is available. No such trace claimed.

Synthetic fixture server was stopped after checks. Screenshots show actual
partial coverage in the desktop and mobile layouts.
