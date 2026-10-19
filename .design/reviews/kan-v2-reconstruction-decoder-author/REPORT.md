# Pure capture-frame decoder qualification

`evidence_reconstruction::decode` interprets a complete bounded decrypted KANC2
frame, with no storage, network, signature or grant API. Recognized input has the
current Header/Event types, borrowed body bytes and exact exclusive byte ranges.
Malformed input, unsupported variants and ordinary opaque input stay distinct.
Every JSON map rejects duplicate keys before variant detection. No wire serializer
is provided; later APIs must encode u64 coordinates without JavaScript rounding.

12 decoder tests pass. They cover exact binary/multibyte/escaped byte spans,
u64 boundaries, strict recognized shapes, unknown variants, recursive/escaped
duplicate keys, length/allocation limits, truncated and mutated input, event/body
constraints and all current production Recorder event forms. The unchanged
capture integration target's 18 functions pass with localhost access (30 distinct
functions total). The first sandboxed attempt passed three capture functions and
failed fifteen at denied localhost binds; it did not execute the decoder target.
That raw failure is retained, not counted as a regression or control.

Six compiled controls fail their named assertions: duplicate keys, non-chunk body,
body limit, unknown version, source span and rounded coordinate. Restored decoder
suite passes. One additional multibyte/escaped-header regression was added after
that control run; final decoder suite (12), strict all-target v2 Clippy and fmt
pass. The control run's restored suite was 11 tests. No production source changed
between the controls and final run.

Actual day schema check passes (8 requirements / 8 criteria), with the preserved
primary-checkout path and withheld-claim warnings described by the earlier design
validation record. Git-first recording remains; no fabricated log claims or
witnesses. Fresh actual Opus 5.5 review remains pending.

This is only the frame decoder checkpoint. Occurrence grouping/assembly, provider
adapters, exact normalized-item spans, authorized APIs, session browser and all
other full-frontend integrations remain required. No parent AC is closed.
