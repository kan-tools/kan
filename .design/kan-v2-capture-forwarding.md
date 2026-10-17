# Feature: Bounded capture and single-attempt forwarding

## Summary

Build the first P6 executable witness: a gateway-side opaque HTTP POST forwarder and a reusable collector/gateway observation recorder. Preserve observed body bytes as encrypted spool events, continue forwarding with visible recording gaps, and never turn evidence delivery into inference retry. This serves the user's server-first raw-evidence goal and telos/raw-data-and-projections; the live legacy view still withholds two claims, so it is not a complete telos inventory.

## Requirements

- REQ-1: Capture ordered raw body chunks and lifecycle observations with a fresh attempt identity, explicit observer and actual configured route; encrypt through the existing durable spool boundary. Never claim a collector observation proves gateway/provider behavior.
- REQ-2: Recording failure must not stop an available provider route. Report unconfirmed capture immediately outside response bytes, keep cumulative gap information in subsequent retained events, and distinguish local queue admission from remote acknowledgment.
- REQ-3: Perform one explicit POST only, with redirects, ambient proxies and HTTP retries disabled. Prompt content cannot choose the route. Capture request intent separately from forwarding intent, response status and terminal outcome. Interrupted forwarding has an unknown provider outcome.
- REQ-4: Bound each evidence chunk and request admission, stream arbitrarily long responses without accumulating them, and stop on deadline, provider disconnect or output failure. Cancellation attempts a terminal observation without claiming crash-proof finalization.
- REQ-5: Exercise real HTTP against deterministic fake providers, durable encrypted spool recovery, exhaustion/unavailability, non-2xx, redirects, binary streaming above 10 MiB, cancellation, slow sinks and uncertain outcomes. Retain an independent frame decoder and runtime negative controls.

## Acceptance Criteria

- [x] AC-1: Decrypt queued observations and independently reconstruct byte-identical request/response bodies, ordered offsets, observer, attempt and route; distinct attempts and observers cannot share operation IDs. (REQ-1, REQ-5)
- [x] AC-2: Full or unavailable capture emits a separate health signal and forwards unchanged bytes; resumed recording carries the earlier unconfirmed count. No signal enters the provider body. (REQ-2, REQ-5)
- [x] AC-3: A counting fake provider sees one request, including non-2xx and redirect cases; no redirect target is contacted and draining evidence does not call the provider. Invalid route/request limits fail before forwarding. (REQ-3, REQ-5)
- [x] AC-4: Disconnect, deadline, output failure and dropped future preserve observed prefixes and expose unknown provider outcome. Slow output does not create an unbounded application queue. Only observed body EOF and successful output flush produce completion. (REQ-3, REQ-4, REQ-5)

## Architecture

Add `src/evidence_capture.rs` behind v2-crypto. Its recorder serializes KANC2 frames: five magic bytes, four-byte big-endian JSON-header length, compact typed JSON header, then zero to 64 KiB exact body bytes. Header v2 contains a fresh random 32-byte attempt, collector/gateway observer, monotonically increasing ordinal, nullable self-reported UTC observation microseconds, monotonic elapsed microseconds since recorder creation, cumulative preceding unconfirmed admissions, and a typed event. Operation IDs are the first 16 bytes of domain-separated SHA-256 over attempt, observer and ordinal. Outer signed spool requests bind writer and scope; attempt IDs are observations, not accepted RFC 2 resource URIs. The generic recorder accepts an explicit observer; the HTTP forwarder always records gateway observations and never synthesizes collector ones.

Events are started (POST and normalized configured URL), request chunk (offset), request end (length), forwarding intent, response head (numeric status), response chunk (offset), and terminal (completed or outcome-unknown). Body capture is HTTP entity-body bytes exposed by reqwest, not TLS packets, transfer framing, arbitrary headers, trailers, attachment expansion or hidden harness events. This deliberately narrow adapter sends application/octet-stream and accepts no credentials or caller-controlled HTTP headers. Complete means observed response EOF plus output flush; it does not mean provider success, especially for non-2xx responses.

`EncryptedSpool` delegates to `src/evidence_delivery.rs` queue; no new persistence API or medium bypasses `src/persistence.rs`. Existing typed spool capabilities and `tests/fixtures/read-write-surface.tsv` remain authoritative. A failed enqueue is **unconfirmed**, since failure may follow commit; it is not proof of loss. Health includes observed/queued/unconfirmed event counts and terminal state, never content or route. Emit health on start and after each observation, including gaps and terminal. Subsequent retained events carry cumulative unconfirmed counts; ordinal discontinuities expose missing observations. Restart cannot establish exact coverage for an attempt whose final events were never retained. Drop attempts unknown-outcome finalization; abrupt process termination cannot run it. No new control reserve or persistent health projection is claimed.

The forwarder validates a configured HTTPS URL (or literal loopback HTTP), with no credentials, fragment or query, at most 2048 URL bytes. One immutable route per invocation; no direct fallback. Requests are admitted up to 16 MiB, chunked for capture before forwarding. This is a per-request experimental profile limit, not an archive/lifetime cap. Responses have no total-size cap, with 64-KiB evidence subchunks and awaited output writes; transport-library buffering is additional and not a measured memory budget. reqwest has redirects, retries, automatic decompression and ambient proxies disabled; idle connection pooling is disabled so hyper-util cannot resend on a canceled reused connection. A caller-supplied positive cumulative I/O budget bounds network/output awaits, excluding this attempt's synchronous spool admission and health callbacks. Those can still delay cancellation and are not a hard real-time bound, but recording latency alone must not falsely fail completed inference.

`capture-post` in `src/bin/kan-v2.rs` reads bounded stdin, takes explicit route, spool, existing signing key and public archive recipient, writes body to stdout and JSON health to stderr. Failure to open the spool uses unavailable capture and continues; invalid keys/route/input and a known mismatch between the signer and a readable spool writer fail before network. No archive drain occurs inside forwarding; use the existing exact-byte drain separately. A successful command with gaps remains explicitly degraded in stderr. Non-2xx bodies are delivered, status is in health; transport/output failure returns failure without logging payload-bearing errors. There is no background server left running.

## Open Questions

No new decision blocks this generic witness. The parent real harness/provider profile, production key custody, authenticated collector-to-gateway transport and independent-host backup/cutover gates remain open. This build point does not complete P6 or claim end-to-end harness coverage. Design/review claim backfill and bridge completeness remain pending under the recorded legacy partial-trust problem; no invented claim IDs or witnesses.

## Out of Scope

Remote gateway listener, collector-to-gateway E2E session protocol, arbitrary provider headers/credentials, full harness hooks, request streaming beyond this bounded profile, persistent health/control reservation, automatic archive drain, real provider calls, deployment, main merge, live migration and post-hoc extraction. These separable next P6 steps retain the parent's full capture requirements.


## Review correction

Initial c78f6a1 received fresh Opus 5.5 APPROVE WITH FOLLOW-UPS. The correction
adds observation clocks omitted by the first draft, advancing its experimental
KANC1 format to KANC2/header v2; no claim is made to reconstruct old timing.
It rejects known writer misconfiguration before forwarding, disables pooled
connection reuse, retains the independent encrypted-frame oracle and strengthens
observer, actual-route, proxy and connection-policy witnesses. Wall-clock values
are writer-reported, may move backward and are nullable if unavailable. The CLI
records after bounded stdin admission, not at original harness creation time.
Fresh review of this correction and a full production-fix reversion witness are
required; the initial verdict does not cover these changes.


### Deadline correction after second review

The second review reproduced a matching-spool SQLite write lock: all response
bytes arrived, but time spent in synchronous admission expired the old timeout
and falsely produced outcome-unknown. Replace that timeout with a cumulative
I/O wait budget around send, read, write and flush individually, subtracting only
those awaited intervals. Recording remains before output, outside the budget.
A slow-admission fixture and the actual CLI/write-lock reproduction must finish
with completed outcome and visible gaps; cumulative slow output must still expire.
This corrects REQ-2/AC-2 without claiming bounded wall-clock capture latency.


## Final checkpoint

The three fresh actual Opus 5.5 review rounds and full-reversion witnesses are
recorded in `.design/reviews/kan-v2-capture-forwarding-2026-10-17.md`. Acceptance
is for this synthetic HTTP body-forwarding profile only; full P6 remains open.
All 29 capture tests pass. The next build point must bound admission latency and
promote the retained response-body timeout probes into CI before operational
streaming qualification. No production key, real provider, deployment or live
cutover was selected. Design validation has five requirements/four criteria;
legacy claim/bridge backfill remains pending under the partial-view limitation.
