# Cumulative health review — 2026-10-18

Author-maintained disposition. The adjacent `.txt` is the exact final independent
report; `kan-v2-coalescing-full-review.md` is the reviewer's separately written
full report. Production range: `96c67f7..cde8b0f594b54b7ccf9a7efb766e66350d1efa76`.
The isolated export's synthetic baseline commit b452aec represents 96c67f7; it is
not the product branch commit. Claude Code initialized as `claude-opus-5-5`, fresh
session `9a7a41b7-deae-49fa-8456-6a95b1182d0a`. The reviewer exited successfully.
Verdict: **APPROVE WITH FOLLOW-UPS**. Final report SHA-256:
`06baa563aecf5d9f0d8350fbf731cd79d75c2277f5b20303f461c20893ba0332`.

Independent verification passed v2 all-target build, operations 18 integration +
3 unit tests, capture 18/adversarial 13/deadlines 6/contention 6, gateway 17 plus
one ignored, surface 19, admission 1, Node 11, both Clippy modes and format. The
reviewer manually reverted production: the burst test failed on 257 versus 1002
observations, persisted terminal regression was accepted, and the future-clock
Node test failed. Restoration passed. The badge-only mutation failed independently.
All nine coalescing mutants were caught at least once, but M3 (uncounted contention)
was caught only probabilistically in 6/8 runs, not deterministically. The parent's
three surviving frontier mutations and reporter-clock mutation were independently
killed by the promoted tests. No SQLite lock panic appeared in 15 operations-suite
runs. A parent-written journal passed backward-compatibility probes.

## Follow-up disposition

1. **Counted contention loss — open, next correction priority.** Synthetic
   synchronized callers can lose terminal health summaries even with a healthy
   journal (up to 78/80 with two tight callers). All observed losses were counted,
   and raw evidence/spool capture is unaffected; this is still a material quality
   limitation. Explore shorter ownership/critical sections or bounded retry while
   preserving the explicit nonblocking callback contract. Do not silently replace
   `try_lock` with an indefinitely blocking mutex. Qualify against actual gateway
   concurrency before claiming normal-load reliability.
2. **Deterministic contention accounting — open.** Add an explicit memory-lock
   barrier and require a lost terminal observation to produce the exact loss
   increment. An unrelated scheduling-sensitive test is insufficient evidence.
3. **Burst barrier identity — open.** Bind the barrier to the first record write;
   a delayed test thread can currently meet it through the 500 ms session write.
   The current reversion failure was an actual counter mismatch, but that does not
   prove every future run exercises the intended in-flight revision.
4. **Unsampled session wording — open.** Separate known stale observations from
   sessions outside the bounded sample, or use “no recent sampled heartbeat”.
5. **Loss-counter units — open.** Make the contract and UI explicit about lost
   cumulative summaries versus individual callback updates. Do not imply a count
   of lost raw messages.
6. **Reversion replay — open.** The retained adapter correctly parsed actual Node
   results in baseline/reverted/restored phases, independently reproduced by the
   reviewer. The bundled tool alone cannot replay `node::future_clock_badge` in
   `--verify` mode; reproducibility requires the adapter. A native mixed Rust/Node
   replay path remains follow-up tooling work.

The author verified all CI jobs passed for cde8b0f in
[run 39158573019](https://github.com/kan-tools/kan/actions/runs/39158573019).
The reviewer did not run Linux CI, full workspace tests, browser checks or live
provider tests; none are attributed to it. The parent theme/browser verification
remains in its own report. Current draft #282 is stacked on #281.

Capacity/counter certainty, owner-triggered preserved-history rotation, stable
source identity, reader API and the full frontend workflow matrix remain required.
This checkpoint does not close their acceptance criteria. Legacy kan/day claim
backfill remains pending under the known partial-trust limitation; no CID or witness
is fabricated. The owned review target was removed after process exit; source and
raw logs/probes remain in the permanent worktree's ignored review export. No live
installation, data migration, main merge or production credential use occurred.
