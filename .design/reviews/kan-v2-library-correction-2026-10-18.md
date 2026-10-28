# Library correction review disposition

Fresh actual Claude Code `claude-opus-5-5`, session
efa9d730-4e15-4369-b0cd-ca2869a01b29, returned **APPROVE WITH FOLLOW-UPS** for
df74506 through 61e2487, 22facfa and a8cbf21. The exact report is retained beside
this file; its SHA-256 is
`c480d4f38d4352d047d3a9b4df771c54db0820d4e2325203ad270603b617d680`.
The initialization identity, probes, raw mutation output and all three replayed
reversion logs are in `kan-v2-library-correction-probes/`.

The reviewer independently ran reader15 (+1 ignored), CLI1, surface19, Node34,
strict v2 all-target Clippy and formatting. All three correction trailers replayed
as DEMONSTRATED with compiled, named assertion failures and passing restoration.
After all mutations the reviewer cleaned its own kan build and reran the tests.
Its 278 tracked-file pre/post hashes match. After exit, the author separately
checked all 276 paths in the export manifest against both their original hashes
and actual a8cbf21 Git objects; all matched. The export contains real objects for
all reviewed commits. No active export was edited by the author.

The reviewer correctly flags the stale `Parent: 833bef3` in the supplied
review-context document. It is historical context, not the baseline for this
review; the actual diff and commit objects used are df74506..a8cbf21. No kan/day
writes or witness claims were made. The known withheld-claim/worktree-discovery
limitations still require later backfill from these Git records.

## Open findings

- Missing/corrupt objects still fail an entire page; AC-3 is unmet. Startup and
  tip verification also depend on retained objects. A later availability design
  must preserve authenticated admission rather than simply bypass those checks.
- The catalog is all-or-error. A forged or unreachable configured scope causes
  503 instead of hiding only that scope. This is an honest failure, but still
  prevents browsing valid neighbours. Per-scope error rows remain required.
- The new queue is bounded in code, but the committed fifth-connection test does
  not prove all bounds: Q01–Q06 survive. Independent timing probes observed the
  fifth request served at 4.9 seconds, immediate refusal of the thirteenth socket,
  and idle sockets closed in bounded groups. Deterministic admission/queue tests
  should pin four execution permits, twelve accepted sockets and both deadlines.
- API-side capability-list assertions are missing (A01/A02); malformed and
  duplicate capability responses lack client negative tests (K13/K14).
- UI tests still lack 401, Previous-during-loading, Unicode isolate, LRM/RLM and
  ALM cases. In the verbatim report, “A 401 mid-session keeps the view open”
  describes surviving mutant K03, not current production: `rpc` explicitly
  classifies both 401 and 403 as access denial. Preserve that distinction.
- M14 (local cursor check) and N03 (second signature-error mapping) were judged
  equivalent survivors because another validation layer still rejects them.
  Their survival is not evidence that the corresponding invalid input succeeds.
- Remote-call/whole-connection timeout composition, constant-time token
  comparison, formatting inside the select macro, external-request tracing and
  full browser-state coverage remain follow-ups. Signed denial can still hide a
  scope, including a request rejected for clock skew; the integrity correction
  only prevents signature verification failures being mistaken for that denial.

Browser file delivery remains unverified. Browser screenshots are author
evidence; this reviewer used no browser. AC-1/2/4/5/6 remain partial, and the full
human frontend is not complete. No production keys, archive reads, provider
traffic, installation, cutover or main merge occurred.

The reviewer exited 0 and reported no remaining processes/listeners. Only its
completed build caches are removed; the frozen source, reports and probe logs
remain in the permanent worktree.
