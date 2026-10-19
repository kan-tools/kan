# Final independent correction review

Actual Claude Code `claude-opus-5-5`, session
`9f7d88b1-03df-462a-b017-d91b22364ff7`, reviewed 8124878 against a95f28f.
Exact returned report: `result.txt`; full report/probes/logs: `evidence/REPORT.txt`.
Verdict: **APPROVE WITH FOLLOW-UPS**. The preceding BLOCK remains retained in
`../kan-v2-library-correction-opus/`; it is not overwritten or relabelled.

All 1170 tracked frozen-export hashes matched after restoration. The reviewer
cleaned/rebuilt kan, reran focused checks, stopped its fixtures and removed its
temporary test sources. The author verified the hashes and removed the completed
review target. All three owned completed review targets from this checkpoint
were removed; their source exports and evidence remain in permanent scratch.

The reviewer independently observed P4 41/41, live socket boundary 25/25 and real
waiting in 35/35 instrumented runs. Production no-wait/1ms-wait mutations failed
P4's named capture assertion 10/10 each. Budgets 5/11/4096 failed the intended live
admission assertions. Budget 3, reader 18, contention 6, CLI 1, Node 41, Python 7,
strict Clippy, fmt and citations passed. The manual loopback fixture was queried
at the HTTP layer and stopped; that is not a browser/download verification.

## Remaining coverage and product work

1. P4 does not assert the first admission's actual spent wait. Deleting the lock
   while retaining the handshake survives; the reviewer's spent>0 probe closes
   this gap. The production wrapper forwards wait values correctly, but an
   optional spy assertion could pin that too. Do not promote window timestamps
   alone to proof that each SQLite acquisition collided.
2. Linux source CI now passes P4 and all newly wired Library checks; repeated
   Linux P4 qualification remains separate from the macOS stress counts above.
3. R11/R13 one-second deadline-tolerance mutations, client scope-entry shape
   checks, and actual browser download delivery remain open.
4. Timing/volume hiding is not implemented. REQ-1 now explicitly covers the JSON
   body. The owner stated in this conversation that rich metadata is the default
   and obfuscation is non-default; the reviewer could not independently trace
   that choice into kan's record, and no claim record was fabricated.
5. Missing-evidence storage/profile/APIs/UI, collection overview, normalized
   conversations, search, annotations/views, analysis and admin remain required.

## Remote validation at the reviewed source commit

For 81248787cfd85acdfe023299dc0073f96cad2e7f, both CI runs 39192553304 and
39192549939 passed; migration matrix 39192553348 passed. The first performance
attempt 39192553317 failed the legacy context/claims ratio: 656.4 ms / 81.9 ms exceeds 8.
The preceding 914e210 has byte-identical src/web/Cargo and passed its performance
run 39191816900. One repeat of 39192553317 was requested, with the original failure
preserved below and the bound unchanged. This is unresolved qualification until
that result is read, not a claim that the initial failure did not happen.

The proposal commit 3d4baebe4b32245a76b807a15840ed250e81d897 passed both CI runs
39192658725 and39192654729, including its independent proposal-fixture oracle.
The final review-record commit is documentation only and will trigger its own CI.
