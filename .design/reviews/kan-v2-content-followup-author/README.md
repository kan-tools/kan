# Content review corrections — author qualification in progress

This branch begins at bb1e0ab. The baseline's actual Opus review is still finishing; final verdict and raw evidence will be incorporated from its original branch. Prepared fixes respond to the review's concrete reproduced findings, without treating a draft report as acceptance.

Source correspondence is validated once per immutable borrowed stream; per-item mapping retains exact duplicate and boundary citations with bounded work. Content presentation limits and busy workers have fixed HTTP outcomes separate from verification failures. The UI exposes observer length claims and unexpected starts and re-enables Interpret when Source supersedes work. Provider version 3 flags malformed error/tool-result shapes and preserves resolving pointers. A private no-op-in-production observation seam allows deterministic real-Reader cancellation/permit tests; it is not an HTTP or environment control.

The staged frontend has 47 passing Node tests, including nine promoted independent review probes. Seven semantic mutations fail assertions; exact restored app/test SHA256 values and raw outputs are retained here. These are staged-file results, not yet a whole-branch acceptance claim. Rust changes have been formatted but not compiled or tested. Remote CI and fresh independent review remain pending. The machine has less than 15GiB free and the original review owns the shared local build target; no parallel heavy local build is started.

After copying the staged UI into this branch, the same 47 Node checks pass (`ui-applied.txt`). Production app/test bytes still match the staged-control identity. Rust compilation, semantic controls and independent review are not yet reported successful.

Initial remote run 39313570931 did not start any jobs: the newly broadened, unquoted Content test filter ended in a YAML colon. The filter now uses `evidence_content` to select both ordinary and worker unit modules without that YAML syntax error. This was a failed validation method, not a test result.


## Current author qualification

The corrected candidate passes 103 integration checks, seven Content units (including the two real-Reader worker/HTTP tests), three Library admission units, 47 UI checks and strict all-target v2 Clippy/formatting. The final named 130-message/500-delta fixture also passes after adding the full streamed message lifecycle and event names. These are author results, not independent acceptance. Raw synthetic build/test outputs are retained in `runs/`; no reviewer session stream is included.

Failed methods are retained: attempt 1 encoded the large test payload in one capture frame, exceeding the existing 64KiB capture-body format boundary; it consequently produced no recognized stream. Fixtures now use real chunk boundaries. The serialized-output test separately proves all 121 normalized items are processed before refusal, preventing another limit from masquerading as coverage of the wired output cap. Attempt 2 passed runtime tests but strict lint found the fault-injection field unused in the unit-test instance of a shared fixture. A field-local test-only annotation documents its integration-only use; strict lint and UI checks then pass. Version 3 also prevents citations/unknown delta variants from promoting an empty JSON key into typed text (A-I1), while retaining that field in the raw parsed event.

Semantic controls on this final source and a fresh cold review remain pending.

The final candidate additionally exercises the acquisition cap and overall deadline through a private acquisition observation seam. A 10-record real encrypted fixture stops after its ninth acquired record crosses8MiB and never fetches the tenth; an eight-record selection succeeds. The deadline test first completes real source verification, then pauses acquisition work and advances virtual time, so no per-RPC timeout can masquerade as the overall deadline. Current qualification:103 integrations,9 Content units,3 Library units,47 Node checks, strict all-target v2 Clippy/fmt. The initial15-control pass caught every selected mutation and restored suites passed; its20MiB serialized-response failure payload remains local and will be represented by an explicitly bounded excerpt. The final17-control pass is pending.

## Final source checkpoint bb661b4

All17 compiled assertion-based mutation controls demonstrated the intended
failures; restored suites passed. Exact source hashes, driver and logs are under
`controls-final/`. Retained browser DOM/screenshots are under`browser-final/`;
actual browser download delivery remains unverified. Fresh correction review
is still required.
