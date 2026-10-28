# Fresh-review A-N1 follow-through

Fifteen physical-reader integration tests, strict all-target v2 Clippy and
formatting pass. The new physical test starts from independently signed accepted
empty-original histories, mutates populated rows to empty TEXT original or empty
BLOB/TEXT candidates, asserts refusal and verifies source bytes are unchanged.
It deliberately does not count a diagnostic change as a semantic guard kill.

The initial wrapper invocation failed before Cargo ran because the shell file
was not executable; invoking it through sh resolved that failed method. No
production reader logic changed. The full fresh review is retained separately.
