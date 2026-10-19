# Proposal preparation, not an implementation review

The independent Python/OpenSSL checker passes two exact deterministic P-256
low-S vectors and twenty hostile cases. Public scalar 1 is deliberately a test
identity. It reads only checked-in synthetic fixture data and invokes no Rust,
service, archive, production key or provider. Normal --check never rewrites data.

The statement-CID predecessor and snapshot commitment was added during the design
pass because manifest-only coordinates do not bind exact receipt/purpose/time.
This is a proposed protocol extension, not an existing compatibility promise.
The checker is deliberately a fixture oracle pinned to its public test identity,
not a general-purpose authorization implementation. No Rust parity, transaction
atomicity, proof-bearing SQLite profile, unavailable-row API or UI exists yet.
A fresh protocol review and the full implementation/negative-control sequence
remain required. No acceptance criterion is marked complete.

Read-only day design validation from main passes 8 requirements/6 criteria,
section/mapping/placeholder checks. Five branch-only path warnings correspond to
files present here; two log claims remain withheld. No kan/day writes were made.

The design branch runs the proposal oracle in CI after the already-pinned
cryptography install. This checks fixture stability, not runtime support.
