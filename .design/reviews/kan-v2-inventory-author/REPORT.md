# Metadata inventory: author qualification

This is author evidence, not independent approval. The governing storage-only
contract is `../../kan-v2-degraded-inventory.md`. Profile-2/3 selection and owner
pins are explicit. Complete metadata/proof audit creates a pinned read-only
inventory without reading payloads. Pages carry exact records/proofs, bounded
samples and opaque selections. Fresh source access rechecks the selected proof,
current bytes and original writer signature. No remote grant is inferred.

Startup/page/source budgets are distinct. The recovery constructor now accepts
an internal pre-read configuration callback so allocation, busy-wait and SQLite
VM cancellation limits apply before the first SQL read. Legacy recovery retains
its existing settings. Page `record_bytes` bounds canonical record/proof bytes,
not a nonexistent wire encoding; the future RPC must also bound encoded overhead.
No persistent surface or mutation API is introduced; existing catalog readers
are extended explicitly. Recipe metadata matching never means capture-ready.

## Executed qualification

127 integration test functions pass across inventory (15), destination (32),
source (10), legacy store (34), lifecycle (11), recovery CLI (6), surface (19).
The production VM callback unit test also passes: 128 functions total, including
existing subprocess-helper functions. The unit test separately demonstrates
actual deadline/cancellation interruption inside an unyielding recursive SQL
query. A three-second watchdog terminates a broken query but is asserted NOT to
be the successful interrupt source. CI runs this test explicitly.

Ten compiled guard removals fail named assertions and the restored inventory
suite passes: indexed oversized lookup; absent VM callback; payload-dependent
startup; omitted payload hash; three purpose guards; absent recipe-metadata
refusal; ignored page count; omitted writer verification. These are selected
controls, not a whole-module-reversion claim. Raw commands/results are retained.
The final changes after controls are SQL substring length parameterization,
comments/formatting and an additional empty/partial positive test; the full
restored targeted run covers that final tree.

Strict v2-crypto all-target Clippy and formatting pass. Storage-only binary check
passes with the three preexisting capture-wait dead-code warnings.

Child-process memory qualification uses 96 MiB corrupt payload/manifest rows,
measures only the fresh reader, and enforces a 64 MiB ceiling. Observed corrected
peaks: object 10,616,832 bytes; manifest 10,010,624 bytes. Maximum valid service
request bytes still return exactly. WAL-backed reads preserve main/WAL bytes.
Other cases include missing/corrupt tip/middle after restart; healthy neighbors;
loss after inventory; same-height valid proof replacement; schema/metadata and
all owner-pin refusals; extra/missing proofs; purpose/issuer mismatch; forged
writer signature under valid issuer metadata; byte/row/work limits; wrong cursor
context; empty admitted and genuinely incomplete retained snapshots.

## Failed attempts retained

01-first.txt: two test compile errors (Vec<i32> vs byte vector; u64 SQL value).
02-second.txt: four synthetic damage mutations were blocked by SQLite foreign
keys. The fixtures now explicitly disable those constraints only for deliberate
corruption. The same run exposed a real implementation problem: indexed lookup
of the WITHOUT ROWID object key materialized a 96 MiB row before SQLite's value
limit, peaking at 111,312,896 bytes. This was not a skipped or raised threshold.
The corrected `NOT INDEXED` / unary-CID scan passes; its indexed-lookup mutant
reproduces the named memory failure. None of the fixture failures count as a
regression control.

## Limits and next acceptance

Every startup audits the full metadata history. Every payload sample scans the
object table to avoid oversized-key materialization. VM cancellation bounds
checked SQL execution, not arbitrary filesystem stalls or OS scheduling. This is
not a large-archive latency/throughput qualification. Metadata trust is issuer
attestation, not renewed writer authentication; source access supplies the latter.
SQLite structural damage may still refuse an entire operation. No forensic repair,
anti-equivocation, rollback fence, remote authorization or plaintext projection
is claimed. No parent frontend AC is closed.

The new bundle codec documents are proposals only; there is no bundle writer.
RPC/proof-aware delivery, recovery jobs, Library missing-evidence rendering and
full conversation/search/analysis/admin remain required. All fixtures are synthetic;
no production keys/archives, install, activation, deployment, server or main merge.
Shared Cargo cache, four jobs, one heavy job at a time; no Mathlib or new toolchain.
