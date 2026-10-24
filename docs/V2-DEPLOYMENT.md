# Managed v2 launches and restore activation

Use one independently retained, owner-only deployment manifest for each host's
archive services, sender processes and Library workspace. Add `--deployment FILE`
to their normal `kan-v2` command. The manifest supplies mandatory erasure custody
and annotation source guards; individual command-line arguments cannot replace
them with a different file. An unregistered data path refuses startup.

The manifest configures this host's managed scope. It is not service discovery,
an assertion that every running process uses it, or evidence about unregistered
copies on another host. Commands launched without it remain explicit unmanaged
or individually enrolled operations. Configure the actual service manager to use
the manifest on every restart, including after a restore.

## Configuration

The JSON file and referenced configuration files must be owner-only regular files,
at most 64 KiB each. Paths must be absolute and contain no `.` or `..` components.
A manifest contains 1–256 entries with distinct data paths. Keep it and its custody
configurations independent of archive/workspace backups.

```json
{
  "version": 1,
  "archives": [
    {"root": "/srv/kan/archive", "history": "/etc/kan/capture-custody.json"},
    {"root": "/srv/kan/replica", "history": "/etc/kan/capture-custody.json"},
    {"root": "/srv/kan/annotations", "history": "/etc/kan/annotation-custody.json"}
  ],
  "workspaces": [
    {"database": "/srv/kan/reader.sqlite", "guard": "/etc/kan/reader-guard.json"}
  ],
  "spools": [
    {"database": "/srv/kan/capture-queue.sqlite", "kind": "raw",
     "history": "/etc/kan/capture-custody.json"},
    {"database": "/srv/kan/annotation-queue.sqlite", "kind": "annotation",
     "history": "/etc/kan/annotation-custody.json",
     "publication_guard": "/etc/kan/reader-guard.json"}
  ]
}
```

`history` names a pinned independent erasure Access configuration described in
[V2-LIBRARY.md](V2-LIBRARY.md#independent-erasure-custody-experimental-storage-integration).
Every use of a given archive binding in this manifest must name identical custody,
including owner and minimum checkpoint. A sender destination must be an admitted
archive. The same custody file can serve multiple replicas.

`guard` names the annotation source-guard configuration from
[V2-DELIVERY.md](V2-DELIVERY.md#annotation-source-guards): `database`, `signing_key`,
`recipient_key` and `sources`. Its database must match its workspace entry; its
source bindings must be unique and independently pinned. An annotation sender
must use its registered workspace's guard. Raw capture/import senders cannot
attach an annotation guard. The manifest contains references, not secret key bytes.

## Launch

For bounded archive services, first initialize the archive and control indexes as
described below, then retain `--indexed` in the service manager configuration.
Keep the usual binding, issuer signing key, access policy and listen options.
Enrollment supplies `--erasure-history` to both service roles:

```sh
kan-v2 --deployment /etc/kan/deployment.json serve-admitted /srv/kan/archive --indexed \
  --binding /etc/kan/capture-binding.json --signing-key /etc/kan/issuer.key \
  --access-policy /etc/kan/capture-policy.json

kan-v2 --deployment /etc/kan/deployment.json serve-proof /srv/kan/archive --indexed \
  --binding /etc/kan/capture-binding.json --signing-key /etc/kan/issuer.key \
  --access-policy /etc/kan/capture-policy.json

kan-v2 --deployment /etc/kan/deployment.json spool-watch /srv/kan/annotation-queue.sqlite \
  --journal /srv/kan/annotation-health.sqlite --endpoint http://127.0.0.1:7282/v1/rpc
```

`serve-proof` accepts either the enrolled archive directory or its exact
`archive.sqlite` path; both select the same independently configured custody.
Other files under that directory are not enrolled implicitly. Unmanaged proof
launches also retain the existing explicit-database form.

`spool-head` and `spool-drain` inherit the same destination and source guards.
`spool-status` inherits destination custody but emits only queue metadata.
`queue-input` is available only for registered raw queues. Existing setup,
collector/gateway capture and offline maintenance commands retain their own
explicit configuration; this launch option currently refuses unsupported command
roles instead of silently ignoring the manifest. Capture producers do not forward
queued evidence to archive storage: their registered sender performs that delivery.

The Library retains its reader sources, keys, token and optional outbox/analysis/
owner settings. Its `--workspace` and key paths must match the registered guard.
Do not also supply `--workspace-erasure-history`: enrollment supplies the complete
source set. Every configured reader source must use the proof protocol and occur
in that set. A configured annotation outbox must be a registered annotation queue
with the same workspace guard; its destination custody is supplied automatically.

```sh
kan-v2 --deployment /etc/kan/deployment.json library \
  --config /etc/kan/reader.json --signing-key /etc/kan/reader.key \
  --workspace /srv/kan/reader.sqlite --workspace-key /etc/kan/reader-workspace.key \
  --token-file /etc/kan/library.token --annotation-outbox /etc/kan/outbox.json \
  --owner-config /etc/kan/owner.json
```

The same enrollment applies to one-shot `--request` and stdio `--mcp` modes.
Signing credentials, content grants, owner authorization and custody remain
separate; adding a path to the manifest grants no new remote permission.

## Owner inventory and restoration

A managed Library or `owner` command validates each capture-erasure target before
opening its owner journal. Every configured erasure archive/replica, queue and
workspace must match the registered custody/credentials. Conversely, targets must
include registered replicas and queues for their bindings, dependent workspaces,
and publication destinations whose annotation source guards depend on the erased
sources. An offline replica can remain absent; it remains a configured pending
cleanup destination and is never created by inventory validation.

Before activating a restored host:

1. Restore independently current custody and its configuration first. Restoring
   old custody and its old checkpoint together does not prove freshness.
2. Restore archive/workspace/queue copies to their registered paths while services
   are stopped. Preserve the originals and backup provenance.
3. Reconcile archives and queues against independent custody using the explicit
   maintenance commands. Resume owner erasure jobs for dependent workspaces,
   publication copies and queued cancellation. See the Library erasure runbook.
4. Start roles with the manifest. A stale archive, removed workspace dependency,
   missing binding or missing custody refuses exposure/publication. Guarded
   annotation head export refuses before writing request bytes.
5. Inspect per-destination cleanup and operation health. Startup enrollment is not
   a claim that all cleanup completed or that every backup was purged.

This implementation does not start/stop external services, edit a service manager,
activate a restored output under a new path, delete historical backups, or claim
cryptographic erasure of old backups plus old keys. Replacing a registered path or
custody configuration is an explicit owner configuration change followed by a
restart; backup purge and off-host coordination remain separate work.

### Explicit indexed ingest and browsing

Admitted and copied archives can opt into authenticated indexed browsing; admitted
archives also support indexed startup and append. Initialize once with an explicit
full audit using the corresponding profile binding:

```sh
kan-v2 rebuild-serving-index /srv/kan/archive \
  --binding /etc/kan/archive-binding.json --signing-key /etc/kan/issuer.key
```

Alternatively, select “Initialize or repair archive reads” on a configured
capture-erasure target in the Library owner panel. That preview-bound job uses
the configured issuer key and checks the root archive against independently
current owner custody before rebuilding. It supports admitted and copied roots;
replicas require their own maintenance. It preserves evidence and does not
restart services, change payload layout, or repair missing/corrupt source bytes.

Then add `--indexed` to `serve-admitted`, keeping the same deployment enrollment,
policy, and independent erasure-history configuration. No missing/corrupt index
silently triggers a full-history scan. Repair uses the explicit rebuild command;
it must verify the source archive before replacing derived index data.

Add `--indexed` to `serve-proof` to use bounded authenticated metadata and selected
payload reads for either initialized archive profile. The Library wire protocol and reader
configuration stay unchanged. New archives use a separate payload CID index;
legacy archives remain readable through the existing mode. For indexed browsing
of an old archive, recover into a new output, initialize its serving index, and
explicitly activate that output after checking the recovery result. Originals
remain untouched; there is no implicit in-place layout conversion.

Copied archive checkpoints retain the recipe digest and completion state through
resumable copy batches, new native admissions and owner erasure. Earlier pinned
prefixes keep their own completion status. Independent custody/policy histories
still use their existing paths; full 10 GiB / 100 GiB qualification remains work
in progress.
Owner erasure workers refresh initialized indexes under current custody after
reconciliation, including replicas and dependent publication archives. An external
erasure that bypasses those workers leaves the old checkpoint refused until
explicit maintenance refreshes it. Indexed startup/admission verify touched evidence and cannot stand in for the
full retained-byte audit exposed by `verify`.

### Independent control checkpoints

After creating the first policy or erasure genesis, initialize its serving index
using the owner signing key (not the archive issuer key):

```sh
kan-v2 rebuild-control-index /etc/kan/access-policy.json --signing-key /etc/kan/owner.key
kan-v2 rebuild-control-index /etc/kan/erasure-history.json --erasure --signing-key /etc/kan/owner.key
```

The Library owner panel also exposes “Initialize or repair control reads” for
access-policy and capture-erasure targets. Preview and submit it as a retained
maintenance job; reconnect to inspect its result after closing the browser.

The live grant reader and indexed archive services then use bounded current/minimum
checks. Existing owner actions update these checkpoints under their control lease.
An interrupted update leaves `INDEX-DIRTY` and refuses indexed serving; rerun the
corresponding rebuild command against verified, independently current history.
Do not delete the marker to bypass repair. The raw signed history remains intact.
Back up `CURRENT` with the independently retained control history. Restoring an
old index database alone is refused; restoring the entire control directory still
requires independently current custody. Uninitialized directories retain full
history audits and do not qualify as bounded deployments.

### Large-archive measurement

`scripts/measure-v2-capacity.py` runs the Linux `evidence_inventory` test executable
against a newly created 10 GiB or 100 GiB opaque-payload archive. Build that test
in release mode on the selected remote host, then pass its executable path:

```sh
CARGO_BUILD_JOBS=4 cargo test --release --locked --features v2-crypto --test evidence_inventory --no-run
python3 scripts/measure-v2-capacity.py --binary target/release/deps/evidence_inventory-EXECUTABLE_HASH --directory /chosen/scratch/kan-v2-10g --gib 10
python3 scripts/measure-v2-capacity.py --binary target/release/deps/evidence_inventory-EXECUTABLE_HASH --directory /chosen/scratch/kan-v2-100g --gib 100
```

Use the executable printed by Cargo, and record the Git revision and build command
with the resulting report. Destinations must not exist. The driver checks for
32 GiB or 302 GiB free respectively before writing: current signed requests store
opaque payload hex, so logical payload size and physical database size differ.
It generates actual random payloads through indexed admission, records allocated
database bytes, preserves raw worker logs and partial failure reports, and never
deletes the fixture automatically.

The initial instrument fixes concurrency at one, chunk size at 1 MiB and page size
at one row. Each open/append/page/source sample uses a fresh process; fixture
creation is outside the measurement. Reports contain p50/p95/p99/max latency,
Linux syscall and physical read-byte counts, and process peak RSS, with a 512 MiB
RSS gate. OS cache is retained and physical reads may therefore be zero; syscall
counts include small harness reads. This is an admitted-storage baseline, not a
16-stream server, HTTP, crypto, policy-history, cold-cache or full-application
qualification. The source operation verifies one complete selected signed request.
The ordinary CI suite exercises a two-chunk smoke fixture; only actual remote
10/100 GiB reports can establish those measured size points.

The `V2 real-byte capacity` workflow runs the 10 GiB point on a hosted Linux
runner only after a 38 GiB free-space preflight; the measurement driver rechecks
its own 32 GiB requirement after compilation. It uses a release executable and
uploads the exact revision, compiler, report and raw failure logs for 30 days.
It does not upload the synthetic database, which disappears with the hosted
runner. This workflow cannot establish the 100 GiB point; that still requires
the separately selected larger host/disk. Copy the reports into durable release
evidence before their artifact retention expires.

The first real 10 GiB run passed at `9cd3adb6b809a43e27a2ca927fd361099906c76f`
on hosted Linux with Rust 1.99.1. Its 10,240 random 1 MiB payloads occupied
21,661,548,544 allocated database bytes; seeding took 614.44 seconds. The
[raw report](../.design/measurements/kan-v2-10g-9cd3adb.json) retains all 128
samples, executable digest and environment. The [CI run](https://github.com/kan-tools/kan/actions/runs/39518793836)
also retains the worker logs and exact compiler/revision record.

| Operation | p50 / p95 / p99 latency (ms) | Peak RSS (MiB) | Maximum syscall reads (MiB) |
|---|---:|---:|---:|
| Open | 3.631 / 3.751 / 3.797 | 11.67 | 0.200 |
| Append 1 MiB | 46.931 / 50.373 / 50.418 | 24.09 | 2.020 |
| Page one row | 6.239 / 6.357 / 6.374 | 17.54 | 2.192 |
| Read selected source | 23.246 / 23.759 / 25.860 | 20.08 | 2.368 |

Every operation had 32 fresh-process samples and stayed below the 512 MiB gate.
Physical read counters were zero with the retained OS cache. These measurements
establish the specified 10 GiB storage workload only; they do not establish a
100 GiB growth ratio, cold-cache behavior or whole-service concurrency/latency.


### Run the 100 GiB point on Modal

The opt-in runner `scripts/modal_v2_capacity.py` creates a **new persistent
Modal Volume v2 for each run**, named `kan-v2-fixture-REVISION-RUN_UUID`. It refuses
to reuse an existing name. The synthetic archive lives on that volume; compilation
uses ordinary container scratch space. No `ephemeral_disk` reservation is requested.
The measurement function uses four CPU cores, 18 GiB requested RAM, a 24 GiB RAM
limit and an eight-hour timeout. A separate read-only verification function has
a six-hour timeout. Neither has automatic retries. The serving-process RSS gate
remains 512 MiB; container memory also covers compilation and OS cache.

Modal Volumes grow without a fixed device allocation. Their `statfs` values are
placeholders, so the driver explicitly uses `--storage-backend modal-volume` and
reports physical allocation as unavailable. Its ordinary local-disk mode retains
the original free-space and allocated-block checks. This run measures a Modal
distributed filesystem, **not a directly comparable local-SSD latency point** for
the prior 10 GiB baseline. It still exercises real random payloads, indexed reads,
append operations and the original memory gates. See [Modal's volume semantics](https://modal.com/docs/guide/volumes)
and [pricing](https://modal.com/pricing) for storage/compute billing. Retaining
the fixture incurs storage charges until deletion (billing can lag deletion).

Preparation and launch (the final command starts paid remote compute):

```sh
uv run --no-project --with-requirements scripts/requirements-modal-capacity.txt modal setup
uv run --no-project --with-requirements scripts/requirements-modal-capacity.txt modal run --detach scripts/modal_v2_capacity.py --revision FULL_PUBLISHED_COMMIT_SHA --gib 100 --samples 32
```

Select the intended workspace with `--profile`/`--env` when needed. Only the runner
and its small evidence helper are uploaded; the job fetches public Git source at
the exact SHA and verifies HEAD before building. No production data or keys are
used. Small logs/reports, exact revision/compiler and runner/driver/executable
hashes are retained separately in `kan-v2-capacity-results`. Check that existing
run at intervals of at least 30 minutes; never blindly restart a detached job.

After all worker processes exit, the runner hashes every retained fixture file,
commits the volume, and mounts it read-only in a second single-use container.
That container checks the manifest identity/digest, every file's full byte hash,
the SQLite structure, record/object counts and payload byte totals, and all sample
counts and 512 MiB RSS gates. Only then do `run.json` and `verification.json` become
`complete`. The volume remains available for inspection; failures also retain it.
A detached client interruption between measurement and verification leaves a
`measured` result, not success. Resume verification against the exact retained
manifest rather than rerunning the measurement.

Retrieve only this run's small evidence directory (printed by the runner):

```sh
uv run --no-project --with-requirements scripts/requirements-modal-capacity.txt modal volume get kan-v2-capacity-results REVISION-100g-RUN_ID .local-state/capacity-modal-RUN_ID
```

Before cleanup, require complete `run.json`, `report.json`, and `verification.json`,
the intended revision and unique fixture-volume identity, a matching manifest,
102,400 seeded 1 MiB payloads plus the 32 measured appends, and all 128 samples.
Review distributions and preserve all small reports/logs locally. Physical block
allocation cannot be claimed from a Modal Volume. Do not download the large archive
to the laptop. After validation and evidence retrieval, remove **only the unique
synthetic fixture volume**; never delete `kan-v2-capacity-results`:

```sh
uv run --no-project --with-requirements scripts/requirements-modal-capacity.txt modal volume delete kan-v2-fixture-REVISION-RUN_UUID
```

Record the exact deletion result beside the retained evidence. A failed or
incomplete run is retained for diagnosis; cleanup is separate from measurement,
and no automatic cleanup runs on failure.


### Representative encrypted HTTP measurement

The PR CI step `HTTP encrypted capture qualification at 64 KiB and four writers`
runs `capacity_measurements::capacity_http_capture_sample` and retains
`v2-http-capture-<revision>/kan-http-capture.json`. It measures four independent
writer chains and 1,024 actual encrypted 64 KiB KANC2 frames (64 MiB of bodies),
including signing, encryption, HTTP admission and proof-source decryption. It
also scans storage, indexes/sidecars and a standalone backup for a plaintext
canary. This is a representative-path supplement to the real 10/100 GiB sweep;
combined client/server process RSS and retained OS cache are disclosed explicitly.
Use `KAN_HTTP_CAPTURE_FRAMES` (32–4,096 per writer) and
`KAN_HTTP_CAPTURE_REPORT` for an explicit remote rerun. Do not run the fixture
on the shared laptop merely to obtain another report.

### Service placement and tunnels

The same configured proof service and Library run on a local or remote host.
Listeners bind literal loopback. For cross-host use, place the Library alongside
the service and forward its loopback port through an authenticated tunnel, or
forward the proof service's loopback port to a reader on the client machine.
The reader's endpoint may change; archive/scope/issuer bindings and reader keys
do not. Keep reader and owner credentials separate and preserve same-origin
browser delivery. Never expose the loopback-only service by changing its bind
check or stripping its authentication. Provision the tunnel and host security
explicitly; Kan does not configure SSH or deploy credentials automatically.

The forwarding regression exercises identical signed reads and current revocation
through a TCP relay. Gateway mTLS tests cover the separate trusted plaintext hop.
These synthetic checks do not claim that an owner-specific production tunnel,
backup destination or host installation has been deployed or qualified.
