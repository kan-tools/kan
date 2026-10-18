# Continuous delivery and the operator dashboard

Build `kan-v2` with `--features v2-crypto`. These commands extend the experimental
collector/gateway; they do not install a service or migrate a live v1 store.
Use an existing provisioned spool, archive grants and endpoint from
[V2-DELIVERY.md](V2-DELIVERY.md). Create one operations journal per observer spool:

```sh
kan-v2 ops-init "$HEALTH" --spool "$QUEUE"
kan-v2 spool-watch "$QUEUE" --journal "$HEALTH" --endpoint "$ENDPOINT"
kan-v2 ops-status "$HEALTH"
kan-v2 dashboard "$HEALTH" --listen 127.0.0.1:7283 --token-file "$DASHBOARD_TOKEN_FILE"
```

Add `--health-journal "$HEALTH"` to the corresponding `collector` or `gateway`
command. It replaces synchronous per-observation stderr health output with a
bounded nonblocking handoff to a dedicated writer. Provision the journal before startup and bind it to the canonical spool path,
scope, writer and audience. Journal opening and binding checks run on the reporter
thread: missing, locked, invalid or full health storage never gates proxy startup.
Until it recovers the dashboard shows unavailable/unknown coverage, and lost
updates are counted when persistence becomes possible. A mismatched journal is
never written; repair configuration explicitly. Do not share journals between
observers. A missing spool remains reportable through its existing journal.

Open `http://127.0.0.1:7283` and enter a separately provisioned, random dashboard
token of at least 32 printable ASCII characters. Its file must be owner-only.
Use a different token from the harness collector token. The page keeps it only
in memory, never in a URL, cookie or browser storage. Lock clears the view and
token. The public static shell has no private data; `/api/status` requires bearer
authentication. Host and Origin are checked, no CORS is enabled, external assets
are absent, and all responses use no-store. There are no mutation or decryption
routes. For remote administration, tunnel the listener and use the same local
port/address on the browser side so its Host matches. Do not expose this HTTP
listener through a public reverse proxy. A privileged local user remains trusted.

The dashboard and `ops-status` use version 2 of the same JSON contract, including
`journal` capacity, scope and persistence observations. Version 1 HTTP clients
must be updated; old v1 SQLite files remain readable without schema migration.
The browser polls every five seconds and flags worker observations older than
45 seconds. Reporter heartbeats and persistence observations older than five
seconds are stale. Fresh unclosed sessions are active observations; stale and
unsampled unclosed sessions remain uncertain. Historical gaps have a separate
retained-coverage display. No absence of reported gaps proves complete capture.

System/Light/Dark defaults to the platform setting. Only the appearance enum is
stored in browser localStorage; tokens and private data remain in tab memory.

Queue totals come from a consistent spool sample. `next - pending` is the number
of locally committed archive acknowledgments in that queue; it is not an
independent server inventory or anti-rollback proof. `last_ack_at` and position
are worker observations and can lag a commit across a crash. Nonempty-since is
when this worker first saw a continuously nonempty queue during its current run,
not the oldest event's creation time. Wall clocks are not trusted chronology.

`spool-watch` holds one audited queue connection, sends only the retained head,
and removes it only through the existing verified acknowledgment path. Errors
back off 2, 4, 8, 16, then 30 seconds. A permanent rejection remains at the head;
the worker never skips it or recreates the queue. Resolve grants, endpoint or
writer conflicts explicitly. An ambiguous remote commit retries identical signed
bytes after restart. No signing or decryption keys are needed by this worker,
and it never sends inference traffic. Run one worker per spool. Competing workers
are still protected by head acknowledgment checks, not a leader election.

Operations metadata is plaintext and owner-only, matching the instance's
rich-metadata default. It contains summaries, counts and identities, not message
bodies or tokens. The journal stores the latest cumulative observation per attempt,
reporter sessions and the latest worker checkpoint. It cannot replace the raw
encrypted append-only evidence ledger. No automatic expiry or deletion occurs.

New v2 journals have an 8192-page (32 MiB) ceiling plus rollback-journal space,
a 100,000-attempt bound and a 1,024-session bound. The first limit reached wins;
the row limits are not promised physical capacities. A 256 KiB reserve is
preallocated for finite control-record recovery. A recorded capacity failure
releases the reserve and sets a sticky exhaustion marker; subsequent attempt
writes are refused until owner rotation. Existing metadata may still update.
Restart or a later successful heartbeat never clears exhaustion. Whole-device
failure can also prevent the marker from being recorded. Capacity, last success
and loss-count certainty are distinct observations, not a disk-health guarantee.

The callback coalesces cumulative observations in a globally bounded 256-attempt
buffer with sharded locks and finite nonblocking retries. Distinct-attempt
overflow, exhausted retry budgets, contradictions and failed summary writes are
counted where possible. Counts are lower bounds, not missing-raw-message counts;
older journal histories can include individual update losses. No arbitrary-load
lossless guarantee is made. A separate journal reserves logical queue-independent
capacity, not physical capacity when the entire device fails or fills.

Startup audit and filesystem calls remain synchronous and are not hard-time
bounded. The current capture queue still audits on opening per request. This
batch does not claim to solve large-history startup or capture-admission latency.
The worker validates its spool independently and continues archive delivery through
telemetry write failures, accumulating a failure counter and retrying persistence
on later samples. An unavailable or mismatched journal is retried without writing through an
unverified binding. Queue failure still exits the worker; the supervisor can restart it. The dashboard shows stale/missing observations when
metadata cannot be persisted. Checkpoint writes transactionally reconcile prior
acknowledgment/time pairs and deduplicate per-run failure deltas, including late
journal return. Mismatched or regressed queue history is refused; delivery still
continues. A dashboard read may fail under contention and displays unavailable
rather than reporting zero.

## Owner-controlled retained generations

Stop the collector/gateway health reporter and archive worker before maintenance.
Upgraded clients hold lifetime shared locks; maintenance refuses them promptly.
Older binaries do not participate in these locks and **must be stopped explicitly**.
No command below deletes the original journal or an old generation.

```sh
kan-v2 ops-adopt "$HEALTH" "$HEALTH_COLLECTION"
kan-v2 ops-status "$HEALTH_COLLECTION"
kan-v2 ops-generations "$HEALTH_COLLECTION" --limit 50
kan-v2 ops-rotate "$HEALTH_COLLECTION"
kan-v2 ops-history "$HEALTH_COLLECTION" --generation "$GENERATION_ID"
```

Adoption requires a new private destination. It copies and verifies the standalone
journal, seals that history by hash and creates a fresh v2 active generation.
Reconfigure `--health-journal` and `--journal`, and the dashboard positional path,
to the collection directory before restarting writers. Worker acknowledgment and
failure history is seeded into the fresh generation; attempt/session snapshots
remain in their old generation. Do not select generation files directly.

Rotation retains the active file under its existing name, creates/fsyncs a unique
new journal and atomically publishes the manifest. Interrupted staging does not
change membership. A failure after publication is commit-uncertain: inspect
`ops-generations` before deciding whether another rotation is wanted. Unreferenced
staged files are retained recovery artifacts and are never automatically admitted
or deleted. Adoption failure similarly preserves partial output; choose a new
destination only after inspecting the existing one.

Active polling reads one generation, explicitly excluding sealed history. History
reads verify the selected sealed hash and binding. Generation pages are bounded
to 100 entries; `next` supplies the following offset. Cumulative attempts/sessions
can recur across generations, so these snapshots **must not be summed**. A bounded
deduplicated whole-collection overview remains a separate build item. Collections
currently allow at most 1,024 generations; hitting this limit refuses rotation
without deleting anything. The dashboard token remains read-only; browser-triggered
rotation belongs to the forthcoming separate owner admin API.

## Supervision and shutdown

Reviewed example argument layouts are in
[`kan-v2-drain.service`](../examples/supervision/kan-v2-drain.service) and
[`ventures.kan.drain.plist`](../examples/supervision/ventures.kan.drain.plist).
Edit binary paths, user and private data directory before using them. The plist's
`/Users/you` is an example, not automatic home discovery. Provision directories,
spool, health journal, archive grants and backup/recovery keys separately. The
examples are not installed by the build. Configure collector, gateway, dashboard
and archive as separate supervised processes using their documented arguments;
only the gateway needs provider credentials. Keep logs private and rotated by
the host supervisor. The archive and dashboard remain loopback services.

SIGINT or SIGTERM stops new proxy/dashboard work and cancels the archive worker.
In-flight provider outcomes can be unknown. Proxy shutdown attempts to flush the
health channel; a stuck filesystem can delay it, so the supervisor's eventual
forced termination leaves an unclosed session. Worker status becomes stale after
stop. Restart reopens retained data; never delete a queue to recover delivery.
Check `ops-status`, oldest visible retry state, backlog and reporter freshness
before treating a restart as recovered. An independent-host restore drill and
migration rehearsal remain required before live cutover.

## Pending gateway admission

Each source IPv4 address or IPv6 /64 has at most eight pending connections;
32 is the global pending limit. Excess arrivals are refused, never used to evict
an already admitted handshake. Authenticated connections have the existing
separate eight-slot bound. A source behind the same NAT shares a pending budget.
Many sources can still fill the global pool, and authenticated clients can
consume the active pool. This is bounded admission, not Internet denial-of-service
qualification. Use private/source-restricted ingress until deployment-specific
capacity and abuse limits are established.
