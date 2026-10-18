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

The dashboard and `ops-status` use version 1 of the same JSON contract. The browser
polls every five seconds and flags worker observations older than 45 seconds.
Reporter heartbeats older than five seconds are stale. Active sessions and
unclean exits are distinguished from clean closes, but an unclosed session alone
cannot tell whether its process is alive. Any cumulative recording gap or lost
telemetry stays visible. An absent report never establishes complete capture.

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

Operations metadata is intentionally plaintext and owner-only, matching the
instance's rich-metadata default. It contains summaries, counts and identities,
not message bodies or tokens. The journal keeps the latest cumulative snapshot
for each attempt, reporter sessions, and the latest worker sample. It is not an
append-only archive of every health callback, and cannot replace raw encrypted
evidence. It retains these records until explicit owner removal, with no automatic
expiry. The database is capped at 8192 4-KiB pages (32 MiB), plus SQLite rollback
journal space, and independently at most 100,000 attempts. The first limit reached wins;
100,000 is not a promised capacity. A realistic review fixture filled the byte
cap near 79,740 attempts. It refuses growth rather than deleting old records. Database-full/lock failures and channel overflow increment telemetry-loss
counts when persistence returns; a crash before that update leaves coverage
unknown. The 256-item FIFO can lose the latest cumulative attempt summary under a burst,
even on healthy storage. Its global loss count is retained where possible; per-
attempt counts can then undercount. Coalescing the latest snapshot per attempt
is a follow-up, not an implemented guarantee. A separate journal reserves logical capacity outside the queue budget,
not physical capacity when the entire device fails or fills. Monitor free disk.

Startup audit and filesystem calls remain synchronous and are not hard-time
bounded. The current capture queue still audits on opening per request. This
batch does not claim to solve large-history startup or capture-admission latency.
The worker validates its spool independently and continues archive delivery through
telemetry write failures, accumulating a failure counter and retrying persistence
on later samples. An unavailable or mismatched journal is retried without writing through an
unverified binding. Queue failure still exits the worker; the supervisor can restart it. The dashboard shows stale/missing observations when
metadata cannot be persisted. A dashboard read may fail under writer
contention and displays unavailable rather than reporting zero.

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
