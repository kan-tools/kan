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

For archive services, retain the usual binding, issuer signing key, access policy
and listen options. Enrollment supplies `--erasure-history` to both service roles:

```sh
kan-v2 --deployment /etc/kan/deployment.json serve-admitted /srv/kan/archive \
  --binding /etc/kan/capture-binding.json --signing-key /etc/kan/issuer.key \
  --access-policy /etc/kan/capture-policy.json

kan-v2 --deployment /etc/kan/deployment.json serve-proof /srv/kan/archive \
  --binding /etc/kan/capture-binding.json --signing-key /etc/kan/issuer.key \
  --access-policy /etc/kan/capture-policy.json

kan-v2 --deployment /etc/kan/deployment.json spool-watch /srv/kan/annotation-queue.sqlite \
  --journal /srv/kan/annotation-health.sqlite --endpoint http://127.0.0.1:7282/v1/rpc
```

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

### Explicit indexed ingest

An admitted archive can opt into authenticated index-based storage startup and
append. Initialize it once with an explicit full audit:

```sh
kan-v2 rebuild-serving-index /srv/kan/archive \
  --binding /etc/kan/archive-binding.json --signing-key /etc/kan/issuer.key
```

Then add `--indexed` to `serve-admitted`, keeping the same deployment enrollment,
policy, and independent erasure-history configuration. No missing/corrupt index
silently triggers a full-history scan. Repair uses the explicit rebuild command;
it must verify the source archive before replacing derived index data.

This option currently covers admitted-archive startup and ingestion. Proof Library
reads and independent custody/policy histories still use their existing paths;
copied archives and full 10 GiB / 100 GiB qualification remain work in progress.
Owner erasure workers refresh initialized indexes under current custody after
reconciliation, including replicas and dependent publication archives. An external
erasure that bypasses those workers leaves the old checkpoint refused until
explicit maintenance refreshes it. Indexed startup/admission verify touched evidence and cannot stand in for the
full retained-byte audit exposed by `verify`.
