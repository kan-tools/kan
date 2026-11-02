# Project-scoped Claude capture and evidence retrieval

This integration is opt-in and uses an explicitly selected project configuration.
It is available in the agent-usability build; released `2.0.0-beta.1` predates these
entry points. Use a binary qualified from the same source revision as the scripts.
It does not replace the installed system Kan, migrate a repository, install global
hooks, or enable owner administration.

## The documentation contract

Start with the relevant existing Day handoff and research packet. Record material
decisions, results and handoffs once through the project's established trusted
Day/v1 workflow. Git holds source, theorem status and reports; v2 supplies supporting
captured evidence. Read decoded summaries/content for a particular missing fact,
then inspect raw evidence when an audit needs it. A recorded statement is not an
accepted decision, an authenticated speaker assertion, or proof of a theorem.

Current Day consumers still expect the v1 claim API. Keep their trusted wrappers,
authors, identities and claim references. Full Day adapter migration remains a
separate compatibility gate, including honest withheld/missing states. A local
capture deployment does not satisfy that gate.

## Configuration and preflight

Use `python3 scripts/kan-project.py --config /absolute/private/project.json check`
from an authorized project/worktree. The file is private (0600), and runtime and
credential files must be owner-controlled. All paths are absolute and canonical,
without symlink components. Existing archives, keys and the encrypted spool are
prepared with the ordinary CLI; this helper never creates or selects identities.
Credential values are not embedded in project configuration.

One configuration can name several explicitly authorized durable worktrees:

```json
{
  "version": 1,
  "binary": "/srv/kan/bin/kan",
  "project_roots": ["/srv/projects/research", "/srv/projects/research-worktree"],
  "transcript_roots": ["/srv/harness/authorized-project-transcripts"],
  "runtime": "/srv/kan/private/research-runtime",
  "spool": "/srv/kan/private/research-spool.sqlite",
  "writer_key": "/srv/kan/private/writer.key",
  "recipient": "replace-with-the-selected-64-character-public-recipient-hex",
  "endpoint": "http://127.0.0.1:17381/v1/rpc",
  "reader_config": "/srv/kan/private/reader.json",
  "reader_key": "/srv/kan/private/reader.key",
  "timeout_seconds": 60,
  "startup_seconds": 30,
  "services": [
    {"role":"serve-admitted","archive":"/srv/kan/private/archive",
     "binding":"/srv/kan/private/binding.json",
     "signing_key":"/srv/kan/private/issuer.key",
     "grants":"/srv/kan/private/grants.json","listen":"127.0.0.1:17381"},
    {"role":"serve-proof","archive":"/srv/kan/private/archive",
     "binding":"/srv/kan/private/binding.json",
     "signing_key":"/srv/kan/private/issuer.key",
     "grants":"/srv/kan/private/grants.json","listen":"127.0.0.1:17382"}
  ]
}
```

Replace illustrative paths and the public recipient before use. The runtime is
an existing 0700 directory. The reader configuration uses the ordinary explicit
proof binding, recipient-key reference and inventory grant from V2-LIBRARY.md.
Use a separate append writer and inventory reader. These files select authority;
the helper neither broadens grants nor qualifies production key custody.

Set transcript roots from the harness's actual exported transcript path. Do not
compute Claude's directory encoding from a Git/worktree pathname or search other
projects' transcripts. Authorizing a transcript directory is an operator decision;
receiving a hook never authorizes a new root. The actual event must name an
approved cwd and its transcript must resolve inside an explicit transcript root.
A missing root or denied access is a setup failure to fix before the substantive
session, not proof of an empty transcript. Preflight checks the current process's
filesystem access; a later harness sandbox can still deny access and will record a gap.

`services` can be empty when explicitly configured services are managed elsewhere.
`start` then verifies reader readiness without acquiring ownership of those services.
With listed services it starts only those two declared roles, waits within the
configured listener budget, then verifies the configured reader can obtain its
catalog. Startup errors identify the phase; private service stderr logs are retained
in the runtime. Failed startup stops only recorded owned services. `stop` checks
recorded process identity before signaling and refuses a reused PID.

## Explicit harness setup

Run `claude-settings` to print two fragments: `settings` for Claude's explicit
project settings and `mcp` for its explicit MCP configuration. It also prints the
project contract. Review and merge those fragments into the harness's project
configuration; the command never writes global or project harness settings.
Launch with the project's intended tools and permissions and the explicit MCP
configuration. Do not use a harness mode that disables hooks while claiming capture.
Read-only MCP is selected; write and owner flags are absent.

The hook invokes this same maintained helper and selected config. SessionStart
injects the concise documentation contract. The other configured events retain
exact exported hook bytes; Stop, SessionEnd, compaction events and SubagentStop
also snapshot the actual authorized transcript path. A hook error emits a visible
recording-gap message and returns success so it cannot block the research agent.
The health outcome, rather than the hook process exit code, records capture failure.

The helper serializes capture and drain within a bounded operation budget. It does
not infer task completion from Claude's exit code or from a collector terminal event.
Provider transport capture still requires the separately configured proxy path.

## Boundary health and finalization

Run `health` at the session boundary, not on every prompt or remote-job poll.
It reports operational event counts, historical gaps, explicit backfills and current
spool delivery. Configured SessionStart/Stop events also expose failures through
hook stderr. Keep the actual hook outcomes when interpreting these fields:

- `capture-failed`: an intended capture step failed; any successful earlier hook
  capture is retained separately in the event observation.
- `queued`: capture was retained locally, but acknowledgment is not established.
- `acknowledged`: the drain succeeded and the queue was empty at that observation.
- `explicit_backfills`: marked later snapshot operations succeeded. They never erase
  or relabel earlier gaps, or prove that the previously missing interval is complete.

`capture_completeness` remains `not-verified` and `task_completion` is not assessed.
A zero queue describes delivery, not whether every intended transcript byte was exported.

For a deliberate final prefix snapshot/backfill use:

```sh
python3 scripts/kan-project.py --config /absolute/private/project.json finalize \
  --session-id ACTUAL_SESSION_ID --transcript /actual/authorized/transcript.jsonl
```

This records `KanFinalSnapshot` with origin `explicit-operator-backfill`, not a
fabricated harness SessionEnd event. It returns failure if capture or delivery is
not acknowledged. Repeating it retains another explicit snapshot; it does not
silently overwrite evidence or resend an inference request. Finally run `stop`
for services this helper started. Operational state, logs and failed outputs remain.

## Ordinary agent retrieval

Use `kan_v2_catalog` first to inspect accessible sources and configured capabilities.
Catalog and help responses are paginated: when `next` is non-null, copy it into
`cursor` on the same tool with unchanged other arguments. Their upstream coverage
describes source enumeration, while presentation coverage describes this page.
For proof sources, `kan_v2_discover` accepts an exact source id and bounded limit;
a fresh pin is obtained when omitted. Continue only with the returned pin and
signed cursor together. Responses contain record descriptions, signed selections,
and portable occurrence URIs. The requested limit defaults to three. The serialized
output budget may return fewer rows; the signed next cursor always follows the
last returned row, so following it does not skip hidden inventory entries.

Pass the returned source, pin and selected record selections to `kan_v2_content`.
It uses existing bounded decoded content and source citations. The default selected
view can contain several attempts. For `kind: attempt`, group discovery rows by
their writer, description observer and description attempt, then supply the
selections from exactly one group; this selects the existing larger reconstruction
budget. Mixing attempt identities is refused. `kan_v2_session`
presents explicitly selected cross-archive attempts with observer membership claims
kept separate from writer identity. `kan_v2_reference` accepts an exact returned
portable URI, rechecks current access and returns decoded occurrence content.
A single occurrence can be an incomplete chunk; use attempt reconstruction where
necessary. References are evidence identity, not enduring grants.

These typed tools return at most 12 KiB of JSON per response. Content, session and
reference responses use `entries`: group/stream availability states, explicit
non-capture observations, observer membership claims, and decoded items with
`citations`. Item text can span several Unicode-safe fragments. Follow `next` by
copying it into `cursor` with the exact same source, pin, selections, kind, URI or
session arguments. `text_fragment.continued`/`final` describe one item's text,
and `complete_selection_view` means that presentation has reached its selected
end, never complete capture. A cursor is a query-bound presentation position,
not source-byte selection or authority. Changed evidence/state invalidates it;
restart the view rather than inventing a replacement. Every page rechecks current
source access through the authenticated reader. There is no plaintext page store.

Citations retain portable occurrence URIs and enclosing source byte ranges.
`coarse` attribution is not the exact JSON string-token range. Large redundant
`parsed_json`, `event_json`, redundant event JSON and raw per-frame metadata are
omitted from this normal view; the advanced shared audit API retains them. A
non-text protocol/framing/context wrapper is counted on its stream state rather
than repeated before its readable children; malformed and unsupported states
remain explicit. A
minimum required citation/metadata unit that cannot fit returns `content-limit`,
not empty success or silently discarded evidence. Unknown, unavailable and partial
states remain explicit even when there is no readable text.

`kan_v2_help` returns advertised common schemas, field-copy examples and configured
capabilities. Signed pins and selections are opaque: copy them verbatim rather
than rebuilding them from partial fields. Examples identify where to obtain these
objects; illustrative signatures are not executable credentials. Raw page/range/hex
and optional operations remain in the documented advanced `kan_v2_read` API.
Unavailable content is an explicit state, never evidence that nothing happened.

## Artifact diagnostics and recovery

`kan backup ARCHIVE_DIR NEW_DATABASE_FILE` requires the directory containing
`archive.sqlite`, plus the archive's explicit proof options. `kan verify` and
`kan recover` take standalone database files; recovery writes a new file and retains
originals and failed destinations. Use the correct proof pins and copied-profile
option for the selected archive. No command silently changes its security profile.

`read-record` and `read-object` remain unsigned profile-1 offline audit commands.
Admitted/copied evidence uses authenticated Library reads or explicit proof-aware
offline verification. A profile refusal is not a corruption diagnosis.

Configuration, `health.jsonl`, service logs, process ownership state and lock files
are private operational artifacts, not an alternate Day research record or archive
payload authority. Health history is not automatically deleted. A deleted process
ownership record is not reconstructed into permission to kill an unidentified
service. Keep configuration and necessary operational history with project backups;
never mistake them for the archive or key-recovery package itself.

The experimental [record/recall facade](V2-RECORD-RECALL.md) keeps deliberate
authoring separate from this capture helper. Bounded decoded retrieval now retains
large tool-input JSON fragments with their own enclosing source citations. These
remain observed inputs, never a task-success or tool-execution certificate.
