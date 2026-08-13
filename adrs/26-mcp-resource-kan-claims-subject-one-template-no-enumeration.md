# ADR 26: MCP resource: `kan://claims/{subject}`, one template, no enumeration

- Status: Not recorded contemporaneously
- Date: 2026-07-17
- Reconstruction: Reconstructed from the historical `docs/DECISIONS.md` during RFC 0 migration.
- Original-number: ADR-26

## Context

Not recorded contemporaneously.

## Decision

Not recorded contemporaneously.

## Rationale

Not recorded contemporaneously.

## Consequences

Not recorded contemporaneously.

## Evidence

Not recorded contemporaneously.

## Alternatives considered

Not recorded contemporaneously.

## Supersession

Not recorded contemporaneously.

## Historical record

**Date:** 2026-07-17
**Decision:** `kan mcp` now advertises one `ResourceTemplate`
(`kan://claims/{subject}`, returned from `list_resource_templates`) and
implements `read_resource` to parse the subject out of a
`kan://claims/<subject>` URI and return `actions::show`'s text as a
`TextResourceContents`. `resources/list` (`list_resources`) stays at
`ServerHandler`'s default empty implementation — no fixed enumeration of
every known subject as a discrete `Resource`, since subjects are
open-ended; a client constructs a URI from a subject name it already knows
from a tool call (`show`/`issues`/`status`). No prompts, matching issue
#28's own framing ("exploratory... start with the smallest real slice").
**`rmcp` API shape, confirmed by reading the actual crate source** (not
guessed at, matching the plugin-manifest research's "verify, don't assume"
discipline from the AX-pass session): `ServerHandler` already has
default-implemented `list_resources`/`list_resource_templates`/
`read_resource` methods (`rmcp-2.2.0/src/handler/server.rs`) — no
attribute-macro equivalent of `#[tool]`/`#[tool_router]` exists for
resources in this version, so they're overridden directly as plain async
fns in the same `impl ServerHandler for KanServer` block that already
holds `get_info`. Confirmed `#[tool_handler]` only ever injects
`call_tool`/`list_tools` (`rmcp-macros-2.2.0/src/tool_handler.rs`), so it
doesn't collide with or need to know about the resource methods.
`ListResourceTemplatesResult`/`ListResourcesResult` both come from a
`paginated_result!` macro exposing a `with_all_items(vec![...])`
constructor (not a builder or `::new`, found by reading the macro
expansion, not assumed from the type name).
**Why:** REQ-17's minimal scope ("one resource," "start with the smallest
real slice") argues directly against also building resource enumeration or
prompts in this pass — both are real, separate scope, not needed to prove
the "an MCP client can read a subject's claims via URI" slice this AC
actually asks for.
**Consequences:** `KanServer::get_info` now also calls `.enable_resources()`
on the capabilities builder, and its instructions gained one factual
sentence naming the resource URI (still guarded by the existing sequencing-
language test in `tests/mcp_server.rs`, unaffected since the new sentence
adds no such language). `tests/mcp_server.rs` gained
`ac10_resource_template_lists_and_reads_a_subjects_claims`, a full
JSON-RPC-over-stdio round trip against the real `kan mcp` subprocess:
`initialize` advertises the resources capability, `resources/templates/list`
returns the template, `resources/read` on `kan://claims/<subject>` returns
the same claim text an equivalent `show` tool call would.
