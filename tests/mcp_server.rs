//! AC-8 (`.design/kan-spine.md`): `kan mcp` serves over stdio; a client can
//! list tools and successfully call the claim-append tool. Also covers
//! `.design/agent-ax-and-tool-boundary.md`'s AC-1 (session tools removed),
//! AC-7 (write tools return rich confirmation text), and AC-8 (factual,
//! non-prescriptive `get_info()` instructions) — same file, unrelated
//! design docs' AC numbering happens to collide. Speaks raw line-delimited
//! JSON-RPC to the real `kan` binary (not a library call) since this is
//! proving the actual `kan mcp` subprocess wiring, matching `tests/cli.rs`'s
//! "real subprocess, not library calls" spirit.

use std::process::Stdio;

use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    dir
}

#[tokio::test]
async fn ac8_lists_tools_and_calls_the_observe_tool() {
    let dir = git_repo();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn kan mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let send = |v: Value| serde_json::to_string(&v).unwrap() + "\n";
    let mut recv_line = String::new();
    macro_rules! recv {
        () => {{
            recv_line.clear();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stdout.read_line(&mut recv_line),
            )
            .await
            .expect("timed out waiting for kan mcp response")
            .expect("failed to read from kan mcp stdout");
            serde_json::from_str::<Value>(&recv_line).expect("response was not valid JSON")
        }};
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "ac8-test", "version": "0.0.1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let init = recv!();
    assert_eq!(init["id"], 1);
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // AC-8: get_info()'s instructions are factual, not a prescribed
    // workflow order -- a cheap guardrail against sequencing language
    // creeping back in.
    let instructions = init["result"]["instructions"]
        .as_str()
        .expect("server should advertise instructions")
        .to_lowercase();
    for word in ["first", "then", "before starting"] {
        assert!(
            !instructions.contains(word),
            "instructions should not prescribe an order of operations, found {word:?} in {instructions:?}"
        );
    }

    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes(),
        )
        .await
        .unwrap();

    stdin
        .write_all(send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).as_bytes())
        .await
        .unwrap();
    let list = recv!();
    let tools = list["result"]["tools"]
        .as_array()
        .expect("tools/list should return an array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "observe", "plan", "decide", "block", "resolve", "result", "same", "relate", "mark",
        "retract", "reject", "show", "issues", "status", "context",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected:?} in {names:?}"
        );
    }
    // AC-1: session lifecycle was removed from kan's CLI+MCP vocabulary
    // entirely (ADR-18) -- no session_start/session_end tool should exist.
    for removed in ["session_start", "session_end"] {
        assert!(
            !names.contains(&removed),
            "{removed:?} should have been removed, found in {names:?}"
        );
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {"text": "mcp ac8 test claim", "subject": "mcp-ac8"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let call = recv!();
    assert_eq!(call["id"], 3);
    assert_eq!(call["result"]["isError"], false);
    // AC-7: MCP write tools always return the richer confirmation text
    // (subject + kind), not just the bare CID -- unlike the CLI, MCP
    // results aren't shell-composed, so there's no bare-CID contract to
    // preserve here.
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("observe tool should return confirmation text");
    assert!(text.contains("mcp-ac8"));
    assert!(text.contains("Observation"));

    drop(stdin);
    let _ = child.kill().await;
}

/// AC-12: MCP `tools/list` includes `relate`/`reject`, and `observe`/
/// `plan`/`decide` schemas show optional `status`/`title`/`kind` params
/// while `block`/`resolve` schemas show `title`/`kind` (no `status` --
/// REQ-9 explicitly excludes those two).
#[tokio::test]
async fn ac12_mcp_tool_surface_mirrors_the_cli() {
    let dir = git_repo();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn kan mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let send = |v: Value| serde_json::to_string(&v).unwrap() + "\n";
    let mut recv_line = String::new();
    macro_rules! recv {
        () => {{
            recv_line.clear();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stdout.read_line(&mut recv_line),
            )
            .await
            .expect("timed out waiting for kan mcp response")
            .expect("failed to read from kan mcp stdout");
            serde_json::from_str::<Value>(&recv_line).expect("response was not valid JSON")
        }};
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "ac12-test", "version": "0.0.1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    recv!();
    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes(),
        )
        .await
        .unwrap();

    stdin
        .write_all(send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).as_bytes())
        .await
        .unwrap();
    let list = recv!();
    let tools = list["result"]["tools"]
        .as_array()
        .expect("tools/list should return an array");

    let schema_of = |name: &str| -> Value {
        tools
            .iter()
            .find(|t| t["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing tool {name:?}"))["inputSchema"]["properties"]
            .clone()
    };

    for name in ["observe", "plan", "decide"] {
        let props = schema_of(name);
        for param in ["status", "title", "kind"] {
            assert!(
                props.get(param).is_some(),
                "{name} schema missing {param:?}: {props:?}"
            );
        }
    }
    for name in ["block", "resolve"] {
        let props = schema_of(name);
        for param in ["title", "kind"] {
            assert!(
                props.get(param).is_some(),
                "{name} schema missing {param:?}: {props:?}"
            );
        }
        assert!(
            props.get("status").is_none(),
            "{name} schema should not have status (REQ-9 excludes it): {props:?}"
        );
    }

    let relate_props = schema_of("relate");
    for param in ["a", "kind", "b"] {
        assert!(relate_props.get(param).is_some());
    }
    // AC-1: same-as is not reachable through relate's kind enum.
    let kind_schema = &relate_props["kind"];
    let kind_json = kind_schema.to_string().to_lowercase();
    assert!(
        !kind_json.contains("sameas") && !kind_json.contains("same_as"),
        "relate's kind schema should not include SameAs: {kind_schema:?}"
    );

    let reject_props = schema_of("reject");
    assert!(reject_props.get("cid").is_some());

    drop(stdin);
    let _ = child.kill().await;
}

/// AC-10 (REQ-17): an MCP client can read the new subject-claims resource
/// at `kan://claims/<subject>` — the same data the `show` tool returns,
/// addressable by URI instead of a tool call.
#[tokio::test]
async fn ac10_resource_template_lists_and_reads_a_subjects_claims() {
    let dir = git_repo();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn kan mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let send = |v: Value| serde_json::to_string(&v).unwrap() + "\n";
    let mut recv_line = String::new();
    macro_rules! recv {
        () => {{
            recv_line.clear();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stdout.read_line(&mut recv_line),
            )
            .await
            .expect("timed out waiting for kan mcp response")
            .expect("failed to read from kan mcp stdout");
            serde_json::from_str::<Value>(&recv_line).expect("response was not valid JSON")
        }};
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "ac10-test", "version": "0.0.1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let init = recv!();
    assert!(
        init["result"]["capabilities"]["resources"].is_object(),
        "server should advertise resource capability"
    );

    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes(),
        )
        .await
        .unwrap();

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {"text": "resource test claim", "subject": "ac10-subject"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let call = recv!();
    assert_eq!(call["result"]["isError"], false);

    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "id": 3, "method": "resources/templates/list"}))
                .as_bytes(),
        )
        .await
        .unwrap();
    let templates = recv!();
    let uri_template = templates["result"]["resourceTemplates"][0]["uriTemplate"]
        .as_str()
        .expect("should list at least one resource template");
    assert_eq!(uri_template, "kan://claims/{subject}");

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "resources/read",
                "params": {"uri": "kan://claims/ac10-subject"}
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let read = recv!();
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .expect("resources/read should return text contents");
    assert!(text.contains("resource test claim"));
    assert!(text.contains("Observation"));

    drop(stdin);
    let _ = child.kill().await;
}

/// REQ-8: the subject-naming nudge (issue #47) appends a warning line to
/// the MCP confirmation text rather than blocking the write -- MCP has no
/// stderr side channel the way the CLI does, so the warning has to ride in
/// the same string the tool call returns.
#[tokio::test]
async fn naming_nudge_appends_a_warning_to_the_confirmation_text() {
    let dir = git_repo();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn kan mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let send = |v: Value| serde_json::to_string(&v).unwrap() + "\n";
    let mut recv_line = String::new();
    macro_rules! recv {
        () => {{
            recv_line.clear();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stdout.read_line(&mut recv_line),
            )
            .await
            .expect("timed out waiting for kan mcp response")
            .expect("failed to read from kan mcp stdout");
            serde_json::from_str::<Value>(&recv_line).expect("response was not valid JSON")
        }};
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "naming-nudge-test", "version": "0.0.1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    recv!();
    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes(),
        )
        .await
        .unwrap();

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {"text": "x", "subject": "f1-c1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    recv!();

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {"text": "y", "subject": "F1-C1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let call = recv!();
    assert_eq!(call["result"]["isError"], false);
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("observe tool should return confirmation text");
    assert!(text.contains("f1-c1"));
    assert!(text.contains("F1-C1"));

    drop(stdin);
    let _ = child.kill().await;
}

/// A bad subject name is refused **early**, on both surfaces, and refusing
/// leaves the repo untouched.
///
/// Note what this does and does not pin. The mint-nothing property comes from
/// `commit_identity` running inside `append` after validation, not from the
/// early check here — a cold review showed the suite stays green with both
/// early checks deleted. What this pins is *where the error surfaces*, and
/// that MCP does not refuse later than the CLI.
///
/// v0.11 hoisted `validate_subject_name` ahead of `Workspace::open`, so a
/// refused subject name cannot mint a signing key or create `.kan/` on its
/// way to being refused (REQ-3). It went into the CLI only — which made it a
/// property of one surface out of two, and CLAUDE.md's "one surface: CLI +
/// MCP" exists precisely so that cannot be a sentence anyone has to write.
///
/// This asserts the property of MCP directly, and the CLI's equivalent lives
/// in `tests/write_guards.rs`. Two tests rather than one because they are two
/// process entry points; the thing that must not drift is the outcome.
#[tokio::test]
async fn an_mcp_write_refused_for_its_subject_name_mints_nothing() {
    let dir = git_repo();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .arg("mcp")
        .current_dir(dir.path())
        .env("KAN_NO_KEYCHAIN", "1")
        .env("KAN_IDENTITY_FILE", dir.path().join("key"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn kan mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let send = |v: Value| serde_json::to_string(&v).unwrap() + "\n";
    let mut recv_line = String::new();
    macro_rules! recv {
        () => {{
            recv_line.clear();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stdout.read_line(&mut recv_line),
            )
            .await
            .expect("timed out waiting for kan mcp response")
            .expect("failed to read from kan mcp stdout");
            serde_json::from_str::<Value>(&recv_line).expect("response was not valid JSON")
        }};
    }

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "mint-test", "version": "0.0.1"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let _ = recv!();
    stdin
        .write_all(
            send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes(),
        )
        .await
        .unwrap();

    stdin
        .write_all(
            send(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "observe",
                    "arguments": {"text": "x", "subject": "bad\nname"}
                }
            }))
            .as_bytes(),
        )
        .await
        .unwrap();
    let refused = recv!();
    let rendered = serde_json::to_string(&refused).unwrap();
    assert!(
        rendered.contains("control character"),
        "the invalid subject name was not refused: {rendered}"
    );

    assert!(
        !dir.path().join("key").exists(),
        "a refused MCP write minted a signing key"
    );
    assert!(
        !dir.path().join(".kan").exists(),
        "a refused MCP write created a workspace"
    );
}
