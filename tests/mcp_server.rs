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
        "observe", "plan", "decide", "resolve", "same", "show", "issues", "status", "context",
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
