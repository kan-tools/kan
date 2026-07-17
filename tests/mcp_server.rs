//! AC-8 (`.design/kan-spine.md`): `kan mcp` serves over stdio; a client can
//! list tools and successfully call the claim-append tool. Speaks raw
//! line-delimited JSON-RPC to the real `kan` binary (not a library call)
//! since this is proving the actual `kan mcp` subprocess wiring, matching
//! `tests/cli.rs`'s "real subprocess, not library calls" spirit.

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
        "observe",
        "plan",
        "decide",
        "resolve",
        "same",
        "show",
        "issues",
        "status",
        "session_start",
        "session_end",
        "context",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected:?} in {names:?}"
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
    let cid = call["result"]["content"][0]["text"]
        .as_str()
        .expect("observe tool should return the appended claim's CID as text");
    assert!(!cid.is_empty());

    drop(stdin);
    let _ = child.kill().await;
}
