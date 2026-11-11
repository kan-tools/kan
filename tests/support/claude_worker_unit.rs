// Unit fixtures stay outside production persistence modules.
use super::*;
#[cfg(unix)]
#[test]
fn runtime_shutdown_cancels_detached_worker_and_its_owned_descendant() {
    use std::{io::Write, os::unix::fs::PermissionsExt, time::Duration};
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().canonicalize().unwrap();
    let marker = directory.join("owned-pids");
    // No model or account access: this fixture behaves like a CLI whose
    // process and descendant outlive a dropped extraction waiter.
    let mut executable = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempfile_in(&directory)
        .unwrap();
    executable
        .write_all(
            b"#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > owned-pids\nwait\n",
        )
        .unwrap();
    executable.flush().unwrap();
    // Close the writable handle before exec (ETXTBSY on Linux), retaining
    // owned temporary-path cleanup until the worker task terminates.
    let executable = executable.into_temp_path();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let worker_directory = directory.clone();
    let task = runtime.spawn(async move {
        run(
            &executable,
            &worker_directory,
            0.05,
            60,
            &"a".repeat(64),
            &json!({"model":"fixture","system":"fixture","messages":[{"content":"synthetic"}]}),
        )
        .await
    });
    let observed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(text) = std::fs::read_to_string(&marker) {
                    if text.split_whitespace().count() == 2 {
                        break text;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    });
    assert!(!task.is_finished());
    // This is the outer CLI deadline path: the separately spawned engine
    // task is still live when the CLI's runtime is dropped.
    drop(runtime);
    let pids: Vec<i32> = observed
        .expect("owned fake worker must start")
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    let running = |pid: i32| {
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8(output.stdout).unwrap();
        // A killed orphan may briefly await the host's reaper. It must
        // never remain executing after owned process-group cleanup.
        !state.trim().is_empty() && !state.trim_start().starts_with('Z')
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while pids.iter().any(|pid| running(*pid)) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pids.iter().all(|pid| !running(*pid)));
}
fn transcript() -> Vec<Value> {
    vec![
        json!({"type":"system","subtype":"init","session_id":"s","model":"claude-sonnet-5-5","apiKeySource":"none","permissionMode":"dontAsk","mcp_servers":[],"tools":[]}),
        json!({"type":"result","subtype":"success","session_id":"s","is_error":false,"total_cost_usd":0.03,"result":"{\"candidates\":[]}"}),
    ]
}
fn bytes(events: &[Value]) -> Vec<u8> {
    events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}
#[test]
fn cli_identity_completion_tools_and_budget_are_checked_not_exit_alone() {
    let e = transcript();
    assert!(normalize(&bytes(&e), "claude-sonnet-5-5", "s", 0.05).is_some());
    for field in ["model", "session_id", "apiKeySource", "permissionMode"] {
        let mut bad = e.clone();
        bad[0][field] = json!("wrong");
        assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    }
    let mut bad = e.clone();
    bad[0]["tools"] = json!(["Read"]);
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e.clone();
    bad[1]["result"] = json!("  ");
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e.clone();
    bad.insert(
        1,
        json!({"type":"assistant","message":{"model":"substituted-model","content":[]}}),
    );
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e.clone();
    bad[0]["mcp_servers"] = json!([{"name":"unexpected","status":"connected"}]);
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e.clone();
    bad[1]["total_cost_usd"] = json!(0.06);
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    assert!(normalize(&bytes(&e[..1]), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e.clone();
    bad.push(e[1].clone());
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
    let mut bad = e;
    bad.insert(
        1,
        json!({"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read"}]}}),
    );
    assert!(normalize(&bytes(&bad), "claude-sonnet-5-5", "s", 0.05).is_none());
}
#[test]
fn session_is_a_fresh_job_bound_uuid_and_not_a_resume() {
    let a = session(&"a".repeat(64)).unwrap();
    assert_eq!(a.len(), 36);
    assert_eq!(&a[14..15], "4");
    assert_ne!(a, session(&"b".repeat(64)).unwrap());
}
