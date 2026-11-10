//! Explicit normal-login Claude Code execution. Kan never reads login tokens.
//! One job invocation, no tools/customizations, bounded pipes and owned process
//! cleanup. The CLI's own provider transport behavior is not an exactly-once API.
use super::{service, Failure};
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn valid(executable: &Path, directory: &Path, budget: f64, seconds: u64) -> bool {
    cfg!(unix)
        && executable.is_absolute()
        && executable.is_file()
        && directory.is_absolute()
        && directory.is_dir()
        && directory.canonicalize().is_ok_and(|p| p == directory)
        && budget.is_finite()
        && (0.01..=100.0).contains(&budget)
        && (1..=600).contains(&seconds)
}
fn session(id: &str) -> Result<String, Failure> {
    let mut bytes = service::unhex(id, 32)?;
    if bytes.len() != 32 {
        return Err(Failure::Invalid);
    }
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let s = service::hex(&bytes[..16]);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}
/// Normalize only an actual complete, tool-free CLI result. Keep the full raw
/// stream separately; normalization is not provider API qualification.
fn normalize(
    raw: &[u8],
    expected_model: &str,
    expected_session: &str,
    budget: f64,
) -> Option<Value> {
    let events: Vec<Value> = std::str::from_utf8(raw)
        .ok()?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .ok()?;
    if events.iter().any(|e| {
        e.get("session_id")
            .and_then(Value::as_str)
            .is_some_and(|s| s != expected_session)
            || e["message"]
                .get("model")
                .and_then(Value::as_str)
                .is_some_and(|m| m != expected_model)
            || e["message"]["content"]
                .as_array()
                .is_some_and(|parts| parts.iter().any(|p| p["type"] == "tool_use"))
    }) {
        return None;
    }
    let init: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "system" && e["subtype"] == "init")
        .collect();
    let terminal: Vec<_> = events.iter().filter(|e| e["type"] == "result").collect();
    if init.len() != 1 || terminal.len() != 1 {
        return None;
    }
    let init = init[0];
    let result = terminal[0];
    if init["session_id"] != expected_session
        || init["model"] != expected_model
        || init["tools"].as_array().is_none_or(|t| !t.is_empty())
        || init["mcp_servers"].as_array().is_none_or(|m| !m.is_empty())
        || init["apiKeySource"] != "none"
        || init["permissionMode"] != "dontAsk"
        || result["session_id"] != expected_session
        || result["is_error"] != false
        || result["subtype"] != "success"
    {
        return None;
    }
    if result.get("total_cost_usd").is_some_and(|v| {
        v.as_f64()
            .is_none_or(|n| !n.is_finite() || n < 0.0 || n > budget + 0.000001)
    }) {
        return None;
    }
    let text = result["result"].as_str().filter(|s| !s.trim().is_empty())?;
    // The exact terminal text is already retained in the raw JSONL stream and
    // normalized content. Keep terminal metadata without another output copy.
    let mut terminal = result.clone();
    terminal.as_object_mut()?.remove("result");
    Some(
        json!({"type":"message","model":expected_model,"content":[{"type":"text","text":text}],
        "usage":result["usage"],"claude_code":{"init":init,"result_metadata":terminal,
        "cost_basis":"CLI-reported list-cost usage, not subscription billing; missing usage remains unavailable."}}),
    )
}

#[cfg(unix)]
struct Group(std::sync::atomic::AtomicI32);
#[cfg(unix)]
impl Group {
    fn kill(&self) {
        // SAFETY: spawn creates a new group with this child's positive PID.
        // A negative PID signals only that owned group, never the parent group.
        let pid = self.0.swap(0, std::sync::atomic::Ordering::SeqCst);
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}
#[cfg(unix)]
impl Drop for Group {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(unix)]
pub(super) async fn run(
    executable: &Path,
    directory: &Path,
    budget: f64,
    seconds: u64,
    id: &str,
    request: &Value,
) -> Result<Value, Failure> {
    use std::{os::unix::process::CommandExt, process::Stdio};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    async fn bounded<R: AsyncRead + Unpin>(
        reader: R,
        bytes: &mut Vec<u8>,
        max: usize,
        limited: &mut bool,
    ) -> std::io::Result<()> {
        reader.take((max + 1) as u64).read_to_end(bytes).await?;
        if bytes.len() > max {
            *limited = true;
            bytes.truncate(max);
            return Err(std::io::Error::other("worker output limit"));
        }
        Ok(())
    }
    if !valid(executable, directory, budget, seconds) {
        return Err(Failure::Invalid);
    }
    let model = request["model"].as_str().ok_or(Failure::Invalid)?;
    let system = request["system"].as_str().ok_or(Failure::Invalid)?;
    let input = request["messages"][0]["content"]
        .as_str()
        .ok_or(Failure::Invalid)?;
    let session = session(id)?;
    let mut command = tokio::process::Command::new(executable);
    command
        .args([
            "-p",
            "--model",
            model,
            "--safe-mode",
            "--effort",
            "high",
            "--no-session-persistence",
            "--session-id",
            &session,
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
            "--disable-slash-commands",
            "--no-chrome",
            "--max-budget-usd",
            &budget.to_string(),
            "--output-format",
            "stream-json",
            "--verbose",
            "--system-prompt",
            system,
        ])
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();
    // Preserve normal user-login discovery, not provider key/proxy/alias overrides.
    for name in [
        "HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|_| Failure::Unavailable)?;
    let group = Group(std::sync::atomic::AtomicI32::new(
        child.id().ok_or(Failure::Unavailable)? as i32,
    ));
    let mut stdin = child.stdin.take().ok_or(Failure::Unavailable)?;
    let stdout = child.stdout.take().ok_or(Failure::Unavailable)?;
    let stderr = child.stderr.take().ok_or(Failure::Unavailable)?;
    let mut raw = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut raw_limited = false;
    let mut stderr_limited = false;
    let operation = async {
        let send = async move {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await?;
            // Unix pipe shutdown is a no-op. Explicitly close the handle so a
            // CLI reading its prompt to EOF can finish before we await it.
            drop(stdin);
            Ok::<(), std::io::Error>(())
        };
        let wait = async {
            let result = child.wait().await;
            group.kill();
            result
        };
        tokio::try_join!(
            send,
            bounded(stdout, &mut raw, 2 * 1024 * 1024, &mut raw_limited),
            bounded(stderr, &mut stderr_bytes, 65536, &mut stderr_limited),
            wait
        )
    };
    let observed = tokio::time::timeout(std::time::Duration::from_secs(seconds), operation).await;
    // Also kills descendants on success, timeout, pipe overflow and cancellation.
    group.kill();
    let timed_out = observed.is_err();
    let status = match observed {
        Ok(Ok((_, _, _, status))) => Some(status),
        _ => None,
    };
    if status.is_none() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await;
    }
    let failed = status.as_ref().is_none_or(|s| !s.success());
    let parsed = (!failed)
        .then(|| normalize(&raw, model, &session, budget))
        .flatten();
    Ok(
        json!({"raw":service::hex(&raw),"stderr_hex":service::hex(&stderr_bytes),
        "truncated":raw_limited,"stderr_truncated":stderr_limited,
        "exit_code":status.and_then(|s|s.code()),"timed_out":timed_out,"transport_failed":failed,"parsed":parsed,"session":session,"model":model,
        "worker":"claude-code","tools":[],"execution":"one CLI invocation; no automatic job retry"}),
    )
}
#[cfg(not(unix))]
pub(super) async fn run(
    _: &Path,
    _: &Path,
    _: f64,
    _: u64,
    _: &str,
    _: &Value,
) -> Result<Value, Failure> {
    Err(Failure::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn runtime_shutdown_cancels_detached_worker_and_its_owned_descendant() {
        use std::{os::unix::fs::PermissionsExt, time::Duration};
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().canonicalize().unwrap();
        let executable = directory.join("fake-worker");
        let marker = directory.join("owned-pids");
        // No model or account access: this fixture behaves like a CLI whose
        // process and descendant outlive a dropped extraction waiter.
        std::fs::write(
            &executable,
            "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > owned-pids\nwait\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
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
}
