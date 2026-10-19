use super::*;
use serde_json::{json, Value};
const TOKEN: &str = "synthetic-proof-library-access-token";
struct Ui {
    url: String,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Drop for Ui {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Ui {
    async fn start(readers: kan::evidence_library::Readers) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/api/library", listener.local_addr().unwrap());
        Self {
            url,
            task: tokio::spawn(kan::evidence_library::serve_readers(
                listener,
                TOKEN.into(),
                readers,
            )),
        }
    }
    async fn call(&self, value: Value, status: u16) -> Value {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(&self.url)
            .bearer_auth(TOKEN)
            .json(&value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        response.json().await.unwrap()
    }
    async fn stop(self) {
        self.task.abort();
        while !self.task.is_finished() {
            tokio::task::yield_now().await;
        }
    }
}
#[tokio::test]
async fn library_browses_two_same_scope_archives_with_verified_tokens_and_current_loss() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let admitted = fixture_requests(a.path(), Profile::Admitted, encrypted);
    let copied = fixture_requests(b.path(), Profile::Copied, encrypted);
    let first = Server::start(&admitted).await;
    let second = Server::start(&copied).await;
    // An unreachable configured legacy source marks coverage partial; it does not
    // suppress the two verified proof archives or turn failure into access denial.
    let legacy = kan::evidence_reader::Reader::new(
        identity(6),
        vec![kan::evidence_reader::ScopeAccess {
            scope: [9; 32],
            endpoint: "invalid-protocol://synthetic-unavailable".into(),
            issuer: identity(8).did().to_string(),
            private_key: PRIVATE,
        }],
    )
    .unwrap();
    let ui = Ui::start(
        kan::evidence_library::Readers::new(
            Some(legacy),
            vec![first.client(&admitted), second.client(&copied)],
        )
        .unwrap(),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    assert_eq!(catalog["version"], 2);
    assert_eq!(catalog["coverage"], "partial");
    let scopes = catalog["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 2);
    assert_eq!(scopes[0]["scope"], scopes[1]["scope"]);
    assert_ne!(scopes[0]["id"], scopes[1]["id"]);
    for (index, entry) in scopes.iter().enumerate() {
        let f = if entry["binding"]["profile"] == "admitted" {
            &admitted
        } else {
            &copied
        };
        let pin = &entry["pin"];
        let id = &entry["id"];
        let page = ui
            .call(
                json!({"action":"proof-page","source":id,"pin":pin,"cursor":null,"limit":1}),
                200,
            )
            .await;
        assert_eq!(page["through"], "3");
        assert_eq!(page["records"][0]["sequence"], "3");
        let selection = &page["records"][0]["selection"];
        let source = json!({"action":"proof-source","source":id,"pin":pin,"selection":selection,"offset":"0","length":"65536"});
        let raw = ui.call(source.clone(), 200).await;
        assert_eq!(raw["bytes_hex"], service::hex(RAW));
        assert_eq!(raw["availability"], "available");
        assert_eq!(
            raw["record"]["receipt_issuer"],
            identity(if f.profile == Profile::Copied { 7 } else { 8 })
                .did()
                .as_str()
        );
        assert!(raw["record"]["issued_at"].is_string());
        assert!(raw["utf8"].is_null());
        let rest = ui.call(json!({"action":"proof-page","source":id,"pin":pin,"cursor":page["next"],"limit":40}),200).await;
        assert_eq!(rest["records"].as_array().unwrap().len(), 2);
        assert!(rest["next"].is_null());
        let mut wrong = source.clone();
        wrong["selection"] = page["next"].clone();
        ui.call(wrong, 403).await;
        let mut wrong = source.clone();
        wrong["source"] = scopes[1 - index]["id"].clone();
        ui.call(wrong, 403).await;
        let mut wrong = source.clone();
        wrong["offset"] = json!("00");
        ui.call(wrong, 400).await;
        f.remove(2);
        let missing = ui.call(source, 200).await;
        assert_eq!(missing["availability"], "missing");
        assert_eq!(missing["record"]["manifest"], raw["record"]["manifest"]);
        for key in ["bytes_hex", "utf8", "total_bytes", "offset", "next"] {
            assert!(missing.get(key).is_none(), "{key}");
        }
        f.edit(&format!(
            "UPDATE objects SET bytes=x'00' WHERE cid='{}'",
            f.id(1)
        ));
        let rows = ui
            .call(
                json!({"action":"proof-page","source":id,"pin":pin,"cursor":null,"limit":40}),
                200,
            )
            .await;
        assert_eq!(rows["records"][0]["availability"], "missing");
        assert_eq!(rows["records"][1]["availability"], "corrupt");
        assert_eq!(rows["records"][2]["availability"], "available");
        let corrupt = ui.call(json!({"action":"proof-source","source":id,"pin":pin,"selection":rows["records"][1]["selection"],"offset":"0","length":"65536"}),200).await;
        assert_eq!(corrupt["availability"], "corrupt");
        assert!(corrupt.get("bytes_hex").is_none());
    }
    first
        .service
        .lock()
        .unwrap()
        .replace_grants(Vec::new())
        .unwrap();
    let denied = scopes
        .iter()
        .find(|entry| entry["binding"]["profile"] == "admitted")
        .unwrap();
    ui.call(json!({"action":"proof-page","source":denied["id"],"pin":denied["pin"],"cursor":null,"limit":1}),403).await;

    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    assert_eq!(catalog["scopes"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["coverage"], "partial");
    ui.stop().await;
    first.stop().await;
    second.stop().await;
}

struct ProcessGuard(std::process::Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start_cli(args: &[&str], prefix: &str) -> (ProcessGuard, String) {
    use std::io::BufRead;
    let mut child = ProcessGuard(
        std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stderr).read_line(&mut line);
        let _ = send.send(result.map(|_| line));
    });
    let received = receive.recv_timeout(std::time::Duration::from_secs(10));
    if received.is_err() {
        let _ = child.0.kill();
        let _ = child.0.wait();
    }
    worker.join().unwrap();
    let line = received.expect("CLI startup deadline").unwrap();
    assert!(line.starts_with(prefix), "{line}");
    (child, line.trim().strip_prefix(prefix).unwrap().to_string())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_proof_service_and_library_cli_restart_with_missing_payload() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, encrypted);
        f.remove(2);
        let owner = dir.path().join("owner.key");
        identity(8).save(&owner).unwrap();
        let principal = dir.path().join("reader.key");
        identity(6).save(&principal).unwrap();
        let binding_file = dir.path().join("binding.json");
        std::fs::write(&binding_file, serde_json::to_vec(&binding(&f)).unwrap()).unwrap();
        let grants = dir.path().join("grants.json");
        std::fs::write(&grants, serde_json::to_vec(&vec![grant()]).unwrap()).unwrap();
        let (service_process, endpoint) = start_cli(
            &[
                "serve-proof",
                f.db().to_str().unwrap(),
                "--binding",
                binding_file.to_str().unwrap(),
                "--signing-key",
                owner.to_str().unwrap(),
                "--grants",
                grants.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
            ],
            "proof reader ",
        );
        let private = dir.path().join("recipient.key");
        std::fs::write(&private, PRIVATE).unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, TOKEN).unwrap();
        let config = dir.path().join("reader.json");
        let mut entry = serde_json::to_value(binding(&f)).unwrap();
        entry["protocol"] = json!(wire::PROTOCOL);
        entry["endpoint"] = json!(endpoint);
        entry["private_key_file"] = json!(private);
        std::fs::write(&config, serde_json::to_vec(&vec![entry]).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&private, &token, &config] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let (library_process, base) = start_cli(
            &[
                "library",
                "--config",
                config.to_str().unwrap(),
                "--signing-key",
                principal.to_str().unwrap(),
                "--token-file",
                token.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
            ],
            "library ",
        );
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let call = |body: Value| {
            client
                .post(format!("{base}/api/library"))
                .bearer_auth(TOKEN)
                .json(&body)
                .send()
        };
        let catalog: Value = call(json!({"action":"catalog"}))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(catalog["coverage"], "complete");
        let entry = &catalog["scopes"][0];
        let page:Value=call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":40})).await.unwrap().json().await.unwrap();
        assert_eq!(page["records"].as_array().unwrap().len(), 3);
        assert_eq!(page["records"][0]["availability"], "missing");
        let source:Value=call(json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":page["records"][1]["selection"],"offset":"0","length":"65536"})).await.unwrap().json().await.unwrap();
        assert_eq!(source["bytes_hex"], service::hex(RAW));
        drop(library_process);
        drop(service_process);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual synthetic browser fixture; requires KAN_PROOF_LIBRARY_FIXTURE_INFO"]
async fn proof_library_browser_fixture() {
    let output = std::path::PathBuf::from(
        std::env::var_os("KAN_PROOF_LIBRARY_FIXTURE_INFO").expect("explicit fixture output"),
    );
    let stop = output.with_extension("stop");
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut admitted = fixture_requests(a.path(), Profile::Admitted, encrypted);
    let copied = fixture_requests(b.path(), Profile::Copied, encrypted);
    let mut previous = Some(
        service::append_manifest(admitted.requests.last().unwrap())
            .unwrap()
            .cid()
            .to_string(),
    );
    for n in 3..25 {
        let bytes = encrypted(n, 8, previous);
        attested::Archive::open(&admitted.root, admitted.binding.clone())
            .unwrap()
            .admit(&bytes, &identity(8), &grant(), 200)
            .unwrap();
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
        admitted.requests.push(bytes);
    }
    admitted.remove(24);
    admitted.edit(&format!(
        "UPDATE objects SET bytes=x'00' WHERE cid='{}'",
        admitted.id(23)
    ));
    copied.remove(1);
    let mut tasks = Vec::new();
    let mut clients = Vec::new();
    for f in [&admitted, &copied] {
        let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let endpoint = format!("http://{}/v2/read", listener.local_addr().unwrap());
        tasks.push(tokio::spawn(kan::evidence_http::serve_proof(
            listener,
            reader(f),
        )));
        clients.push(
            client::Reader::new(
                identity(6),
                client::Access {
                    binding: binding(f),
                    endpoint,
                    private_key: PRIVATE,
                },
            )
            .unwrap(),
        );
    }
    let ui = Ui::start(kan::evidence_library::Readers::new(None, clients).unwrap()).await;
    std::fs::write(&output,serde_json::to_vec(&json!({"url":ui.url.trim_end_matches("/api/library"),"token":TOKEN,"expected_hex":service::hex(RAW),"stop":stop})).unwrap()).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
    while !stop.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    ui.stop().await;
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
