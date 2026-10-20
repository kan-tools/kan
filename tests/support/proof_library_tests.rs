use super::*;
use serde_json::{json, Value};
fn private_workspace_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
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
            .post(
                if value["action"] == "search-attempt"
                    || value["action"] == "proof-content"
                    || value["action"] == "proof-attempt"
                    || value["action"] == "proof-session"
                    || value["action"] == "proof-import"
                {
                    format!("{}/{}", self.url, value["action"].as_str().unwrap())
                } else {
                    self.url.clone()
                },
            )
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
    let mut copied = fixture_requests(b.path(), Profile::Copied, captured_request);
    let mut archive = copied::Archive::open(&copied.root, copied.binding.clone()).unwrap();
    for n in 3..6 {
        let attempt = if n == 3 {
            "a".repeat(64)
        } else {
            "b".repeat(64)
        };
        let mut headers = vec![json!([
            "x-kan-session",
            service::hex("c".repeat(64).as_bytes())
        ])];
        if n > 3 {
            headers.push(json!([
                "x-kan-parent-attempt",
                service::hex("a".repeat(64).as_bytes())
            ]));
            headers.push(json!([
                "x-kan-transition",
                service::hex(if n == 4 { b"branch" } else { b"compaction" })
            ]));
        }
        let frame = frame_bytes(
            &attempt,
            if n == 3 { 3 } else { n - 4 },
            json!({"type":"http-metadata","direction":"request","headers":headers,"omitted":[]}),
            &[],
        );
        let previous = Some(
            service::append_manifest(copied.requests.last().unwrap())
                .unwrap()
                .cid()
                .to_string(),
        );
        let bytes = encrypted_frame(n as u8, 8, previous, &frame);
        archive
            .admit(&bytes, &identity(8), &grant(), 200 + n)
            .unwrap();
        copied.requests.push(bytes);
    }
    drop(archive);
    let mut previous = Some(
        service::append_manifest(admitted.requests.last().unwrap())
            .unwrap()
            .cid()
            .to_string(),
    );
    let chunked_metadata=serde_json::to_vec(&json!({"type":"http-metadata","direction":"request","headers":[["x-kan-session",service::hex("c".repeat(64).as_bytes())],["x-kan-parent-attempt",service::hex("a".repeat(64).as_bytes())],["x-kan-transition",service::hex(b"branch")],["x-large",service::hex(&vec![b'x';70000])]],"omitted":[]})).unwrap();
    let metadata_chunks: Vec<_> = chunked_metadata
        .chunks(kan::evidence_capture::CHUNK)
        .collect();
    for n in 3..25 {
        let bytes = if n < 6 {
            let index = (n - 3) as usize;
            let frame = frame_bytes(
                &"d".repeat(64),
                index as u64,
                json!({"type":"http-metadata-chunk","direction":"request","offset":index*kan::evidence_capture::CHUNK,"total":chunked_metadata.len()}),
                metadata_chunks[index],
            );
            encrypted_frame(n, 8, previous, &frame)
        } else {
            encrypted(n, 8, previous)
        };
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

fn captured_request(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
    captured_request_body(
        n,
        audience,
        previous,
        br#"{"messages":[{"role":"user","content":"Hello proof archive"}]}"#,
    )
}
fn captured_request_body(n: u8, audience: u8, previous: Option<String>, body: &[u8]) -> Vec<u8> {
    let event = match n {
        0 => json!({"type":"started","method":"POST","route":"/v1/messages"}),
        1 => json!({"type":"request-chunk","offset":0}),
        _ => json!({"type":"request-end","bytes":body.len()}),
    };
    let header=serde_json::to_vec(&json!({"version":2,"attempt":"a".repeat(64),"observer":"collector","ordinal":n,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":event})).unwrap();
    let mut frame = b"KANC2".to_vec();
    frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
    frame.extend(header);
    if n == 1 {
        frame.extend_from_slice(body);
    }
    encrypted_frame(n, audience, previous, &frame)
}
fn encrypted_frame(n: u8, audience: u8, previous: Option<String>, frame: &[u8]) -> Vec<u8> {
    let mut req = service::SignedRequest::decode(&request(n, audience, previous))
        .unwrap()
        .request;
    let service::Command::Append { ciphertext, .. } = &mut req.command else {
        unreachable!()
    };
    *ciphertext = service::hex(
        &kan::evidence_crypto::seal(
            &kan::evidence_crypto::public_key(&PRIVATE).unwrap(),
            &[1; 32],
            frame,
        )
        .unwrap(),
    );
    service::SignedRequest::sign(req, &identity(6))
        .unwrap()
        .bytes()
        .unwrap()
}
#[tokio::test]
async fn proof_content_preserves_missing_inputs_and_exact_source_citations() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, captured_request);
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        assert!(entry["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("content-inspection")));
        let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":40}),200).await;
        let selections: Vec<_> = page["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["selection"].clone())
            .collect();
        let query = json!({"action":"proof-content","source":entry["id"],"pin":entry["pin"],"selections":selections,"format":"anthropic-messages-json"});
        let content = ui.call(query.clone(), 200).await;
        assert_eq!(content["pin_wire"], entry["pin_wire"]);
        assert_eq!(content["occurrences"].as_array().unwrap().len(), 3);
        assert_eq!(content["groups"][0]["request"]["state"], "interpreted");
        assert!(content["groups"][0]["request"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["text"] == "Hello proof archive"));
        let references = content["groups"][0]["request"]["citation_sets"]
            .as_array()
            .unwrap();
        assert!(!references.is_empty());
        for set in references {
            for citation in set.as_array().unwrap() {
                assert_eq!(citation["input"], "1");
            }
        }
        f.remove(1);
        let missing = ui.call(query.clone(), 200).await;
        assert_eq!(missing["observations"][1]["kind"], "unavailable");
        assert_eq!(missing["observations"][1]["reason"], "Missing");
        assert_eq!(missing["occurrences"][1]["record"]["sequence"], "2");
        assert!(missing["occurrences"][1]["writer"].is_null());
        assert_eq!(missing["groups"][0]["request"]["state"], "unavailable");
        let mut duplicate = query.clone();
        duplicate["selections"] = json!([selections[0], selections[0]]);
        ui.call(duplicate, 400).await;
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(Vec::new())
            .unwrap();
        ui.call(query, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn proof_discovery_continues_verified_inventory_and_keeps_loss_unassigned() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, captured_request);
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        assert!(entry["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("attempt-discovery")));
        let query = json!({"action":"proof-discover","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":1});
        let first = ui.call(query.clone(), 200).await;
        assert_eq!(first["version"], "kan-discovery/1");
        assert_eq!(first["records"][0]["record"]["sequence"], "3");
        assert_eq!(first["records"][0]["description"]["ordinal"], "2");
        assert_eq!(
            first["records"][0]["description"]["event"]["type"],
            "request-end"
        );
        assert_eq!(first["records"][0]["writer"], identity(6).did().as_str());
        assert!(!first.to_string().contains("Hello proof archive"));
        let mut next = query.clone();
        next["cursor"] = first["next"].clone();
        next["limit"] = json!(20);
        let rest = ui.call(next.clone(), 200).await;
        assert_eq!(rest["records"].as_array().unwrap().len(), 2);
        assert!(rest["next"].is_null());
        assert_eq!(
            rest["records"][1]["description"]["event"]["route"],
            "/v1/messages"
        );
        // Tokens discovered off the currently displayed inventory page still
        // authorize exactly the selected occurrence, with fresh verification.
        let raw = ui.call(json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":rest["records"][0]["record"]["selection"],"offset":"0","length":"65536"}),200).await;
        assert!(raw["bytes_hex"]
            .as_str()
            .unwrap()
            .contains(&service::hex(b"Hello proof archive")));
        f.remove(1);
        let lost = ui.call(next.clone(), 200).await;
        assert_eq!(lost["records"][0]["description"], json!({"kind":"missing"}));
        assert!(lost["records"][0]["writer"].is_null());
        assert_eq!(lost["records"][1]["description"]["kind"], "capture");
        next["cursor"] = rest["records"][0]["record"]["selection"].clone();
        ui.call(next, 403).await;
        for limit in [0, 21] {
            let mut invalid = query.clone();
            invalid["limit"] = json!(limit);
            ui.call(invalid, 400).await;
        }
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(Vec::new())
            .unwrap();
        ui.call(query, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}

fn frame_bytes(attempt: &str, ordinal: u64, event: Value, body: &[u8]) -> Vec<u8> {
    let header=serde_json::to_vec(&json!({"version":2,"attempt":attempt,"observer":"collector","ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":event})).unwrap();
    let mut bytes = b"KANC2".to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend(header);
    bytes.extend_from_slice(body);
    bytes
}
#[tokio::test]
async fn large_attempt_reads_over_ten_megabytes_with_all_chunk_citations() {
    let started = std::time::Instant::now();
    let body = serde_json::to_vec(
        &json!({"messages":[{"role":"user","content":"x".repeat(11*1024*1024)}]}),
    )
    .unwrap();
    let attempt = "a".repeat(64);
    let mut frames = vec![frame_bytes(
        &attempt,
        0,
        json!({"type":"started","method":"POST","route":"/v1/messages"}),
        &[],
    )];
    for (i, chunk) in body.chunks(kan::evidence_capture::CHUNK).enumerate() {
        frames.push(frame_bytes(
            &attempt,
            (i + 1) as u64,
            json!({"type":"request-chunk","offset":i*kan::evidence_capture::CHUNK}),
            chunk,
        ));
    }
    frames.push(frame_bytes(
        &attempt,
        frames.len() as u64,
        json!({"type":"request-end","bytes":body.len()}),
        &[],
    ));
    let dir = tempfile::tempdir().unwrap();
    // Reuse only an explicitly supplied synthetic fixture. The dedicated CI capacity job still
    // creates and admits every record. All real reads/proofs run in either case.
    let f = if let Some(path) = std::env::var_os("KAN_LARGE_ATTEMPT_FIXTURE") {
        use std::os::unix::fs::PermissionsExt;
        let root = dir.path().join("archive");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = root.join("archive.sqlite");
        std::fs::copy(path, &db).unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        let conn =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let requests = conn
            .prepare("SELECT bytes FROM objects")
            .unwrap()
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Fixture {
            root,
            binding: attested::Binding {
                archive: [2; 32],
                scope: [1; 32],
                issuer: identity(8).did().to_string(),
            },
            requests,
            profile: Profile::Admitted,
        }
    } else {
        let mut f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
            encrypted_frame(n, a, p, &frames[n as usize])
        });
        let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
        for (n, frame) in frames.iter().enumerate().skip(3) {
            let previous = Some(
                service::append_manifest(f.requests.last().unwrap())
                    .unwrap()
                    .cid()
                    .to_string(),
            );
            let bytes = encrypted_frame(n as u8, 8, previous, frame);
            archive
                .admit(&bytes, &identity(8), &grant(), 200 + n as u64)
                .unwrap();
            f.requests.push(bytes);
        }
        drop(archive);
        f
    };
    eprintln!(
        "synthetic large archive prepared in {:?}",
        started.elapsed()
    );
    let server = Server::start(&f).await;
    let ui = Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
        .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let mut cursor = Value::Null;
    let mut selections = Vec::new();
    loop {
        let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":cursor,"limit":40}),200).await;
        selections.extend(
            page["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["selection"].clone()),
        );
        cursor = page["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    let query = json!({"action":"proof-attempt","source":entry["id"],"pin":entry["pin"],"selections":selections,"format":"anthropic-messages-json"});
    let read_started = std::time::Instant::now();
    let content = ui.call(query.clone(), 200).await;
    eprintln!(
        "synthetic large attempt read in {:?}",
        read_started.elapsed()
    );
    assert_eq!(
        content["occurrences"].as_array().unwrap().len(),
        frames.len()
    );
    let request = &content["groups"][0]["request"];
    assert_eq!(request["state"], "interpreted");
    let text = request["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "text")
        .unwrap();
    assert_eq!(text["text"].as_str().unwrap().len(), 11 * 1024 * 1024);
    let citations = &request["citation_sets"][text["citation_set"]
        .as_str()
        .unwrap()
        .parse::<usize>()
        .unwrap()];
    assert_eq!(citations.as_array().unwrap().len(), frames.len() - 2);
    let mut invalid = query.clone();
    invalid["selections"] = json!([selections[0], selections[0]]);
    ui.call(invalid, 400).await;
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(Vec::new())
        .unwrap();
    ui.call(query, 403).await;
    ui.stop().await;
    server.stop().await;
}
#[tokio::test]
async fn discovery_retains_explicit_session_edges_and_attempt_api_refuses_mixed_identity() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
        let event = json!({"type":"http-metadata","direction":"request","headers":[["x-kan-session",service::hex("c".repeat(64).as_bytes())],["x-kan-parent-attempt",service::hex("a".repeat(64).as_bytes())],["x-kan-transition",service::hex(if n==0 {b"branch"} else {b"compaction"})]],"omitted":[]});
        encrypted_frame(n, a, p, &frame_bytes(&format!("{n:064x}"), 0, event, &[]))
    });
    let server = Server::start(&f).await;
    let ui = Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
        .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let scan=ui.call(json!({"action":"proof-discover","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":20}),200).await;
    assert_eq!(
        scan["records"][0]["description"]["session_link"]["transition"],
        "compaction"
    );
    assert_eq!(
        scan["records"][2]["description"]["session_link"]["transition"],
        "branch"
    );
    let selections: Vec<_> = scan["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["record"]["selection"].clone())
        .collect();
    ui.call(json!({"action":"proof-attempt","source":entry["id"],"pin":entry["pin"],"selections":selections,"format":"anthropic-messages-json"}),400).await;
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn fragmented_session_metadata_crosses_pages_and_preserves_loss_and_revocation() {
    let headers = json!({"type":"http-metadata","direction":"request","headers":[["x-kan-session",service::hex("c".repeat(64).as_bytes())],["x-kan-parent-attempt",service::hex("b".repeat(64).as_bytes())],["x-kan-transition",service::hex(b"branch")],["x-large",service::hex(&vec![b'x';70000])]],"omitted":[]});
    let bytes = serde_json::to_vec(&headers).unwrap();
    let chunks: Vec<_> = bytes.chunks(kan::evidence_capture::CHUNK).collect();
    assert_eq!(chunks.len(), 3);
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, |n, a, p| {
            encrypted_frame(
                n,
                a,
                p,
                &frame_bytes(
                    &"a".repeat(64),
                    n as u64,
                    json!({"type":"http-metadata-chunk","direction":"request","offset":n as usize*kan::evidence_capture::CHUNK,"total":bytes.len()}),
                    chunks[n as usize],
                ),
            )
        });
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let mut cursor = Value::Null;
        let mut selections = Vec::new();
        for _ in 0..3 {
            let page=ui.call(json!({"action":"proof-discover","source":entry["id"],"pin":entry["pin"],"cursor":cursor,"limit":1}),200).await;
            assert_eq!(
                page["records"][0]["description"]["event"]["direction"],
                "request"
            );
            assert!(page["records"][0]["description"]["session_link"].is_null());
            selections.push(page["records"][0]["record"]["selection"].clone());
            cursor = page["next"].clone();
        }
        assert!(cursor.is_null());
        let query = json!({"action":"proof-attempt","source":entry["id"],"pin":entry["pin"],"selections":selections,"format":"anthropic-messages-json"});
        let content = ui.call(query.clone(), 200).await;
        let m = &content["groups"][0]["metadata"][0];
        assert_eq!(m["state"], "complete");
        assert_eq!(m["session_link"]["transition"], "branch");
        let sources = m["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 3);
        for c in sources {
            let input = c["input"].as_str().unwrap().parse::<usize>().unwrap();
            let sequence = content["occurrences"][input]["record"]["sequence"]
                .as_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let start = c["bytes"][0].as_str().unwrap().parse::<usize>().unwrap();
            let end = c["bytes"][1].as_str().unwrap().parse::<usize>().unwrap();
            assert_eq!(end - start, chunks[sequence - 1].len());
            assert!(start > 9);
        }
        f.remove(1);
        let lost = ui.call(query.clone(), 200).await;
        assert!(lost["groups"][0]["metadata"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["state"] != "complete" && m["session_link"].is_null()));
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(Vec::new())
            .unwrap();
        ui.call(query, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn encrypted_search_views_restart_exact_citations_loss_and_revocation() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    fn text(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
        let mut req = service::SignedRequest::decode(&request(n, audience, previous))
            .unwrap()
            .request;
        let service::Command::Append { ciphertext, .. } = &mut req.command else {
            unreachable!()
        };
        *ciphertext = service::hex(
            &kan::evidence_crypto::seal(
                &kan::evidence_crypto::public_key(&PRIVATE).unwrap(),
                &[1; 32],
                "αβ Needle <script>untrusted</script> 🦀".as_bytes(),
            )
            .unwrap(),
        );
        service::SignedRequest::sign(req, &identity(6))
            .unwrap()
            .bytes()
            .unwrap()
    }
    let admitted = fixture_requests(a.path(), Profile::Admitted, text);
    let copied = fixture_requests(b.path(), Profile::Copied, text);
    let first = Server::start(&admitted).await;
    let second = Server::start(&copied).await;
    let workspace = local.path().join("workspace.sqlite");
    let readers = || {
        kan::evidence_library::Readers::new(
            None,
            vec![first.client(&admitted), second.client(&copied)],
        )
        .unwrap()
        .with_workspace(
            kan::evidence_workspace::Workspace::open(&workspace, identity(6), [97; 32]).unwrap(),
        )
    };
    let ui = Ui::start(readers()).await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    assert!(catalog["capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("text-search")));
    let entries = catalog["scopes"].as_array().unwrap();
    let targets: Vec<_> = entries
        .iter()
        .map(|e| json!({"source":e["id"],"pin":e["pin"]}))
        .collect();
    let filter = json!({"text":"needle","writer":null,"kind":"opaque"});
    let query = json!({"action":"search-page","target":targets[0],"cursor":null,"filter":filter});
    assert_eq!(ui.call(query.clone(), 200).await["state"], "not-indexed");
    for target in &targets {
        let indexed = ui
            .call(
                json!({"action":"index-page","target":target,"cursor":null}),
                200,
            )
            .await;
        assert_eq!(indexed["indexed_occurrences"], 3);
        assert!(indexed["next"].is_null());
    }
    let found = ui.call(query.clone(), 200).await;
    assert_eq!(found["hits"].as_array().unwrap().len(), 3);
    assert_eq!(found["hits"][0]["offset"], "5");
    assert_eq!(found["hits"][0]["end"], "11");
    let hit = &found["hits"][0];
    let source=ui.call(json!({"action":"proof-source","source":targets[0]["source"],"pin":targets[0]["pin"],"selection":hit["record"]["selection"],"offset":hit["offset"],"length":"6"}),200).await;
    assert_eq!(source["utf8"], "Needle");
    let mut wrong_filter = query.clone();
    wrong_filter["filter"]["writer"] = json!(identity(9).did().to_string());
    assert!(ui.call(wrong_filter, 200).await["hits"]
        .as_array()
        .unwrap()
        .is_empty());
    let save = json!({"action":"save-view","name":"Private pinned view","targets":targets,"filter":filter});
    let saved = ui.call(save.clone(), 200).await;
    assert_eq!(saved, ui.call(save, 200).await);
    assert_eq!(
        ui.call(json!({"action":"views"}), 200).await["views"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    ui.stop().await;
    let bytes = std::fs::read(&workspace).unwrap();
    assert!(!bytes
        .windows(b"Private pinned view".len())
        .any(|b| b == b"Private pinned view"));
    assert!(!bytes.windows(6).any(|b| b == b"Needle"));
    let ui = Ui::start(readers()).await;
    assert_eq!(ui.call(query.clone(), 200).await["hits"], found["hits"]);
    assert_eq!(
        ui.call(json!({"action":"views"}), 200).await["views"][0],
        saved
    );
    admitted.remove(2);
    let missing = ui.call(query.clone(), 200).await;
    assert_eq!(missing["hits"].as_array().unwrap().len(), 2);
    assert_eq!(missing["unavailable_matches"], 1);
    first
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    ui.call(query, 403).await;
    assert!(ui.call(json!({"action":"views"}), 200).await["views"]
        .as_array()
        .unwrap()
        .is_empty());
    let authorized =
        json!({"action":"search-page","target":targets[1],"cursor":null,"filter":filter});
    assert_eq!(
        ui.call(authorized, 200).await["hits"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    ui.stop().await;
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn annotations_preview_append_correction_preserve_cites_and_filter_revoked_sources() {
    let dir = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(
                kan::evidence_workspace::Workspace::open(
                    &local.path().join("workspace.sqlite"),
                    identity(6),
                    [97; 32],
                )
                .unwrap(),
            ),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":3}),200).await;
    let cite = |n: usize| json!({"source":entry["id"],"pin":entry["pin"],"selection":page["records"][n]["selection"]});
    let draft = json!({"subject":"telos/reliable-recording","text":"A human note <script>untrusted</script>","tags":["decision","decision"],"relations":[{"kind":"InTensionWith","target":"telos/low-latency"}],"cites":[cite(0)],"supersedes":null});
    let preview = ui
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    assert_eq!(preview["declaration"]["author"], identity(6).did().as_str());
    assert_eq!(preview["declaration"]["draft"]["tags"], json!(["decision"]));
    assert!(ui
        .call(
            json!({"action":"annotations","subject":null,"tag":null}),
            200
        )
        .await["records"]
        .as_array()
        .unwrap()
        .is_empty());
    ui.call(
        json!({"action":"annotation-save","draft":draft,"preview":"wrong-preview"}),
        400,
    )
    .await;
    let saved = ui
        .call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200,
        )
        .await;
    assert_eq!(
        saved,
        ui.call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200
        )
        .await
    );
    let correction = json!({"subject":"telos/reliable-recording","text":"Correction with more evidence","tags":["decision","corrected"],"relations":[{"kind":"DependsOn","target":"atom/storage"}],"cites":[cite(1)],"supersedes":saved["id"]});
    let preview = ui
        .call(
            json!({"action":"annotation-preview","draft":correction}),
            200,
        )
        .await;
    assert_eq!(
        preview["declaration"]["draft"]["cites"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    ui.call(json!({"action":"annotation-save","draft":preview["declaration"]["draft"],"preview":preview["id"]}),200).await;
    let history = ui
        .call(
            json!({"action":"annotations","subject":"telos/reliable-recording","tag":"decision"}),
            200,
        )
        .await;
    assert_eq!(history["records"].as_array().unwrap().len(), 2);
    assert!(history["records"].as_array().unwrap().contains(&saved));
    assert_eq!(
        ui.call(
            json!({"action":"annotations","subject":null,"tag":"corrected"}),
            200
        )
        .await["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let subjects = ui
        .call(
            json!({"action":"knowledge-graph","subject":null,"day":true}),
            200,
        )
        .await;
    assert_eq!(subjects["subjects"][0]["kind"], "telos");
    assert_eq!(subjects["subjects"][0]["declarations"], 2);
    let graph = ui
        .call(
            json!({"action":"knowledge-graph","subject":"telos/reliable-recording","day":false}),
            200,
        )
        .await;
    assert_eq!(graph["relations"].as_array().unwrap().len(), 2);
    let old = graph["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "InTensionWith")
        .unwrap();
    assert_eq!(old["corrected_by"].as_array().unwrap().len(), 1);
    assert_eq!(old["to"], "telos/low-latency");
    assert_eq!(graph["records"].as_array().unwrap().len(), 2);
    f.remove(2);
    let absent = ui
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    assert_eq!(absent["evidence"][0]["availability"], "missing");
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    assert!(ui
        .call(
            json!({"action":"annotations","subject":null,"tag":null}),
            200
        )
        .await["records"]
        .as_array()
        .unwrap()
        .is_empty());
    ui.call(json!({"action":"annotation-preview","draft":draft}), 403)
        .await;
    let hidden = ui
        .call(
            json!({"action":"knowledge-graph","subject":null,"day":false}),
            200,
        )
        .await;
    assert!(hidden["subjects"].as_array().unwrap().is_empty());
    assert!(hidden["relations"].as_array().unwrap().is_empty());
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn application_operations_mount_preserves_its_independent_read_credential() {
    let dir = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let spool = local.path().join("spool.sqlite");
    drop(
        kan::evidence_spool::Spool::create(
            &spool,
            &service::hex(&[1; 32]),
            identity(6).did().as_str(),
            identity(8).did().as_str(),
            1024 * 1024,
        )
        .unwrap(),
    );
    let journal = local.path().join("operations.sqlite");
    drop(kan::evidence_operations::Journal::create(&journal, &spool).unwrap());
    const OPS: &str = "synthetic-separate-operations-token";
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_operations(kan::evidence_dashboard::Embedded::new(journal, OPS.into()).unwrap()),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    assert!(catalog["capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("operations-read")));
    let base = ui.url.trim_end_matches("/api/library");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let html = client
        .get(format!("{base}/operations/"))
        .send()
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let html = html.text().await.unwrap();
    assert!(html.contains("src=\"/operations/app.js\""));
    assert!(html.contains("href=\"/operations/style.css\""));
    assert_eq!(
        client
            .get(format!("{base}/operations/api/status"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let status = client
        .get(format!("{base}/operations/api/status"))
        .bearer_auth(OPS)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let status: Value = status.json().await.unwrap();
    assert_eq!(status["version"], 2);
    assert!(status["journal"].is_object());
    assert_eq!(
        client
            .get(format!("{base}/operations/api/status"))
            .bearer_auth(OPS)
            .header("Origin", "http://untrusted.invalid")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&ui.url)
            .bearer_auth(OPS)
            .json(&json!({"action":"catalog"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn annotation_publication_is_explicit_destination_bound_and_exactly_retried() {
    let dir = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    let remote = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let binding = attested::Binding {
        archive: [81; 32],
        scope: [82; 32],
        issuer: identity(7).did().to_string(),
    };
    let ingest = kan::evidence_service::AdmittingService::new(
        attested::Archive::create(remote.path(), binding.clone()).unwrap(),
        identity(7),
        vec![Grant {
            principal: identity(6).did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let task = tokio::spawn(kan::evidence_http::serve_admitted(listener, ingest));
    let private = [83; 32];
    let recipient = kan::evidence_crypto::public_key(&private).unwrap();
    let spool = local.path().join("publication.sqlite");
    drop(
        kan::evidence_spool::Spool::create(
            &spool,
            &service::hex(&binding.scope),
            identity(6).did().as_str(),
            &binding.issuer,
            8 * 1024 * 1024,
        )
        .unwrap(),
    );
    let readers = kan::evidence_library::Readers::new(None, vec![server.client(&f)])
        .unwrap()
        .with_workspace(
            kan::evidence_workspace::Workspace::open(
                &local.path().join("workspace.sqlite"),
                identity(6),
                [97; 32],
            )
            .unwrap(),
        )
        .with_annotation_outbox(
            kan::evidence_library::AnnotationOutbox::new(spool.clone(), endpoint, recipient)
                .unwrap(),
        )
        .unwrap();
    let ui = Ui::start(readers).await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":1}),200).await;
    let draft = json!({"subject":"decision/publication","text":"Publish only after explicit destination confirmation","tags":[],"cites":[{"source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"]}],"supersedes":null});
    let preview = ui
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    let saved = ui
        .call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200,
        )
        .await;
    let status = ui
        .call(
            json!({"action":"annotation-delivery","id":saved["id"]}),
            200,
        )
        .await;
    assert_eq!(status["state"], "not-queued");
    assert_eq!(status["destination"]["scope"], service::hex(&binding.scope));
    ui.call(
        json!({"action":"annotation-queue","id":saved["id"],"destination":"changed-destination"}),
        400,
    )
    .await;
    assert!(kan::evidence_spool::Spool::open(&spool)
        .unwrap()
        .head()
        .unwrap()
        .is_none());
    let queued=ui.call(json!({"action":"annotation-queue","id":saved["id"],"destination":status["destination_digest"]}),200).await;
    assert_eq!(queued["state"], "queued");
    let before = kan::evidence_spool::Spool::open(&spool)
        .unwrap()
        .head()
        .unwrap()
        .unwrap();
    let plain = kan::evidence_delivery::decrypt_request(
        &before,
        &private,
        &binding.scope,
        identity(6).did().as_str(),
    )
    .unwrap();
    let raw: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(raw["format"], "kan-annotation/1");
    assert_eq!(raw["declaration"], saved);
    assert_eq!(queued,ui.call(json!({"action":"annotation-queue","id":saved["id"],"destination":status["destination_digest"]}),200).await);
    assert_eq!(
        before,
        kan::evidence_spool::Spool::open(&spool)
            .unwrap()
            .head()
            .unwrap()
            .unwrap()
    );
    let delivered = ui
        .call(
            json!({"action":"annotation-drain","destination":status["destination_digest"]}),
            200,
        )
        .await;
    assert_eq!(delivered["pending"], "0");
    assert_eq!(
        ui.call(
            json!({"action":"annotation-delivery","id":saved["id"]}),
            200
        )
        .await["state"],
        "acknowledged"
    );
    assert_eq!(
        attested::Archive::open(remote.path(), binding)
            .unwrap()
            .verify()
            .unwrap()
            .through,
        1
    );
    ui.stop().await;
    server.stop().await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn session_content_preserves_archive_boundaries_membership_loss_and_revocation() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let first_fixture = fixture_requests(a.path(), Profile::Admitted, captured_request);
    let second_fixture = fixture_requests(b.path(), Profile::Copied, |n, a, p| {
        let event = json!({"type":"http-metadata","direction":"request","headers":[["x-kan-session",service::hex("c".repeat(64).as_bytes())]],"omitted":[]});
        encrypted_frame(n, a, p, &frame_bytes(&"b".repeat(64), n.into(), event, &[]))
    });
    let first = Server::start(&first_fixture).await;
    let second = Server::start(&second_fixture).await;
    let ui = Ui::start(
        kan::evidence_library::Readers::new(
            None,
            vec![first.client(&first_fixture), second.client(&second_fixture)],
        )
        .unwrap(),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let mut attempts = Vec::new();
    for entry in catalog["scopes"].as_array().unwrap() {
        let page = ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":3}),200).await;
        attempts.push(json!({"source":entry["id"],"pin":entry["pin"],"selections":page["records"].as_array().unwrap().iter().map(|r|r["selection"].clone()).collect::<Vec<_>>()}));
    }
    let request = json!({"action":"proof-session","identity":{"writer":identity(6).did().as_str(),"observer":"collector","scheme":"kan-header","session":"c".repeat(64)},"attempts":attempts,"format":"anthropic-messages-json"});
    let value = ui.call(request.clone(), 200).await;
    assert_eq!(value["version"], "kan-session-content/1");
    assert_eq!(value["attempts"][0]["membership"], "unconfirmed");
    assert_eq!(value["attempts"][1]["membership"], "claimed");
    assert_ne!(
        value["attempts"][0]["source"],
        value["attempts"][1]["source"]
    );
    assert!(
        value["attempts"][0]["content"]["groups"][0]["request"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["text"] == "Hello proof archive")
    );
    let mut conflict = request.clone();
    conflict["identity"]["session"] = json!("d".repeat(64));
    assert_eq!(
        ui.call(conflict, 200).await["attempts"][1]["membership"],
        "conflicting"
    );
    let mut foreign = request.clone();
    foreign["identity"]["writer"] = json!(identity(9).did().as_str());
    ui.call(foreign, 400).await;
    let mut repeated = request.clone();
    repeated["attempts"] = json!([attempts[0], attempts[0]]);
    ui.call(repeated, 400).await;
    first_fixture.remove(2);
    let degraded = ui.call(request.clone(), 200).await;
    assert!(degraded["attempts"][0]["content"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["kind"] == "unavailable"));
    second
        .service
        .lock()
        .unwrap()
        .replace_grants(Vec::new())
        .unwrap();
    ui.call(request, 403).await;
    ui.stop().await;
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn analysis_retains_exact_lineage_quotas_retries_and_revoked_results() {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, Response};
    let dir = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/messages", listener.local_addr().unwrap());
    let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let captured = received.clone();
    let provider = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        async move {
                            assert_eq!(req.uri().path(), "/v1/messages");
                            let raw = req.into_body().collect().await.unwrap().to_bytes();
                            let count = {
                                let mut all = captured.lock().unwrap();
                                all.push(raw.to_vec());
                                all.len()
                            };
                            if count >= 3 {
                                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                            }
                            Ok::<_,std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(br#"{"type":"message","content":[{"type":"text","text":"Untrusted derived assessment citing input 0"}]}"#))))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let source = {
        let temporary =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = temporary.call(json!({"action":"catalog"}), 200).await;
        temporary.stop().await;
        catalog["scopes"][0]["id"].as_str().unwrap().to_string()
    };
    let readers = || {
        kan::evidence_library::Readers::new(None,vec![server.client(&f)]).unwrap()
        .with_workspace(kan::evidence_workspace::Workspace::open(&local.path().join("workspace.sqlite"),identity(6),[97;32]).unwrap())
        .with_analysis(serde_json::from_value(json!({"endpoint":endpoint,"token":"synthetic-analysis-gateway-token-12345","model":"synthetic-model","sources":[source],"recipes":[{"id":"assess","revision":"1","purpose":"day-assessment","instructions":"Assess progress using only cited evidence."}],"max_input_bytes":1024,"max_output_tokens":128,"max_jobs":5,"triggers":[{"tag":"automatic","recipe":"assess"}]})).unwrap()).unwrap()
    };
    let ui = Ui::start(readers()).await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":1}),200).await;
    let draft = json!({"recipe":"assess","cites":[{"source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"]}],"retry_of":null});
    let preview = ui
        .call(json!({"action":"analysis-preview","draft":draft}), 200)
        .await;
    let mut submit = json!({"action":"analysis-submit","draft":draft,"preview":"wrong","nonce":preview["nonce"],"wait":true});
    ui.call(submit.clone(), 400).await;
    assert!(received.lock().unwrap().is_empty());
    submit["preview"] = preview["digest"].clone();
    let done = ui.call(submit.clone(), 200).await;
    assert_eq!(done["state"], "succeeded");
    let id = done["job"]["id"].clone();
    assert_eq!(ui.call(submit.clone(), 200).await, done);
    assert_eq!(received.lock().unwrap().len(), 1);
    let detail = ui.call(json!({"action":"analysis-job","id":id}), 200).await;
    assert_eq!(
        detail["input"]["request_hex"],
        service::hex(&received.lock().unwrap()[0])
    );
    assert_eq!(
        detail["result"]["parsed"]["content"][0]["text"],
        "Untrusted derived assessment citing input 0"
    );
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    assert_eq!(
        ui.call(json!({"action":"analysis-job","id":id}), 200).await,
        detail
    );
    let promoted_draft = json!({"subject":"day/derived","text":"Human-reviewed assessment","tags":[],"cites":draft["cites"],"supersedes":null,"derived_from":[id]});
    let promotion = ui
        .call(
            json!({"action":"annotation-preview","draft":promoted_draft}),
            200,
        )
        .await;
    let promoted = ui
        .call(
            json!({"action":"annotation-save","draft":promoted_draft,"preview":promotion["id"]}),
            200,
        )
        .await;
    let correction = json!({"subject":"day/derived","text":"Corrected human interpretation","tags":[],"cites":draft["cites"],"supersedes":promoted["id"],"derived_from":[]});
    let corrected = ui
        .call(
            json!({"action":"annotation-preview","draft":correction}),
            200,
        )
        .await;
    assert_eq!(
        corrected["declaration"]["draft"]["derived_from"],
        json!([id])
    );
    assert_eq!(corrected["declaration"]["draft"]["cites"], draft["cites"]);
    let mut retry = draft.clone();
    retry["retry_of"] = id.clone();
    let preview = ui
        .call(json!({"action":"analysis-preview","draft":retry}), 200)
        .await;
    assert_eq!(ui.call(json!({"action":"analysis-submit","draft":retry,"preview":preview["digest"],"nonce":preview["nonce"],"wait":true}),200).await["state"],"succeeded");
    let note_draft = json!({"subject":"day/assessment","text":"Assess this explicit evidence","tags":["automatic"],"cites":draft["cites"],"supersedes":null});
    let note_preview = ui
        .call(
            json!({"action":"annotation-preview","draft":note_draft}),
            200,
        )
        .await;
    assert_eq!(
        note_preview["declaration"]["analysis_trigger_plan"][0]["recipe"]["id"],
        "assess"
    );
    let note_request =
        json!({"action":"annotation-save","draft":note_draft,"preview":note_preview["id"]});
    let note = ui.call(note_request.clone(), 200).await;
    let triggers = ui
        .call(json!({"action":"annotation-triggers","id":note["id"]}), 200)
        .await;
    assert_eq!(triggers["attempts"][0]["outcomes"][0]["state"], "scheduled");
    assert_eq!(ui.call(note_request, 200).await, note);
    assert_eq!(
        ui.call(json!({"action":"annotation-triggers","id":note["id"]}), 200)
            .await,
        triggers
    );
    assert_eq!(ui.call(json!({"action":"analysis-job","id":triggers["attempts"][0]["outcomes"][0]["job"],"cancel":true}),200).await["state"],"cancelled");
    submit["nonce"] = json!("e".repeat(64));
    submit["wait"] = json!(false);
    let running = ui.call(submit.clone(), 200).await;
    assert!(matches!(
        running["state"].as_str(),
        Some("running" | "queued")
    ));
    let cancelled = ui
        .call(
            json!({"action":"analysis-job","id":running["job"]["id"],"cancel":true}),
            200,
        )
        .await;
    assert_eq!(cancelled["state"], "cancelled");
    // Emulate a retained start whose worker died, then inspect it through the
    // real API: status must never invent completion or silently replay it.
    let dead_id = "d".repeat(64);
    let workspace = kan::evidence_workspace::Workspace::open(
        &local.path().join("workspace.sqlite"),
        identity(6),
        [97; 32],
    )
    .unwrap();
    let mut interrupted = done["job"].clone();
    interrupted["id"] = json!(dead_id);
    workspace
        .put("analysis-job", &dead_id, interrupted)
        .unwrap();
    workspace
        .put(
            "analysis-event",
            &format!("{dead_id}/1"),
            json!({"job":dead_id,"sequence":1,"state":"running"}),
        )
        .unwrap();
    assert_eq!(
        ui.call(json!({"action":"analysis-job","id":dead_id}), 200)
            .await["state"],
        "interrupted"
    );
    submit["nonce"] = json!("f".repeat(64));
    ui.call(submit, 422).await;
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(Vec::new())
        .unwrap();
    ui.call(json!({"action":"analysis-job","id":id}), 403).await;
    assert!(
        ui.call(json!({"action":"analysis-jobs"}), 200).await["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    ui.stop().await;
    server.stop().await;
    provider.abort();
    let _ = provider.await;
}

async fn owner_call(ui: &Ui, token: &str, query: Value, status: u16) -> Value {
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(ui.url.replace("/api/library", "/api/owner"))
        .bearer_auth(token)
        .json(&query)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    response.json().await.unwrap()
}
#[tokio::test]
async fn owner_maintenance_uses_separate_authority_preview_exact_retry_and_new_outputs() {
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let output = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let spool = local.path().join("spool.sqlite");
    drop(
        kan::evidence_spool::Spool::create(
            &spool,
            &service::hex(&[1; 32]),
            identity(6).did().as_str(),
            identity(8).did().as_str(),
            1024 * 1024,
        )
        .unwrap(),
    );
    let journal = local.path().join("operations.sqlite");
    drop(kan::evidence_operations::Journal::create(&journal, &spool).unwrap());
    let collection = local.path().join("collection");
    kan::evidence_operations_collection::adopt(&journal, &collection).unwrap();
    const OWNER: &str = "synthetic-separate-owner-token-12345";
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"archive","id":"evidence","root":f.root,"output":output.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer}},{"kind":"operations","id":"health","collection":collection}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    owner_call(&ui, TOKEN, json!({"action":"catalog"}), 401).await;
    let catalog = owner_call(&ui, OWNER, json!({"action":"catalog"}), 200).await;
    assert!(catalog["jobs"].as_array().unwrap().is_empty());
    owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"not-configured","operation":"backup","retry_of":null}),
        403,
    )
    .await;
    let initial_generations = kan::evidence_operations_collection::generations(&collection, 0, 50)
        .unwrap()
        .generations
        .len();
    let mut retained = Vec::new();
    for (target, operation) in [
        ("evidence", "backup"),
        ("evidence", "recover"),
        ("health", "rotate"),
    ] {
        let preview = owner_call(
            &ui,
            OWNER,
            json!({"action":"preview","target":target,"operation":operation,"retry_of":null}),
            200,
        )
        .await;
        let mut request = json!({"action":"submit","target":target,"operation":operation,"retry_of":null,"nonce":preview["nonce"],"preview":"wrong","wait":true});
        owner_call(&ui, OWNER, request.clone(), 400).await;
        request["preview"] = preview["digest"].clone();
        let done = owner_call(&ui, OWNER, request.clone(), 200).await;
        assert_eq!(done["state"], "succeeded", "{done}");
        assert_eq!(owner_call(&ui, OWNER, request, 200).await, done);
        if operation != "rotate" {
            let destination = done["job"]["contract"]["destination"].as_str().unwrap();
            let verified =
                attested::Archive::verify_file(Path::new(destination), f.binding.clone()).unwrap();
            assert_eq!(verified.commits, 3);
            assert_eq!(done["result"]["report"]["activation"], "not-performed");
        }
        retained.push(done);
    }
    assert_eq!(
        kan::evidence_operations_collection::generations(&collection, 0, 50)
            .unwrap()
            .generations
            .len(),
        initial_generations + 1
    );
    let denied = reqwest::Client::new()
        .post(ui.url.replace("/api/library", "/api/owner"))
        .bearer_auth(OWNER)
        .header("Origin", "https://untrusted.invalid")
        .json(&json!({"action":"catalog"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    for done in retained {
        assert_eq!(
            owner_call(
                &ui,
                OWNER,
                json!({"action":"job","id":done["job"]["id"]}),
                200
            )
            .await,
            done
        );
    }
    ui.stop().await;
    server.stop().await;
}

fn imported_claim_frames(audience: u8) -> (String, Vec<Vec<u8>>, Vec<u8>) {
    use atproto_dasl::Ipld;
    use kan::claim::v1::{Anchor, AuthorId, Claim, ClaimBody, ClaimContent, SubjectRef};
    use sha2::{Digest, Sha256};
    let content = ClaimContent {
        author: AuthorId {
            did: identity(6).did().to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("legacy-project".into()),
        subject: SubjectRef::Local("telos/reliable-memory".into()),
        body: ClaimBody::Observation {
            text: "An imported claim <script> is still source data".into(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    let id = kan::cid::content_cid(&content).unwrap();
    let stored = kan::store::log::StoredClaim {
        claim: Claim {
            content,
            sig: identity(6).sign(&id.to_bytes()).unwrap(),
        },
        rev: "3jzfcijpj2z2a".into(),
    };
    let block = atproto_dasl::to_vec(&stored).unwrap();
    let cid = kan::cid::content_cid(&stored).unwrap();
    let header = atproto_dasl::to_vec(&Ipld::Map(std::collections::BTreeMap::from([
        ("version".into(), Ipld::Integer(1)),
        ("roots".into(), Ipld::List(vec![Ipld::Link(cid.clone())])),
    ])))
    .unwrap();
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut car = Vec::new();
    varint(header.len(), &mut car);
    car.extend(header);
    varint(cid.to_bytes().len() + block.len(), &mut car);
    car.extend(cid.to_bytes());
    car.extend(block);
    let hash = service::hex(&Sha256::digest(&car));
    let document=serde_json::to_vec(&json!({"profile":1,"source_id":service::hex(&[44;32]),"selection":"store","recipient":service::hex(&kan::evidence_crypto::public_key(&PRIVATE).unwrap()),"route":{"scope":service::hex(&[1;32]),"writer":identity(6).did().as_str(),"audience":identity(audience).did().as_str()},"inventory":{"selected_inventory_complete":true,"notices":[],"files":[{"path":"repo.car","length":car.len(),"sha256":hash}]},"files":[{"path":"repo.car","length":car.len(),"sha256":hash,"chunks":[{"length":car.len(),"sha256":hash}]}]})).unwrap();
    let mut h = Sha256::new();
    h.update(b"tools.kan.import.plan.v1\0");
    h.update(&document);
    let plan = service::hex(&h.finalize());
    let complete=serde_json::to_vec(&json!({"plan":plan,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false})).unwrap();
    let mut frames = Vec::new();
    for (n, (kind, file, body)) in [
        ("inventory", None, document),
        ("data", Some(0), car.clone()),
        ("complete", None, complete),
    ]
    .into_iter()
    .enumerate()
    {
        let header=serde_json::to_vec(&json!({"version":1,"plan":plan,"ordinal":n,"kind":kind,"file":file,"part":0,"parts":1})).unwrap();
        let mut frame = b"KANI\x01".to_vec();
        frame.extend((header.len() as u32).to_be_bytes());
        frame.extend(header);
        frame.extend(body);
        frames.push(frame);
    }
    (plan, frames, car)
}
fn import_request(
    n: u8,
    audience: u8,
    previous: Option<String>,
    plan: &str,
    frame: &[u8],
    bad_operation: bool,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut r = service::SignedRequest::decode(&encrypted_frame(n, audience, previous, frame))
        .unwrap()
        .request;
    if let service::Command::Append { id, .. } = &mut r.command {
        let mut h = Sha256::new();
        h.update(b"tools.kan.import.operation.v1\0");
        h.update(plan.as_bytes());
        h.update((n as u64).to_be_bytes());
        if !bad_operation {
            *id = service::hex(&h.finalize()[..16]);
        }
    }
    service::SignedRequest::sign(r, &identity(6))
        .unwrap()
        .bytes()
        .unwrap()
}
#[tokio::test]
async fn imported_v1_browser_reconstructs_signed_claims_with_exact_ranges_and_current_grants() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let (plan, frames, car) =
            imported_claim_frames(if profile == Profile::Admitted { 8 } else { 7 });
        let f = fixture_requests(dir.path(), profile, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], false)
        });
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let discovery=ui.call(json!({"action":"proof-discover","source":entry["id"],"pin":entry["pin"],"limit":20}),200).await;
        assert!(discovery["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["description"]["kind"] == "import"));
        let selections: Vec<_> = discovery["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["record"]["selection"].clone())
            .collect();
        let query = json!({"action":"proof-import","source":entry["id"],"pin":entry["pin"],"selections":selections,"plan":plan,"file":0});
        let result = ui.call(query.clone(), 200).await;
        assert_eq!(result["state"], "inventory-verified");
        assert_eq!(result["file"]["state"], "verified");
        assert_eq!(result["file"]["length"], car.len().to_string());
        let claim = &result["file"]["car"]["records"][0];
        assert_eq!(claim["state"], "verified-claim");
        assert_eq!(
            claim["claim"]["content"]["subject"]["Local"],
            "telos/reliable-memory"
        );
        assert_eq!(result["file"]["car"]["scan"]["verified_blocks"], 1);
        assert!(result["file"]["car"]["scan"]["error"].is_null());
        let cite = &claim["sources"][0];
        assert_eq!(cite["record"]["sequence"], "2");
        let start: usize = cite["bytes"][0].as_str().unwrap().parse().unwrap();
        let end: usize = cite["bytes"][1].as_str().unwrap().parse().unwrap();
        let stored: kan::store::log::StoredClaim =
            atproto_dasl::from_slice(&frames[1][start..end]).unwrap();
        assert_eq!(
            stored.claim.content.subject,
            kan::claim::v1::SubjectRef::Local("telos/reliable-memory".into())
        );
        let mut absent = query.clone();
        absent["selections"] = json!([selections[0], selections[1]]);
        assert_eq!(ui.call(absent, 200).await["state"], "inventory-incomplete");
        let mut duplicate = query.clone();
        duplicate["selections"] = json!([selections[2], selections[2]]);
        ui.call(duplicate, 400).await;
        f.remove(2); // The completion observation is not required to verify file bytes.
        let without_observation = ui.call(query.clone(), 200).await;
        assert_eq!(without_observation["file"]["state"], "verified");
        assert!(without_observation["completion_observation"].is_null());
        f.remove(1); // The file body itself is now unavailable.
        let missing = ui.call(query.clone(), 200).await;
        assert_eq!(missing["file"]["state"], "incomplete");
        assert_eq!(missing["unavailable"].as_array().unwrap().len(), 2);
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(Vec::new())
            .unwrap();
        ui.call(query, 403).await;
    }
}
#[tokio::test]
async fn imported_v1_browser_refuses_mismatched_operations_or_file_commitments() {
    for bad_operation in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (plan, mut frames, _) = imported_claim_frames(8);
        if !bad_operation {
            *frames[1].last_mut().unwrap() ^= 1;
        }
        let f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], bad_operation)
        });
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let page = ui
            .call(
                json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":20}),
                200,
            )
            .await;
        let selections: Vec<_> = page["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["selection"].clone())
            .collect();
        ui.call(json!({"action":"proof-import","source":entry["id"],"pin":entry["pin"],"selections":selections,"plan":plan,"file":0}),400).await;
    }
}

#[tokio::test]
async fn owner_import_pins_source_batches_exact_retry_and_preserves_originals() {
    let local = private_workspace_directory();
    let source = private_workspace_directory();
    let dir = tempfile::tempdir().unwrap();
    let raw = b"synthetic preserved v1 raw bytes";
    std::fs::write(source.path().join("repo.car"), raw).unwrap();
    std::fs::write(source.path().join("HEAD"), []).unwrap();
    let spool = local.path().join("spool.sqlite");
    drop(
        kan::evidence_spool::Spool::create(
            &spool,
            &service::hex(&[1; 32]),
            identity(6).did().as_str(),
            identity(8).did().as_str(),
            4 * 1024 * 1024,
        )
        .unwrap(),
    );
    let workspace = kan::evidence_workspace::Workspace::open(
        &local.path().join("owner.sqlite"),
        identity(6),
        [84; 32],
    )
    .unwrap();
    let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":"synthetic-owner-import-only-token","max_jobs":10,"targets":[{"kind":"migration","id":"old-project","source":source.path(),"selection":"store","source_id":service::hex(&[44;32]),"recipient":service::hex(&kan::evidence_crypto::public_key(&PRIVATE).unwrap()),"spool":spool,"batch":1,"recovered":local.path().join("recovered")}]})).unwrap(),workspace).unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner),
    )
    .await;
    const OWNER: &str = "synthetic-owner-import-only-token";
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"old-project","operation":"import"}),
        200,
    )
    .await;
    assert_eq!(preview["contract"]["import"]["files"], 2);
    let request = json!({"action":"submit","target":"old-project","operation":"import","nonce":preview["nonce"],"preview":preview["digest"],"wait":true});
    std::fs::write(source.path().join("repo.car"), b"changed before submit").unwrap();
    owner_call(&ui, OWNER, request, 400).await;
    assert!(
        owner_call(&ui, OWNER, json!({"action":"catalog"}), 200).await["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    std::fs::write(source.path().join("repo.car"), raw).unwrap();
    let mut parent = Value::Null;
    let mut first = None;
    for n in 0..4 {
        let preview=owner_call(&ui,OWNER,json!({"action":"preview","target":"old-project","operation":"import","retry_of":parent}),200).await;
        let request = json!({"action":"submit","target":"old-project","operation":"import","retry_of":parent,"nonce":preview["nonce"],"preview":preview["digest"],"wait":true});
        let result = owner_call(&ui, OWNER, request.clone(), 200).await;
        assert_eq!(result["state"], "succeeded", "{result}");
        assert_eq!(result["result"]["report"]["progress"]["newly_queued"], 1);
        assert_eq!(
            result["result"]["report"]["progress"]["queue_coverage_complete"],
            n == 3
        );
        assert_eq!(
            result["result"]["report"]["progress"]["recovery_verified"],
            false
        );
        parent = result["job"]["id"].clone();
        if n == 0 {
            first = Some((request, result));
        }
    }
    let (request, first) = first.unwrap();
    let recovered = local.path().join("recovered");
    let archive = local.path().join("imported-archive");
    let mut destination = Service::new(
        Ledger::create(&archive).unwrap(),
        [1; 32],
        identity(8),
        vec![grant()],
    )
    .unwrap();
    let mut queue = kan::evidence_spool::Spool::open(&spool).unwrap();
    assert_eq!(queue.status().unwrap().pending, 4);
    while let Some(bytes) = queue.head().unwrap() {
        let reply = destination.dispatch(&bytes, 1000).unwrap();
        assert!(reply.reply.result.is_ok());
        queue.acknowledge(&reply.bytes().unwrap()).unwrap();
    }
    drop(queue);
    drop(destination);
    let plan_id = first["job"]["contract"]["import"]["plan"].as_str().unwrap();
    let did = identity(6).did().to_string();
    kan::evidence_restore::restore(
        &archive.join("archive.sqlite"),
        &recovered,
        &kan::evidence_restore::Pins {
            expected_plan: plan_id,
            scope: [1; 32],
            writer: &did,
            recipient_private: PRIVATE,
            max_records: 100,
        },
    )
    .unwrap();
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"old-project","operation":"reconcile-import"}),
        200,
    )
    .await;
    let reconciled=owner_call(&ui,OWNER,json!({"action":"submit","target":"old-project","operation":"reconcile-import","nonce":preview["nonce"],"preview":preview["digest"],"wait":true}),200).await;
    assert_eq!(reconciled["state"], "succeeded", "{reconciled}");
    assert_eq!(
        reconciled["result"]["report"]["recovered_selected_bytes_match"],
        true
    );
    assert_eq!(reconciled["result"]["report"]["ready_for_cutover"], false);

    std::fs::write(source.path().join("repo.car"), b"later source state").unwrap();
    assert_eq!(
        owner_call(&ui, OWNER, request, 200).await,
        first,
        "exact retry inspects the original job without requeueing changed source"
    );
    assert_eq!(
        std::fs::read(source.path().join("repo.car")).unwrap(),
        b"later source state"
    );
    assert_eq!(
        kan::evidence_spool::Spool::open(&spool)
            .unwrap()
            .status()
            .unwrap()
            .pending,
        0
    );
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn proof_import_restoration_and_owner_job_verify_selected_bytes_without_cutover() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = private_workspace_directory();
        let output = private_workspace_directory();
        let local = private_workspace_directory();
        let (plan, frames, car) =
            imported_claim_frames(if profile == Profile::Admitted { 8 } else { 7 });
        let f = fixture_requests(dir.path(), profile, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], false)
        });
        let binding = super::super::binding(&f);
        let restored = output.path().join("direct");
        let writer = identity(6).did().to_string();
        let pins = kan::evidence_restore::Pins {
            expected_plan: &plan,
            scope: [1; 32],
            writer: &writer,
            recipient_private: PRIVATE,
            max_records: 100,
        };
        let report =
            kan::evidence_restore::restore_proof(&f.db(), &restored, &pins, &binding).unwrap();
        assert_eq!(std::fs::read(restored.join("files/repo.car")).unwrap(), car);
        assert_eq!(report["server_attestation"], true);
        assert_eq!(report["ready_for_cutover"], false);
        let mut wrong = binding.clone();
        wrong.archive = service::hex(&[99; 32]);
        let refused = output.path().join("wrong");
        assert!(kan::evidence_restore::restore_proof(&f.db(), &refused, &pins, &wrong).is_err());
        assert!(!refused.exists());
        let key = local.path().join("recipient.key");
        std::fs::write(&key, PRIVATE).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cli_output = output.path().join("cli");
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"));
        command
            .arg("restore-import")
            .arg(f.db())
            .arg(&cli_output)
            .args([
                "--expected-plan",
                &plan,
                "--scope",
                &service::hex(&[1; 32]),
                "--writer",
                &writer,
                "--recipient-key",
            ])
            .arg(&key)
            .args([
                "--proof-archive",
                &binding.archive,
                "--proof-scope",
                &binding.scope,
                "--proof-issuer",
                &binding.issuer,
            ]);
        if profile == Profile::Copied {
            command.arg("--copy-profile");
        }
        let restored_cli = command.output().unwrap();
        assert!(
            restored_cli.status.success(),
            "{}",
            String::from_utf8_lossy(&restored_cli.stderr)
        );
        assert_eq!(
            std::fs::read(cli_output.join("files/repo.car")).unwrap(),
            car
        );
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":"synthetic-owner-restore-only-token","max_jobs":10,"targets":[{"kind":"import-recovery","id":"snapshot","database":f.db(),"output":output.path(),"binding":binding,"plan":plan,"scope":service::hex(&[1;32]),"writer":identity(6).did().as_str(),"recipient_key":key,"max_records":100}]})).unwrap(),kan::evidence_workspace::Workspace::open(&local.path().join("owner.sqlite"),identity(9),[84;32]).unwrap()).unwrap();
        let server = Server::start(&f).await;
        let ui = Ui::start(
            kan::evidence_library::Readers::new(None, vec![server.client(&f)])
                .unwrap()
                .with_owner(owner),
        )
        .await;
        const OWNER: &str = "synthetic-owner-restore-only-token";
        let preview = owner_call(
            &ui,
            OWNER,
            json!({"action":"preview","target":"snapshot","operation":"restore-import"}),
            200,
        )
        .await;
        assert!(preview["contract"]["effect"]
            .as_str()
            .unwrap()
            .contains("PLAINTEXT"));
        let done=owner_call(&ui,OWNER,json!({"action":"submit","target":"snapshot","operation":"restore-import","nonce":preview["nonce"],"preview":preview["digest"],"wait":true}),200).await;
        assert_eq!(done["state"], "succeeded", "{done}");
        let destination = Path::new(done["result"]["report"]["destination"].as_str().unwrap());
        assert_eq!(
            std::fs::read(destination.join("files/repo.car")).unwrap(),
            car
        );
        assert!(destination.join("report.json").is_file());
        assert_eq!(done["result"]["report"]["activation"], "not-performed");
        assert!(f.db().exists());
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn search_normalizes_complete_json_with_enclosing_cites_and_reproducible_facets() {
    let dir = tempfile::tempdir().unwrap();
    let local = private_workspace_directory();
    let body = br#"{"messages":[{"role":"user","content":"Hello \u0070roof archive"}]}"#;
    let f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
        captured_request_body(n, a, p, body)
    });
    let server = Server::start(&f).await;
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(
                kan::evidence_workspace::Workspace::open(
                    &local.path().join("search.sqlite"),
                    identity(6),
                    [97; 32],
                )
                .unwrap(),
            ),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let target = json!({"source":entry["id"],"pin":entry["pin"]});
    let indexed = ui
        .call(json!({"action":"index-page","target":target}), 200)
        .await;
    assert_eq!(indexed["facets_as_indexed"]["observer"]["collector"], 3);
    let mut query = json!({"action":"search-page","target":target,"filter":{"text":"Hello proof","observer":"collector","attempt":"a".repeat(64)}});
    let found = ui.call(query.clone(), 200).await;
    assert_eq!(found["hits"].as_array().unwrap().len(), 1);
    let hit = &found["hits"][0];
    assert_eq!(hit["interpretation"], "json-string");
    assert_eq!(hit["coarse"], true);
    assert_eq!(hit["record"]["sequence"], "2");
    let source=ui.call(json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":hit["record"]["selection"],"offset":hit["offset"],"length":body.len().to_string()}),200).await;
    assert_eq!(source["bytes_hex"], service::hex(body));
    query["filter"]["attested_from"] = hit["attested_at"].clone();
    query["filter"]["attested_to"] = hit["attested_at"].clone();
    assert_eq!(
        ui.call(query.clone(), 200).await["hits"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut facets = query.clone();
    facets["filter"] = json!({"text":"","observer":"collector"});
    let rows = ui.call(facets, 200).await;
    assert_eq!(rows["hits"].as_array().unwrap().len(), 3);
    assert_eq!(rows["hits"][0]["interpretation"], "metadata-only");
    let saved=ui.call(json!({"action":"save-view","name":"One attested attempt","targets":[target],"filter":query["filter"]}),200).await;
    assert_eq!(saved["filter"]["observer"], "collector");
    assert_eq!(saved["filter"]["attested_from"], hit["attested_at"]);
    let mut wrong = query.clone();
    wrong["filter"]["observer"] = json!("gateway");
    assert!(ui.call(wrong, 200).await["hits"]
        .as_array()
        .unwrap()
        .is_empty());
    wrong = query.clone();
    wrong["filter"]["attempt"] = json!("b".repeat(64));
    assert!(ui.call(wrong, 200).await["hits"]
        .as_array()
        .unwrap()
        .is_empty());
    wrong = query.clone();
    wrong["filter"]["attested_to"] = json!("0");
    ui.call(wrong, 400).await;
    wrong = query.clone();
    wrong["filter"]["attested_from"] = json!("01");
    ui.call(wrong, 400).await;
    f.remove(1);
    let erased = ui.call(query, 200).await;
    assert!(erased["hits"].as_array().unwrap().is_empty());
    assert_eq!(erased["unavailable_matches"], 1);
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn owner_workspace_recovery_is_previewed_separate_and_retains_authored_history() {
    const OWNER: &str = "synthetic-workspace-recovery-owner-token";
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let output = private_workspace_directory();
    let signing = local.path().join("reader.signing");
    let key = local.path().join("reader.recipient");
    for (path, bytes) in [(&signing, [6; 32]), (&key, [8; 32])] {
        // Synthetic private-key fixture, outside the production mutation surface.
        #[allow(clippy::disallowed_types)]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    let source = local.path().join("reader.sqlite");
    let reader = kan::evidence_workspace::Workspace::open(&source, identity(6), [8; 32]).unwrap();
    reader
        .put("view", "retained", json!({"title":"Preserved scope"}))
        .unwrap();
    let journal = kan::evidence_workspace::Workspace::open(
        &local.path().join("owner.sqlite"),
        identity(7),
        [9; 32],
    )
    .unwrap();
    let owner = kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"workspace-recovery","id":"reader","database":source,"output":output.path(),"signing_key":signing,"recipient_key":key}]})).unwrap(),journal).unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner),
    )
    .await;
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"reader","operation":"recover"}),
        200,
    )
    .await;
    let request = json!({"action":"submit","target":"reader","operation":"recover","nonce":preview["nonce"],"preview":preview["digest"],"wait":true});
    let blocked = owner_call(&ui, OWNER, request.clone(), 200).await;
    assert_eq!(blocked["state"], "failed");
    drop(reader);
    // An exact retry preserves the failed job. A linked attempt performs recovery.
    assert_eq!(owner_call(&ui, OWNER, request, 200).await, blocked);
    let prior = &blocked["job"]["id"];
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"reader","operation":"recover","retry_of":prior}),
        200,
    )
    .await;
    let request = json!({"action":"submit","target":"reader","operation":"recover","retry_of":prior,"nonce":preview["nonce"],"preview":preview["digest"],"wait":true});
    let done = owner_call(&ui, OWNER, request.clone(), 200).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(done["result"]["report"]["authenticated_entries"]["view"], 1);
    assert_eq!(done["result"]["report"]["activation"], "not-performed");
    assert_eq!(owner_call(&ui, OWNER, request, 200).await, done);
    let destination = Path::new(done["result"]["report"]["destination"].as_str().unwrap());
    let recovered =
        kan::evidence_workspace::Workspace::open(destination, identity(6), [8; 32]).unwrap();
    assert_eq!(
        recovered.views().unwrap(),
        vec![json!({"title":"Preserved scope"})]
    );
    assert!(source.exists());
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn search_reconstructs_chunked_messages_with_all_citations_and_rechecks_loss_and_access() {
    let body = br#"{"messages":[{"role":"user","content":"Hello \u0070roof archive"}]}"#;
    let split = 47;
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = private_workspace_directory();
        let local = private_workspace_directory();
        let f = fixture_requests(dir.path(), profile, |n, a, p| {
            let (event, bytes) = match n {
                0 => (json!({"type":"request-chunk","offset":0}), &body[..split]),
                1 => (
                    json!({"type":"request-chunk","offset":split}),
                    &body[split..],
                ),
                _ => (json!({"type":"request-end","bytes":body.len()}), &b""[..]),
            };
            encrypted_frame(
                n,
                a,
                p,
                &frame_bytes(&"a".repeat(64), n as u64, event, bytes),
            )
        });
        let server = Server::start(&f).await;
        let ui = Ui::start(
            kan::evidence_library::Readers::new(None, vec![server.client(&f)])
                .unwrap()
                .with_workspace(
                    kan::evidence_workspace::Workspace::open(
                        &local.path().join("search.sqlite"),
                        identity(6),
                        [97; 32],
                    )
                    .unwrap(),
                ),
        )
        .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let target = json!({"source":entry["id"],"pin":entry["pin"]});
        ui.call(json!({"action":"index-page","target":target}), 200)
            .await;
        let filter = json!({"text":"Hello proof","observer":"collector"});
        let raw = ui
            .call(
                json!({"action":"search-page","target":target,"filter":filter}),
                200,
            )
            .await;
        assert!(raw["hits"].as_array().unwrap().is_empty());
        assert_eq!(raw["attempt_members"].as_array().unwrap().len(), 3);
        let selections: Vec<_> = raw["attempt_members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["record"]["selection"].clone())
            .collect();
        let query = json!({"action":"search-attempt","target":target,"selections":selections,"filter":filter});
        let found = ui.call(query.clone(), 200).await;
        assert_eq!(found["hits"].as_array().unwrap().len(), 1, "{found}");
        let hit = &found["hits"][0];
        assert_eq!(hit["interpretation"], "reconstructed-message");
        assert_eq!(hit["snippet"], "Hello proof archive");
        let cites = hit["cites"].as_array().unwrap();
        assert_eq!(cites.len(), 2);
        let mut reconstructed = Vec::new();
        for cite in cites {
            let start = cite["offset"].as_str().unwrap().parse::<u64>().unwrap();
            let end = cite["end"].as_str().unwrap().parse::<u64>().unwrap();
            let source = ui.call(json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":cite["record"]["selection"],"offset":start.to_string(),"length":(end-start).to_string()}),200).await;
            reconstructed.extend(
                service::unhex(
                    source["bytes_hex"].as_str().unwrap(),
                    (end - start) as usize,
                )
                .unwrap(),
            );
        }
        assert_eq!(reconstructed, body);
        let mut excluded = query.clone();
        excluded["filter"]["kind"] = json!("opaque");
        assert!(ui.call(excluded, 200).await["hits"]
            .as_array()
            .unwrap()
            .is_empty());
        f.remove(1);
        let missing = ui.call(query.clone(), 200).await;
        assert!(missing["hits"].as_array().unwrap().is_empty());
        assert!(missing["streams"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["state"] == "unavailable"));
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(vec![])
            .unwrap();
        ui.call(query, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn portable_references_rebind_for_another_reader_without_granting_access_or_hiding_loss() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = private_workspace_directory();
        let f = fixture_requests(dir.path(), profile, encrypted);
        let server = Server::start(&f).await;
        let first = server.client(&f);
        let pin = first.snapshot().await.unwrap();
        let page = first.page(&pin, None, 3).await.unwrap();
        let row = &page.records[0];
        let reference = client::Reference::new(first.binding(), row);
        let second = || {
            client::Reader::new(
                identity(7),
                client::Access {
                    binding: binding(&f),
                    endpoint: server.endpoint.clone(),
                    private_key: PRIVATE,
                },
            )
            .unwrap()
        };
        assert!(matches!(
            second().resolve_reference(&reference).await,
            Err(Failure::AccessLimited)
        ));
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(vec![
                grant(),
                Grant {
                    principal: identity(7).did(),
                    append: false,
                    inventory: true,
                },
            ])
            .unwrap();
        // Reader-local selections remain local. The portable identity is resolved afresh.
        assert!(matches!(
            second().source(&pin, &row.selection).await,
            Err(Failure::AccessLimited)
        ));
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![second()]).unwrap()).await;
        let request = json!({"action":"resolve-reference","reference":reference});
        let resolved = ui.call(request.clone(), 200).await;
        assert_eq!(resolved["record"]["manifest"], row.manifest);
        assert_eq!(resolved["record"]["receipt"], row.receipt);
        assert_ne!(
            resolved["record"]["selection"],
            serde_json::to_value(&row.selection).unwrap()
        );
        let source = ui.call(json!({"action":"proof-source","source":resolved["source"],"pin":resolved["pin"],"selection":resolved["record"]["selection"],"offset":"0","length":"100"}),200).await;
        assert_eq!(source["bytes_hex"], service::hex(RAW));
        assert_eq!(
            source["reference"],
            serde_json::to_value(&reference).unwrap()
        );
        let mut forged = request.clone();
        forged["reference"]["receipt"] = json!(page.records[1].receipt);
        ui.call(forged, 503).await;
        f.remove(2);
        let missing = ui.call(request.clone(), 200).await;
        assert_eq!(missing["record"]["availability"], "missing");
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(vec![grant()])
            .unwrap();
        ui.call(request, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn published_annotations_restore_original_authorship_and_rebind_citations_without_side_effects(
) {
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let first = Ui::start(
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(
                kan::evidence_workspace::Workspace::open(
                    &local.path().join("original.sqlite"),
                    identity(6),
                    [91; 32],
                )
                .unwrap(),
            ),
    )
    .await;
    let catalog = first.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let rows = first
        .call(
            json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":3}),
            200,
        )
        .await;
    let cite = json!({"source":entry["id"],"pin":entry["pin"],"selection":rows["records"][0]["selection"]});
    let draft = json!({"subject":"telos/durable-knowledge","text":"Original annotation must survive workspace loss","tags":["retained"],"cites":[cite],"supersedes":null});
    let preview = first
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    let saved = first
        .call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200,
        )
        .await;
    let bytes =
        serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":saved})).unwrap();
    let previous = Some(
        service::append_manifest(f.requests.last().unwrap())
            .unwrap()
            .cid()
            .to_string(),
    );
    let publication = encrypted_frame(3, 8, previous, &bytes);
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    archive
        .admit(&publication, &identity(8), &grant(), 1000)
        .unwrap();
    drop(archive);
    first.stop().await;
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![
            grant(),
            Grant {
                principal: identity(7).did(),
                append: false,
                inventory: true,
            },
        ])
        .unwrap();
    let other = client::Reader::new(
        identity(7),
        client::Access {
            binding: binding(&f),
            endpoint: server.endpoint.clone(),
            private_key: PRIVATE,
        },
    )
    .unwrap();
    let pin = other.snapshot().await.unwrap();
    let page = other.page(&pin, None, 1).await.unwrap();
    let reference = client::Reference::new(other.binding(), &page.records[0]);
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![other])
            .unwrap()
            .with_workspace(
                kan::evidence_workspace::Workspace::open(
                    &local.path().join("rebuilt.sqlite"),
                    identity(7),
                    [92; 32],
                )
                .unwrap(),
            ),
    )
    .await;
    let preview = ui
        .call(
            json!({"action":"restore-annotation","reference":reference}),
            200,
        )
        .await;
    assert_eq!(preview["contract"]["declaration"], saved);
    ui.call(
        json!({"action":"restore-annotation","reference":reference,"preview":"wrong"}),
        400,
    )
    .await;
    let request =
        json!({"action":"restore-annotation","reference":reference,"preview":preview["digest"]});
    let restored = ui.call(request.clone(), 200).await;
    assert_eq!(restored["annotation"]["author"], identity(6).did());
    assert_eq!(restored["annotation"]["id"], saved["id"]);
    assert_eq!(restored["annotation"]["recorded_at"], saved["recorded_at"]);
    assert_eq!(restored["annotation"]["draft"], saved["draft"]);
    assert_eq!(restored["automatic_analysis"], "not-triggered");
    assert_eq!(ui.call(request, 200).await, restored);
    let notes = ui.call(json!({"action":"annotations"}), 200).await;
    assert_eq!(notes["records"].as_array().unwrap().len(), 1);
    let source = ui
        .call(
            json!({"action":"citation-source","cite":cite,"offset":"0","length":"100"}),
            200,
        )
        .await;
    assert_eq!(source["bytes_hex"], service::hex(RAW));
    assert_ne!(source["record"]["selection"], cite["selection"]);
    let mut forged = cite.clone();
    forged["selection"]["signature"] = json!("00".repeat(64));
    ui.call(
        json!({"action":"citation-source","cite":forged,"offset":"0","length":"100"}),
        400,
    )
    .await;
    ui.call(
        json!({"action":"annotation-delivery","id":saved["id"]}),
        403,
    )
    .await;
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![grant()])
        .unwrap();
    assert!(
        ui.call(json!({"action":"annotations"}), 200).await["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    ui.call(
        json!({"action":"citation-source","cite":cite,"offset":"0","length":"100"}),
        403,
    )
    .await;
    ui.stop().await;
    server.stop().await;
}

async fn repository_import_frames(audience: u8, damage: &str) -> (String, Vec<Vec<u8>>) {
    use kan::claim::v1::{ClaimBody, StatusValue};
    use sha2::{Digest, Sha256};
    let (_, _, mut car) = imported_claim_frames(audience);
    let first = atproto_dasl::car::CarReader::new(std::io::Cursor::new(&car))
        .await
        .unwrap()
        .next_block()
        .await
        .unwrap()
        .unwrap();
    let original = atproto_dasl::Cid::from(first.cid);
    let old_root = original.to_string();
    let claim: kan::store::log::StoredClaim = atproto_dasl::from_slice(&first.data).unwrap();
    fn push(car: &mut Vec<u8>, bytes: Vec<u8>) -> atproto_dasl::Cid {
        let cid = atproto_dasl::Cid::from(atproto_repo::compute_cid(&bytes));
        let mut n = cid.to_bytes().len() + bytes.len();
        while n >= 128 {
            car.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        car.push(n as u8);
        car.extend(cid.to_bytes());
        car.extend(bytes);
        cid
    }
    let mut entries = vec![("dev.kan.claim/original".to_string(), original)];
    for (author, status, key) in [
        (6, StatusValue::Blocked, "tools.kan.claim/status-a"),
        (7, StatusValue::Resolved, "tools.kan.claim/status-b"),
        (8, StatusValue::Open, "orphan"),
    ] {
        let mut record = claim.clone();
        record.claim.content.author.did = identity(author).did().to_string();
        record.claim.content.body = ClaimBody::Status { value: status };
        let id = kan::cid::content_cid(&record.claim.content).unwrap();
        record.claim.sig = identity(author).sign(&id.to_bytes()).unwrap();
        let cid = push(&mut car, atproto_dasl::to_vec(&record).unwrap());
        if key != "orphan" {
            entries.push((key.into(), cid));
        }
    }
    let node = kan::mst::MstNode::new(
        entries
            .into_iter()
            .map(|(k, c)| kan::mst::TreeEntry::first(&k, c))
            .collect(),
    );
    let node_bytes = atproto_dasl::to_vec(&node).unwrap();
    let node_cid = if damage == "missing-node" {
        atproto_dasl::Cid::from(atproto_repo::compute_cid(&node_bytes))
    } else {
        push(&mut car, node_bytes)
    };
    let unsigned = atproto_repo::repo::Commit::new_unsigned(
        identity(6).did().to_string(),
        node_cid,
        "3jzfcijpj2z2a".into(),
        None,
    );
    let mut signature = identity(6).sign(&unsigned.to_bytes().unwrap()).unwrap();
    if damage == "bad-signature" {
        signature[0] ^= 1;
    }
    let head = push(&mut car, unsigned.sign(signature).to_bytes().unwrap());
    let head = if damage == "wrong-head" {
        old_root.into_bytes()
    } else {
        head.to_string().into_bytes()
    };
    if damage == "corrupt-tail" {
        car.push(128);
    }
    if damage == "unsupported-block" {
        car.push(37);
        car.extend([1, 0x71, 0x13, 32]);
        car.extend([0; 32]);
        car.push(0);
    }
    let inputs = [("repo.car", car), ("HEAD", head)];
    let files: Vec<_>=inputs.iter().map(|(path,body)|{let hash=service::hex(&Sha256::digest(body));json!({"path":path,"length":body.len(),"sha256":hash,"chunks":[{"length":body.len(),"sha256":hash}]})}).collect();
    let inventory: Vec<_> = files
        .iter()
        .map(|f| json!({"path":f["path"],"length":f["length"],"sha256":f["sha256"]}))
        .collect();
    let document=serde_json::to_vec(&json!({"profile":1,"source_id":service::hex(&[44;32]),"selection":"store","recipient":service::hex(&kan::evidence_crypto::public_key(&PRIVATE).unwrap()),"route":{"scope":service::hex(&[1;32]),"writer":identity(6).did().as_str(),"audience":identity(audience).did().as_str()},"inventory":{"selected_inventory_complete":true,"notices":[],"files":inventory},"files":files})).unwrap();
    let mut hash = Sha256::new();
    hash.update(b"tools.kan.import.plan.v1\0");
    hash.update(&document);
    let plan = service::hex(&hash.finalize());
    let mut frames = Vec::new();
    for (n, (kind, file, body)) in std::iter::once(("inventory", None, document))
        .chain(
            inputs
                .into_iter()
                .enumerate()
                .map(|(i, (_, body))| ("data", Some(i), body)),
        )
        .enumerate()
    {
        let header=serde_json::to_vec(&json!({"version":1,"plan":plan,"ordinal":n,"kind":kind,"file":file,"part":0,"parts":1})).unwrap();
        let mut frame = b"KANI\x01".to_vec();
        frame.extend((header.len() as u32).to_be_bytes());
        frame.extend(header);
        frame.extend(body);
        frames.push(frame);
    }
    (plan, frames)
}
#[tokio::test]
async fn imported_repository_membership_and_trust_fold_preserve_head_boundaries_and_citations() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let (plan, frames) =
            repository_import_frames(if profile == Profile::Admitted { 8 } else { 7 }, "none")
                .await;
        let f = fixture_requests(dir.path(), profile, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], false)
        });
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let page = ui
            .call(
                json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":20}),
                200,
            )
            .await;
        let selections: Vec<_> = page["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["selection"].clone())
            .collect();
        let mut query = json!({"action":"proof-import","source":entry["id"],"pin":entry["pin"],"selections":selections,"plan":plan,"file":0});
        let untrusted = ui.call(query.clone(), 200).await;
        let repo = &untrusted["file"]["car"]["repository"];
        assert_eq!(repo["state"], "membership-verified");
        assert_eq!(repo["records"], 3);
        assert_eq!(repo["fold"]["verified_claims"], 3);
        assert_eq!(repo["fold"]["total_classes"], 0);
        assert_eq!(repo["fold"]["excluded_by_trust"][0]["claims"], 3);
        assert_eq!(repo["commit"]["signature"], "valid-static-did-key");
        assert_eq!(repo["head_sources"][0]["record"]["sequence"], "3");
        assert_eq!(
            untrusted["file"]["car"]["records"][3]["membership"]["state"],
            "not-a-current-record"
        );
        let author6 = json!({"did":identity(6).did().as_str(),"agent":null});
        let author7 = json!({"did":identity(7).did().as_str(),"agent":null});
        query["view"] = json!({"trust":[author6]});
        let solo = ui.call(query.clone(), 200).await;
        assert_eq!(
            solo["file"]["car"]["repository"]["fold"]["classes"][0]["status"]["value"],
            "Blocked"
        );
        query["view"] = json!({"trust":[author6,author7]});
        let peers = ui.call(query.clone(), 200).await;
        let group = &peers["file"]["car"]["repository"]["fold"]["classes"][0];
        assert_eq!(group["status"]["kind"], "contested");
        assert_eq!(group["live_status_claims"].as_array().unwrap().len(), 2);
        let position = group["claims"][0]["source"]["after"].as_u64().unwrap() as usize;
        let record = &peers["file"]["car"]["records"][position];
        assert_eq!(record["id"], group["claims"][0]["id"]);
        assert_eq!(record["membership"]["state"], "reachable");
        assert!(!record["sources"].as_array().unwrap().is_empty());
        let mut no_head = query.clone();
        no_head["selections"] = json!([selections[1], selections[2]]);
        assert_eq!(
            ui.call(no_head, 200).await["file"]["car"]["repository"]["state"],
            "head-unavailable"
        );
        f.remove(2);
        assert_eq!(
            ui.call(query.clone(), 200).await["file"]["car"]["repository"]["state"],
            "head-unavailable"
        );
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(vec![])
            .unwrap();
        ui.call(query, 403).await;
        ui.stop().await;
        server.stop().await;
    }
}
#[tokio::test]
async fn imported_repository_never_falls_back_from_invalid_head_or_partial_tree() {
    for (damage, expected) in [
        ("wrong-head", "commit-invalid"),
        ("bad-signature", "commit-invalid"),
        ("missing-node", "membership-incomplete"),
        ("corrupt-tail", "car-incomplete"),
        ("unsupported-block", "car-incomplete"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (plan, frames) = repository_import_frames(8, damage).await;
        let f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], false)
        });
        let server = Server::start(&f).await;
        let ui =
            Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
                .await;
        let catalog = ui.call(json!({"action":"catalog"}), 200).await;
        let entry = &catalog["scopes"][0];
        let page = ui
            .call(
                json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":20}),
                200,
            )
            .await;
        let selections: Vec<_> = page["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["selection"].clone())
            .collect();
        let value=ui.call(json!({"action":"proof-import","source":entry["id"],"pin":entry["pin"],"selections":selections,"plan":plan,"file":0}),200).await;
        assert_eq!(
            value["file"]["car"]["repository"]["state"], expected,
            "{damage}"
        );
        assert!(value["file"]["car"]["repository"]["fold"].is_null());
        assert_eq!(
            value["file"]["car"]["records"][0]["membership"]["state"],
            "unknown"
        );
        ui.stop().await;
        server.stop().await;
    }
}

#[tokio::test]
async fn owner_access_policy_previews_preserve_history_and_reject_reader_authority_and_stale_edits()
{
    const OWNER: &str = "synthetic-policy-owner-token-123456789";
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let policy_dir = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let policy:kan::evidence_policy::Access=serde_json::from_value(json!({"directory":policy_dir.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer},"owner":identity(9).did().as_str()})).unwrap();
    policy.initialize().unwrap();
    let key = local.path().join("policy-owner.key");
    std::fs::write(&key, [9; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"access-policy","id":"archive-access","policy":policy,"signing_key":key}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    owner_call(
        &ui,
        TOKEN,
        json!({"action":"access","target":"archive-access"}),
        401,
    )
    .await;
    let empty = owner_call(
        &ui,
        OWNER,
        json!({"action":"access","target":"archive-access"}),
        200,
    )
    .await;
    assert_eq!(empty["snapshot"]["changes"], 0);
    let grants = json!([{"principal":identity(6).did().as_str(),"append":true,"inventory":true}]);
    let first = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview-access","target":"archive-access","grants":grants}),
        200,
    )
    .await;
    let stale = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview-access","target":"archive-access","grants":[]}),
        200,
    )
    .await;
    let mut submit = json!({"action":"apply-access","target":"archive-access","change":first["change"],"preview":"wrong"});
    owner_call(&ui, OWNER, submit.clone(), 400).await;
    submit["preview"] = first["digest"].clone();
    let applied = owner_call(&ui, OWNER, submit.clone(), 200).await;
    assert_eq!(applied["state"], "applied");
    assert_eq!(
        owner_call(&ui, OWNER, submit.clone(), 200).await["state"],
        "already-applied"
    );
    owner_call(&ui,OWNER,json!({"action":"apply-access","target":"archive-access","change":stale["change"],"preview":stale["digest"]}),409).await;
    let revoke = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview-access","target":"archive-access","grants":[]}),
        200,
    )
    .await;
    owner_call(&ui,OWNER,json!({"action":"apply-access","target":"archive-access","change":revoke["change"],"preview":revoke["digest"]}),200).await;
    assert_eq!(
        owner_call(&ui, OWNER, submit, 200).await["state"],
        "already-applied"
    );
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    let history = owner_call(
        &ui,
        OWNER,
        json!({"action":"access","target":"archive-access"}),
        200,
    )
    .await;
    assert_eq!(history["snapshot"]["changes"], 2);
    assert_eq!(history["records"][0]["change"]["grants"], grants);
    assert_eq!(
        history["snapshot"]["current"]["change"]["grants"],
        json!([])
    );
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn owner_key_epochs_require_owner_preview_and_restore_wrapped_history_after_restart() {
    const OWNER: &str = "synthetic-key-owner-token-123456789";
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let key_dir = private_workspace_directory();
    let restored_dir = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let history:kan::evidence_keys::Access=serde_json::from_value(json!({"directory":key_dir.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer},"owner":identity(9).did().as_str(),"recovery_recipient":service::hex(&kan::evidence_crypto::public_key(&[83;32]).unwrap())})).unwrap();
    history.initialize().unwrap();
    let mut restored = history.clone();
    restored.directory = restored_dir.path().to_owned();
    restored.initialize().unwrap();
    let signing_key = local.path().join("owner.key");
    let recovery_key = local.path().join("recovery.key");
    for (path, key) in [(&signing_key, [9; 32]), (&recovery_key, [83; 32])] {
        std::fs::write(path, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"key-history","id":"keys","history":history,"signing_key":signing_key,"recovery_key":recovery_key},{"kind":"key-history","id":"restored","history":restored,"signing_key":signing_key,"recovery_key":recovery_key}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    owner_call(&ui, TOKEN, json!({"action":"keys","target":"keys"}), 401).await;
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview-key-rotation","target":"keys"}),
        200,
    )
    .await;
    assert_eq!(history.read().unwrap().history.len(), 0);
    let mut apply = json!({"action":"apply-key-rotation","target":"keys","change":preview["change"],"preview":"wrong"});
    owner_call(&ui, OWNER, apply.clone(), 400).await;
    apply["preview"] = preview["digest"].clone();
    assert_eq!(
        owner_call(&ui, OWNER, apply.clone(), 200).await["state"],
        "applied"
    );
    assert_eq!(
        owner_call(&ui, OWNER, apply, 200).await["state"],
        "already-applied"
    );
    let export = owner_call(
        &ui,
        OWNER,
        json!({"action":"export-keys","target":"keys"}),
        200,
    )
    .await;
    assert_eq!(export["package"]["records"].as_array().unwrap().len(), 1);
    let package = export["package"].clone();
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"restore-keys","target":"restored","package":package,"preview":null}),
        200,
    )
    .await;
    assert!(restored.read().unwrap().history.is_empty());
    owner_call(
        &ui,
        OWNER,
        json!({"action":"restore-keys","target":"restored","package":package,"preview":"wrong"}),
        400,
    )
    .await;
    assert_eq!(owner_call(&ui,OWNER,json!({"action":"restore-keys","target":"restored","package":package,"preview":preview["digest"]}),200).await["state"],"restored");
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    let state = owner_call(
        &ui,
        OWNER,
        json!({"action":"keys","target":"restored"}),
        200,
    )
    .await;
    assert_eq!(state["snapshot"]["epochs"], 1);
    assert_eq!(state["snapshot"]["tip"], export["package"]["tip"]);
    assert_eq!(
        restored.read().unwrap().unlock(&[83; 32]).unwrap(),
        history.read().unwrap().unlock(&[83; 32]).unwrap()
    );
    ui.stop().await;
    server.stop().await;
}
