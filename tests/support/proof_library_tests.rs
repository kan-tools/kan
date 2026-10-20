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
    let first = Server::start_indexed(&admitted).await;
    let second = Server::start_indexed(&copied).await;
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
        let binding = attested::Binding {
            archive: [2; 32],
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        };
        attested::Archive::open(&root, binding.clone())
            .unwrap()
            .rebuild_serving_index(&identity(8))
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
        archive.rebuild_serving_index(&identity(8)).unwrap();
        for (n, frame) in frames.iter().enumerate().skip(3) {
            let previous = Some(
                service::append_manifest(f.requests.last().unwrap())
                    .unwrap()
                    .cid()
                    .to_string(),
            );
            let bytes = encrypted_frame(n as u8, 8, previous, frame);
            archive
                .admit_indexed(&bytes, &identity(8), &grant(), 200 + n as u64, None)
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
    let server = Server::start_initialized(&f).await;
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
    let other_page=ui.call(json!({"action":"proof-page","source":targets[1]["source"],"pin":targets[1]["pin"],"limit":3}),200).await;
    let cross_draft = json!({"subject":"project/cross-host","text":"Cross-archive association","tags":["cross-host"],"relations":[],"cites":[{"source":targets[0]["source"],"pin":targets[0]["pin"],"selection":hit["record"]["selection"]},{"source":targets[1]["source"],"pin":targets[1]["pin"],"selection":other_page["records"][0]["selection"]}],"supersedes":null});
    let preview = ui
        .call(
            json!({"action":"annotation-preview","draft":cross_draft}),
            200,
        )
        .await;
    ui.call(
        json!({"action":"annotation-save","draft":cross_draft,"preview":preview["id"]}),
        200,
    )
    .await;
    let cross_search = json!({"action":"search-page","target":targets[1],"cursor":null,"filter":{"text":"needle","writer":null,"kind":null,"annotation_tag":"cross-host"}});
    assert_eq!(
        ui.call(cross_search.clone(), 200).await["hits"]
            .as_array()
            .unwrap()
            .len(),
        1
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
    assert!(
        ui.call(cross_search, 200).await["hits"]
            .as_array()
            .unwrap()
            .is_empty(),
        "revoked source must hide cross-archive annotation associations"
    );
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
    let target = json!({"source":entry["id"],"pin":entry["pin"]});
    ui.call(
        json!({"action":"index-page","target":target,"cursor":null}),
        200,
    )
    .await;
    let tagged = json!({"action":"search-page","target":target,"cursor":null,"filter":{"text":"","writer":null,"kind":null,"annotation_tag":"decision","annotation_subject":"telos/reliable-recording"}});
    let found = ui.call(tagged.clone(), 200).await;
    assert_eq!(found["hits"].as_array().unwrap().len(), 1);
    assert_eq!(
        found["hits"][0]["record"]["sequence"],
        page["records"][0]["sequence"]
    );
    let mut absent = tagged.clone();
    absent["filter"]["annotation_tag"] = json!("absent");
    assert!(ui.call(absent, 200).await["hits"]
        .as_array()
        .unwrap()
        .is_empty());
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
    assert_eq!(
        ui.call(tagged.clone(), 200).await["hits"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
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
    let withdrawal = json!({"subject":"telos/reliable-recording","text":"Withdrawn: this interpretation was mistaken","tags":[],"cites":[cite(0)],"supersedes":null,"withdraws":preview["id"]});
    for field in ["supersedes", "subject", "derived_from", "tags"] {
        let mut invalid = withdrawal.clone();
        invalid[field] = match field {
            "supersedes" => saved["id"].clone(),
            "subject" => json!("different/subject"),
            "derived_from" => json!(["invented-analysis"]),
            _ => json!(["new-tag"]),
        };
        ui.call(
            json!({"action":"annotation-preview","draft":invalid}),
            if field == "subject" { 403 } else { 400 },
        )
        .await;
    }
    let retract_preview = ui
        .call(
            json!({"action":"annotation-preview","draft":withdrawal}),
            200,
        )
        .await;
    assert_eq!(
        retract_preview["declaration"]["draft"]["cites"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        retract_preview["declaration"]["analysis_trigger_plan"],
        json!([])
    );
    let retract = ui
        .call(
            json!({"action":"annotation-save","draft":withdrawal,"preview":retract_preview["id"]}),
            200,
        )
        .await;
    assert_eq!(
        retract,
        ui.call(
            json!({"action":"annotation-save","draft":withdrawal,"preview":retract_preview["id"]}),
            200
        )
        .await
    );
    let history = ui
        .call(
            json!({"action":"annotations","subject":null,"tag":"corrected"}),
            200,
        )
        .await;
    assert_eq!(history["records"].as_array().unwrap().len(), 1);
    assert_eq!(
        history["withdrawals"][preview["id"].as_str().unwrap()],
        json!([retract["id"]])
    );
    let graph = ui
        .call(
            json!({"action":"knowledge-graph","subject":"telos/reliable-recording","day":false}),
            200,
        )
        .await;
    assert_eq!(graph["records"].as_array().unwrap().len(), 3);
    assert_eq!(graph["relations"].as_array().unwrap().len(), 2);
    let edge = graph["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "DependsOn")
        .unwrap();
    assert_eq!(edge["withdrawn_by"], json!([retract["id"]]));
    // A withdrawal labels history; it does not erase old search associations.
    assert_eq!(
        ui.call(tagged, 200).await["hits"].as_array().unwrap().len(),
        2
    );
    let mut recursive = withdrawal.clone();
    recursive["withdraws"] = retract["id"].clone();
    ui.call(
        json!({"action":"annotation-preview","draft":recursive}),
        400,
    )
    .await;
    assert_eq!(
        ui.call(
            json!({"action":"annotation-triggers","id":retract["id"],"retry":true}),
            200
        )
        .await["attempts"],
        json!([])
    );
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
    ui.call(
        json!({"action":"annotation-preview","draft":withdrawal}),
        403,
    )
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
    let custody = private_workspace_directory();
    let mut history:kan::evidence_erasure_history::Access=serde_json::from_value(json!({"directory":custody.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer},"owner":identity(9).did().as_str()})).unwrap();
    history.initialize().unwrap();
    let genesis = kan::evidence_erasure_history::Record::sign(
        history.preview(None, "a".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(minimum);

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
    let readers = |histories| {
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(
                kan::evidence_workspace::Workspace::open(
                    &local.path().join("workspace.sqlite"),
                    identity(6),
                    [97; 32],
                )
                .unwrap()
                .with_erasure_histories(histories)
                .unwrap(),
            )
            .with_annotation_outbox(
                kan::evidence_library::AnnotationOutbox::new(
                    spool.clone(),
                    endpoint.clone(),
                    recipient,
                )
                .unwrap(),
            )
            .unwrap()
    };
    let ui = Ui::start(readers(vec![history.clone()])).await;
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
    let other_custody = private_workspace_directory();
    let mut incomplete: kan::evidence_erasure_history::Access = serde_json::from_value(json!({
        "directory":other_custody.path(),"binding":{"profile":"admitted","archive":service::hex(&binding.archive),"scope":service::hex(&binding.scope),"issuer":binding.issuer},"owner":identity(9).did().as_str()
    })).unwrap();
    incomplete.initialize().unwrap();
    let genesis = kan::evidence_erasure_history::Record::sign(
        incomplete.preview(None, "c".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    incomplete.append(genesis).unwrap();
    incomplete.minimum = Some(minimum);
    let partially_enrolled = Ui::start(readers(vec![incomplete])).await;
    partially_enrolled
        .call(
            json!({"action":"annotation-drain","destination":status["destination_digest"]}),
            403,
        )
        .await;
    assert_eq!(
        attested::Archive::open(remote.path(), binding.clone())
            .unwrap()
            .verify()
            .unwrap()
            .through,
        0,
        "an enrolled publisher cannot send a source missing from its custody configuration"
    );
    assert_eq!(
        kan::evidence_spool::Spool::open(&spool)
            .unwrap()
            .head()
            .unwrap()
            .as_ref(),
        Some(&before)
    );
    partially_enrolled.stop().await;
    let guard = kan::evidence_workspace::Workspace::open(
        &local.path().join("workspace.sqlite"),
        identity(6),
        [97; 32],
    )
    .unwrap()
    .with_erasure_histories(vec![history.clone()])
    .unwrap();
    assert!(guard.authorize_publication(&before).is_ok());
    let mut substituted = service::SignedRequest::decode(&before).unwrap().request;
    let service::Command::Append { ciphertext, .. } = &mut substituted.command else {
        unreachable!()
    };
    *ciphertext = service::hex(b"same operation, different signed ciphertext");
    let substituted = service::SignedRequest::sign(substituted, &identity(6))
        .unwrap()
        .bytes()
        .unwrap();
    assert!(
        guard.authorize_publication(&substituted).is_err(),
        "operation IDs cannot authorize a substituted request"
    );
    assert!(
        kan::evidence_workspace::Workspace::open(
            &local.path().join("workspace.sqlite"),
            identity(6),
            [97; 32]
        )
        .unwrap()
        .authorize_publication(&before)
        .is_err(),
        "standalone publication requires independent source enrollment"
    );
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
    let initial_queue = local.path().join("initial-queue.sqlite");
    std::fs::copy(&spool, &initial_queue).unwrap();
    {
        let mut sender = kan::evidence_spool::Spool::open(&spool).unwrap();
        assert!(
            kan::evidence_delivery::deliver_with_workspace(&mut sender, &endpoint, &guard)
                .await
                .unwrap()
                .is_some()
        );
    }
    // A pre-ACK restored queue may retry the identical authorized request;
    // the Library also uses the authenticated exact-request source binding.
    std::fs::copy(&initial_queue, &spool).unwrap();
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
        attested::Archive::open(remote.path(), binding.clone())
            .unwrap()
            .verify()
            .unwrap()
            .through,
        1
    );
    // Queuing while readable does not authorize a later send after source erasure.
    let mut later = draft.clone();
    later["text"] = json!("Queued derivative must be withheld when its source is erased");
    let preview = ui
        .call(json!({"action":"annotation-preview","draft":later}), 200)
        .await;
    let saved = ui
        .call(
            json!({"action":"annotation-save","draft":later,"preview":preview["id"]}),
            200,
        )
        .await;
    ui.call(json!({"action":"annotation-queue","id":saved["id"],"destination":status["destination_digest"]}),200).await;
    let retained = kan::evidence_spool::Spool::open(&spool)
        .unwrap()
        .head()
        .unwrap()
        .unwrap();
    let old_workspace = local.path().join("workspace-before.sqlite");
    std::fs::copy(local.path().join("workspace.sqlite"), &old_workspace).unwrap();
    let old_queue = local.path().join("queue-before.sqlite");
    std::fs::copy(&spool, &old_queue).unwrap();
    let signing = local.path().join("sender.key");
    let recipient_key = local.path().join("workspace.key");
    for (path, key) in [(&signing, [6; 32]), (&recipient_key, [97; 32])] {
        std::fs::write(path, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let config = local.path().join("publication-guard.json");
    std::fs::write(&config,serde_json::to_vec(&json!({"database":old_workspace,"signing_key":signing,"recipient_key":recipient_key,"sources":[history]})).unwrap()).unwrap();
    let destination_custody = private_workspace_directory();
    let mut destination: kan::evidence_erasure_history::Access = serde_json::from_value(json!({
        "directory":destination_custody.path(),"binding":{"profile":"admitted","archive":service::hex(&binding.archive),"scope":service::hex(&binding.scope),"issuer":binding.issuer},"owner":identity(9).did().as_str()
    })).unwrap();
    destination.initialize().unwrap();
    let genesis = kan::evidence_erasure_history::Record::sign(
        destination.preview(None, "d".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    destination.append(genesis).unwrap();
    destination.minimum = Some(minimum);
    let destination_file = local.path().join("destination-custody.json");
    std::fs::write(&destination_file, serde_json::to_vec(&destination).unwrap()).unwrap();
    let deployment = local.path().join("deployment.json");
    std::fs::write(&deployment,serde_json::to_vec(&json!({"version":1,
        "workspaces":[{"database":old_workspace,"guard":config}],
        "spools":[{"database":old_queue,"history":destination_file,"kind":"annotation","publication_guard":config}]
    })).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [&config, &destination_file, &deployment] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let managed_head = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("--deployment")
        .arg(&deployment)
        .arg("spool-head")
        .arg(&old_queue)
        .output()
        .unwrap();
    assert!(
        managed_head.status.success(),
        "{}",
        String::from_utf8_lossy(&managed_head.stderr)
    );
    assert_eq!(
        managed_head.stdout, retained,
        "managed launch supplies destination and source guards"
    );
    for wrong_queue in [&spool, &local.path().join("unregistered.sqlite")] {
        let denied = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .arg("--deployment")
            .arg(&deployment)
            .arg("spool-head")
            .arg(wrong_queue)
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert!(denied.stdout.is_empty());
    }
    let override_guard = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("--deployment")
        .arg(&deployment)
        .arg("spool-head")
        .arg(&old_queue)
        .arg("--publication-guard")
        .arg(local.path().join("another-guard.json"))
        .output()
        .unwrap();
    assert!(!override_guard.status.success());
    assert!(override_guard.stdout.is_empty());
    let mut source = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    let sequence = page["records"][0]["sequence"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let plan = source
        .preview_erasure(&[sequence], service::hex(&[74; 32]), 2000)
        .unwrap();
    let erasure = store::erasure::Record::sign(plan, &identity(8)).unwrap();
    let authorization = kan::evidence_erasure_history::Record::sign(
        history
            .preview(Some(erasure.clone()), "b".repeat(64))
            .unwrap(),
        &identity(9),
    )
    .unwrap();
    history.append(authorization.clone()).unwrap();
    // Independent custody fences the standalone sender before physical deletion.
    let mut sender = kan::evidence_spool::Spool::open(&spool).unwrap();
    assert!(
        kan::evidence_delivery::deliver_with_workspace(&mut sender, &endpoint, &guard)
            .await
            .is_err()
    );
    assert_eq!(sender.head().unwrap().as_ref(), Some(&retained));
    drop(sender);
    for action in ["spool-head", "spool-drain"] {
        for (flag, file) in [
            ("--publication-guard", &config),
            ("--deployment", &deployment),
        ] {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"));
            command.arg(action).arg(&old_queue).arg(flag).arg(file);
            if action == "spool-drain" {
                command.arg("--endpoint").arg(&endpoint);
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "old workspace/queue restore cannot publish erased sources"
            );
            assert!(
                output.stdout.is_empty(),
                "raw request must not leak through guarded export"
            );
        }
    }
    source.apply_erasure(erasure.clone()).unwrap();
    ui.call(
        json!({"action":"annotation-drain","destination":status["destination_digest"]}),
        403,
    )
    .await;
    assert_eq!(
        kan::evidence_spool::Spool::open(&spool)
            .unwrap()
            .head()
            .unwrap()
            .as_ref(),
        Some(&retained)
    );
    assert_eq!(
        attested::Archive::open(remote.path(), binding)
            .unwrap()
            .verify()
            .unwrap()
            .through,
        1,
        "erased derivative was not published"
    );
    ui.stop().await;
    drop(guard);
    {
        let clean = kan::evidence_workspace::Workspace::open_for_erasure(
            &local.path().join("workspace.sqlite"),
            identity(6),
            [97; 32],
        )
        .unwrap();
        let plan = clean
            .preview_source_erasure(&history.binding, &erasure, authorization.id().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.targets
                .iter()
                .filter(|t| t.kind == "annotation-publication")
                .count(),
            2,
            "publication bindings join source dependency cleanup"
        );
        clean.apply_erasure(&plan).unwrap();
        clean.reclaim_erased_pages().unwrap();
    }
    let clean = kan::evidence_workspace::Workspace::open(
        &local.path().join("workspace.sqlite"),
        identity(6),
        [97; 32],
    )
    .unwrap()
    .with_erasure_histories(vec![history.clone()])
    .unwrap();
    let manifest = service::append_manifest(&retained)
        .unwrap()
        .cid()
        .to_string();
    assert!(clean
        .get("annotation-publication", &manifest)
        .unwrap()
        .is_none());
    assert!(
        clean
            .put(
                "annotation-publication",
                &manifest,
                json!({"version":1,"annotation":saved["id"],"manifest":manifest})
            )
            .is_err(),
        "removed sender binding cannot be reintroduced"
    );
    assert!(clean.authorize_publication(&retained).is_err());
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

#[tokio::test]
async fn owner_backup_purge_is_exact_scoped_and_resumes_staged_copies() {
    const OWNER: &str = "synthetic-owner-backup-purge-token";
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let output = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":2,"targets":[
            {"kind":"archive","id":"archive","root":f.root,"output":output.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer}}
        ]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"archive","operation":"backup"}),
        200,
    )
    .await;
    let backup=owner_call(&ui,OWNER,json!({"action":"submit","target":"archive","operation":"backup","nonce":preview["nonce"],"preview":preview["digest"],"wait":true}),200).await;
    assert_eq!(backup["state"], "succeeded");
    let file = PathBuf::from(backup["result"]["report"]["destination"].as_str().unwrap());
    let original = std::fs::read(&file).unwrap();
    let query = json!({"action":"preview-backup-purge","backup_job":backup["job"]["id"]});
    owner_call(&ui, TOKEN, query.clone(), 401).await;
    let preview = owner_call(&ui, OWNER, query.clone(), 200).await;
    assert_eq!(
        std::fs::read(&file).unwrap(),
        original,
        "preview deletes nothing"
    );
    let request = json!({"action":"apply-backup-purge","plan":preview["plan"],"preview":preview["digest"],"wait":true});
    let mut forged = request.clone();
    forged["plan"]["database"] = json!(f.db());
    owner_call(&ui, OWNER, forged, 400).await;
    // A valid but changed snapshot at the same path invalidates the exact preview.
    let previous = service::append_manifest(f.requests.last().unwrap())
        .unwrap()
        .cid()
        .to_string();
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .admit(
            &encrypted(3, 8, Some(previous)),
            &identity(8),
            &grant(),
            200,
        )
        .unwrap();
    let other = output.path().join("independent.sqlite");
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .backup(&other)
        .unwrap();
    std::fs::write(&file, std::fs::read(&other).unwrap()).unwrap();
    owner_call(&ui, OWNER, request.clone(), 409).await;
    assert!(file.exists());
    std::fs::write(&file, &original).unwrap();
    // An occupied staging namespace cannot be overwritten or recursively removed.
    let stage = output.path().join(format!(
        ".kan-purge-{}",
        preview["digest"].as_str().unwrap()
    ));
    std::fs::create_dir(&stage).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let foreign = stage.join("unexpected");
    std::fs::write(&foreign, b"retain unknown bytes").unwrap();
    let blocked = owner_call(&ui, OWNER, request.clone(), 200).await;
    assert_eq!(blocked["state"], "purge-pending", "{blocked}");
    assert_eq!(std::fs::read(&file).unwrap(), original);
    assert_eq!(std::fs::read(&foreign).unwrap(), b"retain unknown bytes");
    std::fs::remove_file(&foreign).unwrap();
    let done = owner_call(&ui, OWNER, request.clone(), 200).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(
        done["result"]["report"]["backup_purge"],
        "removed-configured-copy"
    );
    assert!(!file.exists());
    assert!(!stage.join("backup.sqlite").exists());
    assert_eq!(
        owner_call(&ui, OWNER, request, 200).await,
        done,
        "lost acknowledgment does not repeat deletion"
    );
    assert_eq!(
        attested::Archive::verify_file(&f.db(), f.binding.clone())
            .unwrap()
            .commits,
        4
    );
    assert_eq!(
        attested::Archive::verify_file(&other, f.binding.clone())
            .unwrap()
            .commits,
        4
    );
    // Reproduce interruption after durable authorization and relocation, before removal.
    let snapshot = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"archive","operation":"backup"}),
        200,
    )
    .await;
    let backup=owner_call(&ui,OWNER,json!({"action":"submit","target":"archive","operation":"backup","nonce":snapshot["nonce"],"preview":snapshot["digest"],"wait":true}),200).await;
    let preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview-backup-purge","backup_job":backup["job"]["id"]}),
        200,
    )
    .await;
    ui.stop().await;
    {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        workspace
            .put(
                "owner-job",
                preview["digest"].as_str().unwrap(),
                json!({"id":preview["digest"],"contract":preview["contract"],"started_at":"200"}),
            )
            .unwrap();
        for n in 0..33 {
            workspace
                .put(
                    "owner-result",
                    &format!(
                        "backup-purge:{}:{n}:started",
                        preview["digest"].as_str().unwrap()
                    ),
                    json!({"job":preview["digest"],"attempt":n}),
                )
                .unwrap();
        }
    }
    let staged_dir = output.path().join(format!(
        ".kan-purge-{}",
        preview["digest"].as_str().unwrap()
    ));
    std::fs::create_dir(&staged_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let staged = staged_dir.join("backup.sqlite");
    std::fs::rename(preview["plan"]["database"].as_str().unwrap(), &staged).unwrap();
    let ui = Ui::start(readers()).await;
    let resumed=owner_call(&ui,OWNER,json!({"action":"apply-backup-purge","plan":preview["plan"],"preview":preview["digest"],"wait":true}),200).await;
    assert_eq!(resumed["state"], "succeeded", "{resumed}");
    assert!(!staged.exists());
    assert_eq!(resumed["attempts"], 34);
    let catalog = owner_call(&ui, OWNER, json!({"action":"catalog"}), 200).await;
    assert_eq!(catalog["jobs"].as_array().unwrap().len(), 2);
    assert!(catalog["next"].is_string());
    let second = owner_call(
        &ui,
        OWNER,
        json!({"action":"catalog","after":catalog["next"]}),
        200,
    )
    .await;
    assert_eq!(second["jobs"].as_array().unwrap().len(), 2);
    assert!(second["next"].is_null());
    let ids = catalog["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["jobs"].as_array().unwrap())
        .map(|j| j["job"]["id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        4,
        "pagination retains every historical job without duplicates"
    );
    owner_call(
        &ui,
        OWNER,
        json!({"action":"catalog","after":"invalid"}),
        400,
    )
    .await;
    assert_eq!(
        attested::Archive::verify_file(&other, f.binding.clone())
            .unwrap()
            .commits,
        4
    );
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
    if damage == "current" {
        use kan::claim::{
            CanonicalSet, Claim, ClaimContent, RecordedAt, SubjectPath, UniqueSequence,
        };
        use kan::identity::{authorship::Author, control::IdentityVersion};
        let (inception, _) = current_import_scope();
        for author in [6, 7] {
            let signer = identity(author);
            let did = signer.did();
            let content = ClaimContent::new(
                Author::new(
                    did.clone(),
                    format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
                    IdentityVersion::Static,
                )
                .unwrap(),
                inception.scope_id().unwrap(),
                None,
                SubjectPath::new("v2/current".into()).unwrap(),
                CanonicalSet::new(vec![]).unwrap(),
                kan::claim::ClaimBody::Status {
                    value: if author == 6 {
                        kan::claim::StatusValue::Blocked
                    } else {
                        kan::claim::StatusValue::Resolved
                    },
                },
                CanonicalSet::new(vec![]).unwrap(),
                UniqueSequence::new(vec![]).unwrap(),
                RecordedAt::new(100).unwrap(),
            )
            .unwrap();
            let claim = Claim::sign_static(content, &signer).unwrap();
            let bytes = kan::claim::codec::encode_claim(&claim, "3jzfcijpj2z2a").unwrap();
            entries.push((
                format!("tools.kan.claim/current-{author}"),
                push(&mut car, bytes),
            ));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
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
    let repair = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"archive-access","operation":"rebuild-control-index"}),
        200,
    )
    .await;
    let repaired = owner_call(&ui, OWNER, json!({"action":"submit","target":"archive-access","operation":"rebuild-control-index","nonce":repair["nonce"],"preview":repair["digest"],"wait":true}), 200).await;
    assert_eq!(repaired["state"], "succeeded");
    assert!(policy.current().unwrap().grants().unwrap()[0].inventory);

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
    assert!(policy.current().unwrap().grants().unwrap().is_empty());
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
    let origin = ui.url.trim_end_matches("/api/library");
    for (credential, status) in [(TOKEN, 403), (OWNER, 200)] {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{origin}/api/owner/download"))
            .header("origin", origin)
            .header("content-type", "text/plain")
            .body(format!(
                "payload={}\r\n",
                json!({"token":credential,"package":package})
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == 200 {
            assert_eq!(
                response.headers()["content-disposition"],
                "attachment; filename=\"kan-wrapped-key-recovery.json\""
            );
            assert_eq!(response.json::<Value>().await.unwrap(), package);
        }
    }
    let inspected = owner_call(&ui, OWNER, json!({"action":"keys","target":"keys"}), 200).await;
    let request = json!({"action":"preview-key-transfer","target":"keys","recipient":service::hex(&kan::evidence_crypto::public_key(&[85;32]).unwrap()),"epochs":inspected["epoch_ids"],"purpose":"replace-recovery"});
    owner_call(&ui, TOKEN, request.clone(), 401).await;
    let transfer = owner_call(&ui, OWNER, request, 200).await;
    assert!(transfer.get("package").is_none());
    let exported=owner_call(&ui,OWNER,json!({"action":"apply-key-transfer","target":"keys","plan":transfer["plan"],"preview":transfer["digest"]}),200).await;
    let transferred: kan::evidence_keys::RecoveryPackage =
        serde_json::from_value(exported["package"].clone()).unwrap();
    assert_eq!(
        transferred.records[0].change.unlock(&[85; 32]).unwrap(),
        history.read().unwrap().unlock(&[83; 32]).unwrap()[0]
    );
    assert!(transferred.records[0].change.unlock(&[83; 32]).is_err());
    assert_eq!(
        history.read().unwrap().tip.as_deref(),
        package["tip"].as_str()
    );
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

fn current_import_scope() -> (
    kan::identity::scope_inception::ScopeInception,
    kan::identity::control::ControlEvent,
) {
    use kan::identity::{
        control::{IdentityVersion, Proof},
        scope_inception::ScopeInception,
    };
    let root = identity(6);
    let inception =
        ScopeInception::new([27; 32], vec!["current".into()], vec![root.did()], vec![]).unwrap();
    let input = inception.signing_input().unwrap();
    let did = root.did();
    let proof = Proof {
        method: format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
        controller_state: IdentityVersion::Static,
        alg: "P256".into(),
        sig: root.sign(&input.canonical_bytes().unwrap()).unwrap(),
    };
    let event = inception.proved_event(vec![proof]).unwrap();
    (inception, event)
}
#[tokio::test]
async fn imported_current_claims_keep_signature_scope_authority_and_selected_trust_distinct() {
    for damaged in [false, true] {
        let dir = private_workspace_directory();
        let (plan, frames) = repository_import_frames(8, "current").await;
        let f = fixture_requests(dir.path(), Profile::Admitted, |n, a, p| {
            import_request(n, a, p, &plan, &frames[n as usize], false)
        });
        let (_, mut control) = current_import_scope();
        if damaged {
            control.proofs[0].sig[0] ^= 1;
        }
        let previous = Some(
            service::append_manifest(f.requests.last().unwrap())
                .unwrap()
                .cid()
                .to_string(),
        );
        let control_bytes = encrypted_frame(3, 8, previous, &control.canonical_bytes().unwrap());
        let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
        archive
            .admit(&control_bytes, &identity(8), &grant(), 200)
            .unwrap();
        drop(archive);
        let server = Server::start(&f).await;
        let local = private_workspace_directory();
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
        let page = ui
            .call(
                json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":20}),
                200,
            )
            .await;
        let rows = page["records"].as_array().unwrap();
        let selections = rows
            .iter()
            .filter(|r| r["sequence"] != "4")
            .map(|r| r["selection"].clone())
            .collect::<Vec<_>>();
        let control = rows.iter().find(|r| r["sequence"] == "4").unwrap();
        let mut query = json!({"action":"proof-import","source":entry["id"],"pin":entry["pin"],"selections":selections,"plan":plan,"file":0,"view":{"principals":[identity(6).did(),identity(7).did()]}});
        let absent = ui.call(query.clone(), 200).await;
        let current = &absent["file"]["car"]["repository"]["current"];
        assert_eq!(current["verified_claims"], 2);
        assert_eq!(current["classes"][0]["status"]["kind"], "unclassified");
        assert!(current["classes"][0]["claims"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["judgments"]["cryptographicValidity"] == "valid"
                && c["judgments"]["scopeAdmission"] == "unknown"));
        query["view"]["controls"] = json!([{"parts":[{"source":entry["id"],"pin":entry["pin"],"selection":control["selection"]}]}]);
        let resolved = ui.call(query.clone(), 200).await;
        let current = &resolved["file"]["car"]["repository"]["current"];
        assert_eq!(
            current["controls"][0]["sources"][0]["record"]["sequence"],
            "4"
        );
        if damaged {
            assert_eq!(current["classes"][0]["status"]["kind"], "unclassified");
        } else {
            assert_eq!(current["classes"][0]["status"]["value"], "blocked");
            assert_eq!(
                current["classes"][0]["live_status_claims"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        if !damaged {
            let mut save = query.clone();
            save["action"] = json!("save-import-view");
            save["name"] = json!("Pinned current claim authority");
            let saved = ui.call(save.clone(), 200).await;
            assert_eq!(saved["kind"], "import");
            assert_eq!(
                saved["query"]["view"]["principals"],
                query["view"]["principals"]
            );
            assert_eq!(ui.call(save.clone(), 200).await, saved);
            assert_eq!(
                ui.call(json!({"action":"views"}), 200).await["views"][0],
                saved
            );
            let mut replay = saved["query"].clone();
            replay["action"] = json!("proof-import");
            assert_eq!(
                ui.call(replay, 200).await["file"]["car"]["repository"]["current"]["classes"],
                current["classes"]
            );
            save["view"]["principals"] = json!([]);
            assert_ne!(ui.call(save, 200).await["id"], saved["id"]);
        }
        query["view"]["principals"] = json!([]);
        assert_eq!(
            ui.call(query.clone(), 200).await["file"]["car"]["repository"]["current"]
                ["total_classes"],
            0
        );
        server
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
        ui.stop().await;
        server.stop().await;
    }
}

/// One cold-host drill composes the independently backed-up archive, wrapped
/// epoch history and encrypted reader state. No original path survives restart.
#[tokio::test]
async fn cold_host_restores_source_search_annotations_and_references_from_independent_backups() {
    use kan::{evidence_crypto as crypto, evidence_keys as keys, evidence_workspace::Workspace};
    let original = private_workspace_directory();
    let key_dir = private_workspace_directory();
    let local = private_workspace_directory();
    let backup = private_workspace_directory();
    let independent_custody = private_workspace_directory();
    let restored_keys = private_workspace_directory();
    let restored_data = private_workspace_directory();
    let recovered_local = private_workspace_directory();
    let binding = wire::Binding {
        profile: wire::Profile::Admitted,
        archive: service::hex(&[2; 32]),
        scope: service::hex(&[1; 32]),
        issuer: identity(8).did().to_string(),
    };
    let history = keys::Access {
        directory: key_dir.path().to_owned(),
        binding,
        owner: identity(9).did().to_string(),
        recovery_recipient: service::hex(&crypto::public_key(&[92; 32]).unwrap()),
        minimum: None,
    };
    // Current owner custody is independently retained, never selected from the
    // archive or workspace being restored.
    let mut custody = kan::evidence_erasure_history::Access {
        directory: independent_custody.path().to_owned(),
        binding: history.binding.clone(),
        owner: identity(9).did().to_string(),
        minimum: None,
    };
    custody.initialize().unwrap();
    let genesis = kan::evidence_erasure_history::Record::sign(
        custody.preview(None, "d".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    custody.append(genesis).unwrap();
    custody.minimum = Some(minimum);
    history.initialize().unwrap();
    let change = history.preview(service::hex(&[1; 32])).unwrap();
    let recipient = crypto::public_key(&change.unlock(&[92; 32]).unwrap()).unwrap();
    history
        .append(keys::Record::sign(change, &identity(9)).unwrap())
        .unwrap();
    let f = fixture_requests(
        original.path(),
        Profile::Admitted,
        |n, audience, previous| {
            let mut req = service::SignedRequest::decode(&request(n, audience, previous))
                .unwrap()
                .request;
            let service::Command::Append { ciphertext, .. } = &mut req.command else {
                unreachable!()
            };
            *ciphertext = service::hex(
                &crypto::seal(
                    &recipient,
                    &[1; 32],
                    b"Cold recovery needle: retained exact source.",
                )
                .unwrap(),
            );
            service::SignedRequest::sign(req, &identity(6))
                .unwrap()
                .bytes()
                .unwrap()
        },
    );
    let key_file = local.path().join("recovery.key");
    std::fs::write(&key_file, [92; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = Server::start(&f).await;
    let r = client::Reader::new(
        identity(6),
        client::Access {
            binding: history.binding.clone(),
            endpoint: server.endpoint.clone(),
            private_key: [0; 32],
        },
    )
    .unwrap()
    .with_epochs(keys::ReaderAccess {
        history: history.clone(),
        recovery_key: key_file,
    })
    .unwrap();
    let workspace = local.path().join("workspace.sqlite");
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![r])
            .unwrap()
            .with_workspace(Workspace::open(&workspace, identity(6), [97; 32]).unwrap()),
    )
    .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let target = json!({"source":entry["id"],"pin":entry["pin"]});
    let page=ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":3}),200).await;
    let cite = json!({"source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"]});
    let source=ui.call(json!({"action":"proof-source","source":cite["source"],"pin":cite["pin"],"selection":cite["selection"],"offset":"0","length":"100"}),200).await;
    let reference = source["reference"].clone();
    let indexed = ui
        .call(
            json!({"action":"index-page","target":target,"cursor":null}),
            200,
        )
        .await;
    assert_eq!(indexed["indexed_occurrences"], 3);
    let filter = json!({"text":"needle","writer":null,"kind":"opaque"});
    ui.call(json!({"action":"save-view","name":"Recovery checkpoint","targets":[target],"filter":filter}),200).await;
    let draft = json!({"subject":"telos/recoverable-memory","text":"Retain independent custody","tags":["decision"],"relations":[],"cites":[cite],"supersedes":null});
    let preview = ui
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    let note = ui
        .call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200,
        )
        .await;
    ui.stop().await;
    server.stop().await;
    let archive_backup = backup.path().join("evidence.sqlite");
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .backup(&archive_backup)
        .unwrap();
    let workspace_backup = backup.path().join("workspace.sqlite");
    Workspace::recover(&workspace, &workspace_backup, identity(6), [97; 32]).unwrap();
    let epochs = history
        .read()
        .unwrap()
        .history
        .iter()
        .map(|r| r.id().unwrap())
        .collect();
    let transfer = history
        .preview_transfer(
            service::hex(&crypto::public_key(&[93; 32]).unwrap()),
            epochs,
            keys::TransferPurpose::ReplaceRecovery,
        )
        .unwrap();
    let key_backup = backup.path().join("wrapped-keys.json");
    std::fs::write(
        &key_backup,
        serde_json::to_vec(
            &history
                .transfer(
                    &transfer,
                    &transfer.digest().unwrap(),
                    &[92; 32],
                    &identity(9),
                )
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    // The synthetic source machine is gone. Only independent artifacts and
    // separately held credentials are used by the newly configured instance.
    drop(original);
    drop(local);
    drop(key_dir);
    assert!(!workspace.exists());
    assert!(!f.db().exists());
    assert!(!history.directory.exists());
    let package: keys::RecoveryPackage =
        serde_json::from_slice(&std::fs::read(key_backup).unwrap()).unwrap();
    let mut recovered_history = history.clone();
    recovered_history.directory = restored_keys.path().to_owned();
    recovered_history.recovery_recipient = service::hex(&crypto::public_key(&[93; 32]).unwrap());
    recovered_history.minimum = package.tip.clone();
    recovered_history.initialize().unwrap();
    recovered_history.restore(&package).unwrap();
    let new_key = recovered_local.path().join("recovery.key");
    std::fs::write(&new_key, [93; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let restored_root = restored_data.path().join("archive");
    std::fs::create_dir(&restored_root).unwrap();
    attested::Recovery::open(&archive_backup, f.binding.clone())
        .unwrap()
        .rebuild(&restored_root.join("archive.sqlite"))
        .unwrap();
    let restored = Fixture {
        root: restored_root,
        binding: f.binding.clone(),
        requests: f.requests,
        profile: Profile::Admitted,
    };
    let restored_workspace = recovered_local.path().join("workspace.sqlite");
    Workspace::recover(
        &workspace_backup,
        &restored_workspace,
        identity(6),
        [97; 32],
    )
    .unwrap();
    let server = Server::start(&restored).await;
    let r = client::Reader::new(
        identity(6),
        client::Access {
            binding: recovered_history.binding.clone(),
            endpoint: server.endpoint.clone(),
            private_key: [0; 32],
        },
    )
    .unwrap()
    .with_epochs(keys::ReaderAccess {
        history: recovered_history.clone(),
        recovery_key: new_key.clone(),
    })
    .unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = recovered_local.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let signing = recovered_local.path().join("reader-signing.key");
    identity(6).save(&signing).unwrap();
    let workspace_key = write("workspace.key", &[97; 32]);
    let fixed_key = write("fixed.key", &[0; 32]);
    let custody_file = write("custody.json", &serde_json::to_vec(&custody).unwrap());
    let guard = write("guard.json", &serde_json::to_vec(&json!({
        "database":restored_workspace,"signing_key":signing,"recipient_key":workspace_key,"sources":[custody]
    })).unwrap());
    let deployment = write(
        "deployment.json",
        &serde_json::to_vec(&json!({"version":1,
            "archives":[{"root":restored.root,"history":custody_file}],
            "workspaces":[{"database":restored_workspace,"guard":guard}]
        }))
        .unwrap(),
    );
    let config = write(
        "reader.json",
        &serde_json::to_vec(&json!([{
            "scope":recovered_history.binding.scope,"issuer":recovered_history.binding.issuer,
            "profile":"admitted","archive":recovered_history.binding.archive,
            "protocol":wire::PROTOCOL,"endpoint":server.endpoint,"private_key_file":fixed_key,
            "epoch_keys":{"history":recovered_history,"recovery_key":new_key}
        }]))
        .unwrap(),
    );
    let request = write(
        "request.json",
        &serde_json::to_vec(&json!({"action":"resolve-reference","reference":reference})).unwrap(),
    );
    let managed = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"));
        command
            .arg("--deployment")
            .arg(&deployment)
            .arg("library")
            .arg("--config")
            .arg(&config)
            .arg("--signing-key")
            .arg(&signing)
            .arg("--workspace")
            .arg(&restored_workspace)
            .arg("--workspace-key")
            .arg(&workspace_key)
            .arg("--request")
            .arg(&request)
            .kill_on_drop(true);
        command
    };
    let activated = tokio::time::timeout(Duration::from_secs(30), managed().output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        activated.status.success(),
        "{}",
        String::from_utf8_lossy(&activated.stderr)
    );
    let activated: Value = serde_json::from_slice(&activated.stdout).unwrap();
    assert_eq!(activated["reference"], reference);
    assert_eq!(
        activated["record"]["manifest"],
        page["records"][0]["manifest"]
    );
    assert_eq!(activated["record"]["availability"], "available");
    // Prepare exact custody while the restored archive is still intact. Publish
    // only after the reader has stopped, simulating independent owner activity
    // between a backup and a later activation.
    let erasure = attested::Archive::open(&restored.root, restored.binding.clone())
        .unwrap()
        .preview_erasure(&[1, 2, 3], "e".repeat(64), 100)
        .unwrap();
    let erasure = kan::evidence_store::erasure::Record::sign(erasure, &identity(8)).unwrap();
    let erase = kan::evidence_erasure_history::Record::sign(
        custody.preview(Some(erasure), "f".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let ui = Ui::start(
        kan::evidence_library::Readers::new(None, vec![r])
            .unwrap()
            .with_workspace(Workspace::open(&restored_workspace, identity(6), [97; 32]).unwrap()),
    )
    .await;
    let resolved = ui
        .call(
            json!({"action":"resolve-reference","reference":reference}),
            200,
        )
        .await;
    let read=ui.call(json!({"action":"proof-source","source":resolved["source"],"pin":resolved["pin"],"selection":resolved["record"]["selection"],"offset":"0","length":"100"}),200).await;
    assert_eq!(read["bytes_hex"], source["bytes_hex"]);
    assert_eq!(read["reference"], reference);
    let notes = ui
        .call(
            json!({"action":"annotations","subject":null,"tag":null}),
            200,
        )
        .await;
    assert_eq!(notes["records"][0]["id"], note["id"]);
    assert_eq!(notes["records"][0]["author"], note["author"]);
    let views = ui.call(json!({"action":"views"}), 200).await;
    assert_eq!(views["views"].as_array().unwrap().len(), 1);
    let search = json!({"action":"search-page","target":target,"cursor":null,"filter":filter});
    assert_eq!(
        ui.call(search.clone(), 200).await["hits"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    restored.remove(2);
    assert_eq!(ui.call(search.clone(), 200).await["unavailable_matches"], 1);
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    ui.call(
        json!({"action":"resolve-reference","reference":reference}),
        403,
    )
    .await;
    ui.call(search, 403).await;
    assert!(ui
        .call(
            json!({"action":"annotations","subject":null,"tag":null}),
            200
        )
        .await["records"]
        .as_array()
        .unwrap()
        .is_empty());
    ui.stop().await;
    // An independently advanced custody checkpoint fences the stale restored
    // workspace before the CLI can serve its retained annotation/search data.
    custody.append(erase).unwrap();
    let refused = tokio::time::timeout(Duration::from_secs(30), managed().output())
        .await
        .unwrap()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        refused.stdout.is_empty(),
        "no stale derived bytes may be returned"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("AccessLimited"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    server.stop().await;
}

#[tokio::test]
async fn native_source_download_rechecks_grants_and_origin_and_exports_only_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let ui = Ui::start(kan::evidence_library::Readers::new(None, vec![server.client(&f)]).unwrap())
        .await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let page = ui.call(json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"cursor":null,"limit":1}),200).await;
    let query = json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"],"offset":"1","length":"4"});
    let retained = ui.call(query.clone(), 200).await;
    let payload = json!({"token":TOKEN,"request":query});
    let origin = ui.url.trim_end_matches("/api/library");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let post = |payload: &Value| {
        client
            .post(format!("{}/download", ui.url))
            .header("origin", origin)
            .header("content-type", "text/plain")
            .body(format!("payload={payload}\r\n"))
    };
    let response = post(&payload).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(
        response.headers()["content-disposition"],
        format!(
            "attachment; filename=\"kan-occurrence-{}-offset-1.bin\"",
            retained["record"]["sequence"].as_str().unwrap()
        )
    );
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        service::unhex(retained["bytes_hex"].as_str().unwrap(), 262144).unwrap()
    );
    for bad_origin in [None, Some("http://foreign.invalid")] {
        let mut req = client
            .post(format!("{}/download", ui.url))
            .header("content-type", "text/plain")
            .body(format!("payload={payload}\r\n"));
        if let Some(origin) = bad_origin {
            req = req.header("origin", origin);
        }
        assert_eq!(req.send().await.unwrap().status(), 403);
    }
    let mut invalid = payload.clone();
    invalid["token"] = json!("wrong");
    assert_eq!(post(&invalid).send().await.unwrap().status(), 403);
    invalid = payload.clone();
    invalid["request"] = json!({"action":"catalog"});
    assert_eq!(post(&invalid).send().await.unwrap().status(), 400);
    assert_eq!(
        post(&payload)
            .body(format!("payload={payload}\r\nextra=field\r\n"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .get(format!("{}/download", ui.url))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    f.remove(2);
    assert_eq!(post(&payload).send().await.unwrap().status(), 404);
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    let response = post(&payload).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(!response.headers().contains_key("content-disposition"));
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn erased_source_is_explicit_and_its_derived_annotation_is_withheld_without_retraction() {
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
    let mut drafts = Vec::new();
    let mut ids = Vec::new();
    for n in 0..2 {
        let draft = json!({"subject":format!("note/{n}"),"text":format!("private derived excerpt {n}"),"tags":[],"cites":[{"source":entry["id"],"pin":entry["pin"],"selection":page["records"][n]["selection"]}],"supersedes":null});
        let preview = ui
            .call(json!({"action":"annotation-preview","draft":draft}), 200)
            .await;
        let saved = ui
            .call(
                json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
                200,
            )
            .await;
        ids.push(saved["id"].clone());
        drafts.push(draft);
    }
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    let sequence = page["records"][0]["sequence"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let plan = archive
        .preview_erasure(&[sequence], service::hex(&[23; 32]), 200)
        .unwrap();
    archive
        .apply_erasure(store::erasure::Record::sign(plan, &identity(8)).unwrap())
        .unwrap();
    let source=ui.call(json!({"action":"proof-source","source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"],"offset":"0","length":"100"}),200).await;
    assert_eq!(source["availability"], "erased");
    assert!(source.get("bytes_hex").is_none());
    let notes = ui
        .call(
            json!({"action":"annotations","subject":null,"tag":null}),
            200,
        )
        .await;
    assert_eq!(notes["records"].as_array().unwrap().len(), 1);
    assert_eq!(notes["records"][0]["id"], ids[1]);
    assert_eq!(notes["erased"][0]["id"], ids[0]);
    assert_eq!(notes["erased"][0]["state"], "erased-source");
    assert!(!notes.to_string().contains("private derived excerpt 0"));
    ui.call(
        json!({"action":"annotation-preview","draft":drafts[0]}),
        403,
    )
    .await;
    ui.call(json!({"action":"annotation-delivery","id":ids[0]}), 403)
        .await;
    let graph = ui
        .call(
            json!({"action":"knowledge-graph","subject":null,"day":false}),
            200,
        )
        .await;
    assert_eq!(graph["erased"][0]["id"], ids[0]);
    assert!(!graph.to_string().contains("private derived excerpt 0"));
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn owner_capture_erasure_revalidates_full_selection_and_resumes_offline_replica_after_restart(
) {
    use kan::evidence_erasure_history::{Access, Record};
    const OWNER: &str = "synthetic-capture-erasure-owner-token";
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let custody = private_workspace_directory();
    let replica = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, |n, audience, previous| {
        if n < 2 {
            return captured_request(n, audience, previous);
        }
        let header=serde_json::to_vec(&json!({"version":2,"attempt":"a".repeat(64),"observer":"collector","ordinal":n,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"terminal","outcome":"completed"}})).unwrap();
        let mut frame = b"KANC2".to_vec();
        frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
        frame.extend(header);
        encrypted_frame(n, audience, previous, &frame)
    });
    // The independent replica starts offline. Its old encrypted bytes remain in
    // this owner-selected backup until explicitly brought online for cleanup.
    let backup = local.path().join("before-erasure.sqlite");
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .backup(&backup)
        .unwrap();
    let server = Server::start(&f).await;
    let binding = json!({"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer});
    let mut history: Access = serde_json::from_value(
        json!({"directory":custody.path(),"binding":binding,"owner":identity(9).did().as_str()}),
    )
    .unwrap();
    history.initialize().unwrap();
    let genesis =
        Record::sign(history.preview(None, "b".repeat(64)).unwrap(), &identity(9)).unwrap();
    let minimum = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(minimum);
    let signing = local.path().join("owner.key");
    let issuer = local.path().join("issuer.key");
    let private = local.path().join("capture.key");
    for (path, key) in [(&signing, [9; 32]), (&issuer, [8; 32]), (&private, PRIVATE)] {
        std::fs::write(path, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    // Populate direct and transitive dependencies plus unrelated evidence.
    let other_dir = private_workspace_directory();
    let other = fixture_requests(other_dir.path(), Profile::Copied, encrypted);
    let other_server = Server::start(&other).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 3).await.unwrap();
    let other_reader = other_server.client(&other);
    let other_pin = other_reader.snapshot().await.unwrap();
    let other_page = other_reader.page(&other_pin, None, 1).await.unwrap();
    let cite = json!({"source":"source","pin":pin,"selection":page.records[0].selection});
    let unrelated =
        json!({"source":"other","pin":other_pin,"selection":other_page.records[0].selection});
    // Publications live in a distinct copied archive, including a correction
    // whose only source citation is unrelated. Its signed parent edge must
    // still carry the erasure dependency across archive boundaries.
    let publication_dir = private_workspace_directory();
    let publication_custody = private_workspace_directory();
    let publication_replica = private_workspace_directory();
    let mut parent_publication = None;
    let publications = fixture_requests(
        publication_dir.path(),
        Profile::Copied,
        |n, audience, previous| {
            use sha2::{Digest, Sha256};
            let mut declaration = json!({"version":1,"author":identity(6).did().as_str(),"analysis_trigger_plan":[],
            "draft":{"subject":"publication-erasure","text":if n==2 {page.records[0].manifest.clone()} else {format!("derived publication {n}")},
                "tags":[],"cites":[if n==0 {cite.clone()} else {unrelated.clone()}],"supersedes":if n==1 {parent_publication.clone()} else {None::<String>}}});
            let id = service::hex(&Sha256::digest(serde_json::to_vec(&declaration).unwrap()));
            if n == 0 {
                parent_publication = Some(id.clone());
            }
            declaration["id"] = json!(id);
            declaration["recorded_at"] = json!("100");
            let plain =
                serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":declaration}))
                    .unwrap();
            encrypted_frame(n, audience, previous, &plain)
        },
    );
    let mut publication_history:Access=serde_json::from_value(json!({"directory":publication_custody.path(),
        "binding":{"profile":"copied","archive":service::hex(&publications.binding.archive),"scope":service::hex(&publications.binding.scope),"issuer":publications.binding.issuer},
        "owner":identity(9).did().as_str()})).unwrap();
    publication_history.initialize().unwrap();
    let genesis = Record::sign(
        publication_history.preview(None, "c".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    publication_history.append(genesis).unwrap();
    publication_history.minimum = Some(minimum);
    let publication_backup = local.path().join("publications-before.sqlite");
    copied::Archive::open(&publications.root, publications.binding.clone())
        .unwrap()
        .backup(&publication_backup)
        .unwrap();
    // A separate admitted destination has unpublished note / unrelated note /
    // correction. Cancellation preserves the original writer chain and must
    // wait for the unrelated middle request to be normally delivered.
    let queue_dir = private_workspace_directory();
    let queue_custody = private_workspace_directory();
    let queue_policy_dir = private_workspace_directory();
    let queue_root = queue_dir.path().join("archive");
    let queue_binding = attested::Binding {
        archive: [42; 32],
        scope: f.binding.scope,
        issuer: f.binding.issuer.clone(),
    };
    attested::Archive::create(&queue_root, queue_binding.clone()).unwrap();
    let mut queue_history:Access=serde_json::from_value(json!({"directory":queue_custody.path(),"binding":{"profile":"admitted","archive":service::hex(&queue_binding.archive),"scope":service::hex(&queue_binding.scope),"issuer":queue_binding.issuer},"owner":identity(9).did().as_str()})).unwrap();
    queue_history.initialize().unwrap();
    let genesis = Record::sign(
        queue_history.preview(None, "d".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    queue_history.append(genesis).unwrap();
    queue_history.minimum = Some(minimum);
    let mut queue_policy:kan::evidence_policy::Access=serde_json::from_value(json!({"directory":queue_policy_dir.path(),"binding":queue_history.binding,"owner":identity(9).did().as_str()})).unwrap();
    queue_policy.initialize().unwrap();
    let genesis = kan::evidence_policy::Record::sign(
        queue_policy.preview(vec![grant()], "e".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    let minimum = genesis.id().unwrap();
    queue_policy.append(genesis).unwrap();
    queue_policy.minimum = Some(minimum);
    let queue_path = queue_dir.path().join("sender.sqlite");
    let mut queue = kan::evidence_spool::Spool::create(
        &queue_path,
        &service::hex(&queue_binding.scope),
        identity(6).did().as_str(),
        &queue_binding.issuer,
        1024 * 1024,
    )
    .unwrap();
    let mut queued_parent = None;
    let mut previous = None;
    let mut queued_requests = Vec::new();
    for n in 0..3 {
        use sha2::{Digest, Sha256};
        let mut declaration = json!({"version":1,"author":identity(6).did().as_str(),"analysis_trigger_plan":[],
            "draft":{"subject":"queue-erasure","text":format!("queued publication {n}"),"tags":[],
                "cites":[if n==0 {cite.clone()} else {unrelated.clone()}],"supersedes":if n==2 {queued_parent.clone()} else {None::<String>}}});
        let id = service::hex(&Sha256::digest(serde_json::to_vec(&declaration).unwrap()));
        if n == 0 {
            queued_parent = Some(id.clone());
        }
        declaration["id"] = json!(id);
        declaration["recorded_at"] = json!("100");
        let raw = encrypted_frame(
            n,
            8,
            previous,
            &serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":declaration}))
                .unwrap(),
        );
        previous = Some(service::append_manifest(&raw).unwrap().cid().to_string());
        queue.enqueue(&raw).unwrap();
        queued_requests.push(raw);
    }
    drop(queue);
    let derived_path = local.path().join("reader.sqlite");
    let derived =
        kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE).unwrap();
    let annotation = |mut draft: Value| {
        use sha2::{Digest, Sha256};
        draft["subject"] = json!("workspace-erasure");
        draft["tags"] = json!([]);
        if draft.get("supersedes").is_none() {
            draft["supersedes"] = Value::Null;
        }
        let mut declaration = json!({"version":1,"author":identity(9).did().as_str(),"analysis_trigger_plan":[],"draft":draft});
        let id = service::hex(&Sha256::digest(serde_json::to_vec(&declaration).unwrap()));
        declaration["id"] = json!(id);
        declaration["recorded_at"] = json!("100");
        derived.put("annotation", &id, declaration).unwrap();
        id
    };
    let job = "5".repeat(64);
    let retry = "6".repeat(64);
    let note = annotation(json!({"cites":[cite],"text":"raw-derived-secret"}));
    let correction = annotation(
        json!({"cites":[unrelated],"supersedes":note,"text":"corrected-derived-secret"}),
    );
    derived
        .put(
            "analysis-job",
            &job,
            json!({"id":job,"draft":{"cites":[unrelated],"trigger_annotation":correction}}),
        )
        .unwrap();
    derived
        .put(
            "analysis-job",
            &retry,
            json!({"id":retry,"draft":{"cites":[unrelated],"retry_of":job}}),
        )
        .unwrap();
    derived
        .put(
            "analysis-result",
            &retry,
            json!({"state":"succeeded","text":"model-derived-secret"}),
        )
        .unwrap();
    let promoted =
        annotation(json!({"cites":[unrelated],"derived_from":[retry],"text":"promoted-secret"}));
    let keep = annotation(json!({"cites":[unrelated],"text":page.records[0].manifest}));
    // This published annotation's own raw citation is unrelated. Its source
    // dependency is only in the local trigger -> retry -> promotion graph.
    let plain=serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":derived.get("annotation",&promoted).unwrap().unwrap()})).unwrap();
    let raw = service::SignedRequest::sign(
        service::Request {
            version: 1,
            scope: service::hex(&queue_binding.scope),
            audience: queue_binding.issuer.clone(),
            principal: identity(9).did().to_string(),
            expires: None,
            command: service::Command::Append {
                id: service::hex(&[99; 16]),
                position: 0,
                previous: None,
                ciphertext: service::hex(
                    &kan::evidence_crypto::seal(
                        &kan::evidence_crypto::public_key(&PRIVATE).unwrap(),
                        &queue_binding.scope,
                        &plain,
                    )
                    .unwrap(),
                ),
            },
        },
        &identity(9),
    )
    .unwrap()
    .bytes()
    .unwrap();
    attested::Archive::open(&queue_root, queue_binding.clone())
        .unwrap()
        .admit(
            &raw,
            &identity(8),
            &Grant {
                principal: identity(9).did().to_string(),
                append: true,
                inventory: false,
            },
            150,
        )
        .unwrap();
    derived
        .put(
            "analysis-input",
            "orphan-before-job",
            json!({"draft":{"cites":[cite]},"request":"orphan-input-secret"}),
        )
        .unwrap();
    derived
        .put(
            "analysis-trigger",
            &format!("{note}/0"),
            json!({"annotation":note,"outcomes":[{"job":job}]}),
        )
        .unwrap();
    derived.put("search-page","selected-cache",json!({"version":3,"documents":[{"record":page.records[0],"spans":[{"text":"indexed-secret"}]}]})).unwrap();
    derived
        .put(
            "search-page",
            "unrelated-cache",
            json!({"version":3,"documents":[{"record":other_page.records[0]}]}),
        )
        .unwrap();
    derived
        .put(
            "view",
            "snapshot-scope",
            json!({"kind":"search","targets":[{"pin":pin}],"name":"keep snapshot scope"}),
        )
        .unwrap();
    drop(derived);
    let old_workspace = local.path().join("reader-before.sqlite");
    std::fs::copy(&derived_path, &old_workspace).unwrap();
    let held_workspace =
        kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE)
            .unwrap()
            .with_erasure_histories(vec![history.clone()])
            .unwrap();
    let sender_path = local.path().join("sender.sqlite");
    {
        let mut sender = kan::evidence_spool::Spool::create(
            &sender_path,
            &service::hex(&f.binding.scope),
            identity(6).did().as_str(),
            &f.binding.issuer,
            1024 * 1024,
        )
        .unwrap();
        let mut ingest = service::AdmittingService::new(
            attested::Archive::open(&f.root, f.binding.clone()).unwrap(),
            identity(8),
            vec![grant()],
        )
        .unwrap();
        for (n, raw) in f.requests.iter().enumerate() {
            sender.enqueue(raw).unwrap();
            let ack = ingest.dispatch(raw, 200).unwrap().bytes().unwrap();
            if n < 2 {
                sender.acknowledge(&ack).unwrap();
            }
        }
    }
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"capture-erasure","id":"capture","root":f.root,"history":history,"signing_key":signing,"issuer_key":issuer,"private_keys":[private],"replicas":[replica.path()],"workspaces":[{"database":derived_path,"signing_key":signing,"recipient_key":private}],"spools":[sender_path],"publications":[{"root":publications.root,"history":publication_history,"signing_key":signing,"issuer_key":issuer,"private_keys":[private],"replicas":[publication_replica.path()]},{"root":queue_root,"history":queue_history,"signing_key":signing,"issuer_key":issuer,"private_keys":[private],"policy":queue_policy,"spools":[queue_path]}]}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    let index_preview = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"capture","operation":"rebuild-archive-index"}),
        200,
    )
    .await;
    let index_job = owner_call(&ui, OWNER, json!({"action":"submit","target":"capture","operation":"rebuild-archive-index","nonce":index_preview["nonce"],"preview":index_preview["digest"],"wait":true}), 200).await;
    assert_eq!(index_job["state"], "succeeded", "{index_job}");
    assert_eq!(
        attested::Archive::open_indexed(&f.root, f.binding.clone(), None)
            .unwrap()
            .indexed_frontier(None)
            .unwrap()
            .through,
        3
    );
    let query = json!({"action":"preview-erasure","target":"capture","page_records":1,"capture":{"writer":identity(6).did().as_str(),"observer":"collector","attempt":"a".repeat(64)}});
    owner_call(&ui, TOKEN, query.clone(), 401).await;
    let first = owner_call(&ui, OWNER, query.clone(), 200).await;
    assert_eq!(first["state"], "discovering");
    assert_eq!(first["progress"]["scanned_through"], "1");
    assert!(first.get("plan").is_none());
    assert_eq!(
        history.current().unwrap().history.len(),
        1,
        "partial discovery authorizes no erasure"
    );
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    let second = owner_call(&ui, OWNER, query.clone(), 200).await;
    assert_eq!(second["state"], "discovering");
    assert_eq!(
        second["progress"]["scanned_through"], "2",
        "restart resumes authenticated discovery"
    );
    let preview = owner_call(&ui, OWNER, query, 200).await;
    assert_eq!(
        preview["plan"]["authorization"]["erasure"]["plan"]["targets"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        history.current().unwrap().history.len(),
        1,
        "preview publishes no authorization"
    );
    let mut forged = preview["plan"].clone();
    forged["authorization"]["erasure"]["plan"]["targets"]
        .as_array_mut()
        .unwrap()
        .pop();
    let mut contract = preview["contract"].clone();
    contract["plan"] = forged.clone();
    use sha2::{Digest, Sha256};
    let forged_hash = service::hex(&Sha256::digest(serde_json::to_vec(&contract).unwrap()));
    owner_call(&ui,OWNER,json!({"action":"apply-erasure","target":"capture","plan":forged,"preview":forged_hash,"wait":true}),409).await;
    assert_eq!(history.current().unwrap().history.len(), 1);
    let apply = json!({"action":"apply-erasure","target":"capture","plan":preview["plan"],"preview":preview["digest"],"wait":true});
    let held = history.current().unwrap();
    let blocked = owner_call(&ui, OWNER, apply.clone(), 200).await;
    assert_eq!(blocked["state"], "cleanup-pending");
    assert!(blocked["result"].get("error").is_some(), "{blocked}");
    assert_eq!(held.history.len(), 1);
    assert_eq!(
        history.current().unwrap().history.len(),
        1,
        "exclusive publication refused before deletion"
    );
    drop(held);
    let done = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(done["state"], "cleanup-pending", "{done}");
    assert_eq!(
        done["result"]["report"]["archives"][0]["state"], "payloads-erased",
        "{done}"
    );
    assert_eq!(done["result"]["report"]["archives"][1]["state"], "pending");
    // The same human maintenance action preserves erased evidence and follows
    // current owner custody after cleanup; it cannot resurrect the raw bytes.
    let repair = owner_call(
        &ui,
        OWNER,
        json!({"action":"preview","target":"capture","operation":"rebuild-archive-index"}),
        200,
    )
    .await;
    let repaired = owner_call(&ui, OWNER, json!({"action":"submit","target":"capture","operation":"rebuild-archive-index","nonce":repair["nonce"],"preview":repair["digest"],"wait":true}), 200).await;
    assert_eq!(repaired["state"], "succeeded", "{repaired}");
    let tip = history.current().unwrap().storage_tip().unwrap();
    assert!(attested::Archive::open_indexed(&f.root, f.binding.clone(), tip.as_deref()).is_ok());
    assert!(attested::Archive::open_indexed(&f.root, f.binding.clone(), None).is_err());
    assert_eq!(done["result"]["report"]["backup_purge"], "not-performed");
    assert_eq!(
        done["result"]["report"]["spools"][0]["state"], "admitted-erasure-reconciled",
        "{done}"
    );
    assert_eq!(
        done["result"]["report"]["spools"][0]["retired_operations"],
        3
    );
    assert!(kan::evidence_spool::Spool::open(&sender_path)
        .unwrap()
        .head()
        .unwrap()
        .is_none());
    assert_eq!(
        done["result"]["report"]["publications"]["state"], "selected-prefix-planned",
        "{done}"
    );
    assert_eq!(
        done["result"]["report"]["publications"]["destinations"][0]["archives"][0]["state"],
        "reconciled",
        "{done}"
    );
    assert_eq!(
        done["result"]["report"]["publications"]["destinations"][0]["archives"][1]["state"],
        "pending"
    );
    let erased = copied::Archive::open(&publications.root, publications.binding.clone())
        .unwrap()
        .erasure_history()
        .unwrap();
    assert_eq!(erased.records.len(), 1);
    assert_eq!(
        erased.records[0]
            .plan
            .targets
            .iter()
            .map(|t| t.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "correction follows dependency; unrelated CID text is retained"
    );
    let retained = kan::evidence_store::inventory::Inventory::open(
        &publications.db(),
        Profile::Copied,
        publications.binding.clone(),
        budget(),
    )
    .unwrap();
    let rows = retained
        .page(
            None,
            PageBudget {
                rows: 3,
                record_bytes: 1024 * 1024,
                payload_bytes: 16 * 1024 * 1024,
            },
            budget(),
        )
        .unwrap();
    assert_eq!(rows.records[0].availability, Availability::Available);
    assert_eq!(rows.records[1].availability, Availability::Erased);
    assert_eq!(rows.records[2].availability, Availability::Erased);
    drop(retained);
    assert_eq!(
        done["result"]["report"]["publications"]["destinations"][1]["spools"][0]["cancellation"]
            ["state"],
        "pending-unrelated-prefix",
        "{done}"
    );
    assert_eq!(
        done["result"]["report"]["publications"]["destinations"][1]["spools"][0]["cancellation"]
            ["processed"],
        1
    );
    let queue = kan::evidence_spool::Spool::open(&queue_path).unwrap();
    assert_eq!(queue.head().unwrap().as_ref(), Some(&queued_requests[1]));
    assert!(
        queue
            .operation(&service::hex(&[1; 16]))
            .unwrap()
            .unwrap()
            .erased
    );
    assert!(
        !queue
            .operation(&service::hex(&[3; 16]))
            .unwrap()
            .unwrap()
            .erased,
        "selected tail cannot jump unaffected prefix"
    );
    drop(queue);
    assert_eq!(
        attested::Archive::verify_file(&queue_root.join("archive.sqlite"), queue_binding.clone())
            .unwrap()
            .erased_objects,
        2
    );
    {
        let retained =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        for suffix in ["publication-plan", "queue-intent:0"] {
            let value = retained
                .get(
                    "owner-result",
                    &format!("erasure:{}:{suffix}", preview["digest"].as_str().unwrap()),
                )
                .unwrap()
                .unwrap();
            let bytes = serde_json::to_string(&value).unwrap();
            assert!(
                !bytes.contains("publication-erasure")
                    && !bytes.contains("queue-erasure")
                    && !bytes.contains("workspace-erasure"),
                "cleanup journal must not retain erased subject text"
            );
            assert!(
                !bytes.contains("derived publication") && !bytes.contains("queued publication"),
                "cleanup journal must not retain erased bodies"
            );
        }
    }
    let selected = attested::Archive::open(&queue_root, queue_binding.clone())
        .unwrap()
        .erasure_history()
        .unwrap();
    assert_eq!(
        selected.records[0].plan.targets[0].sequence, 1,
        "analysis-only publication dependency is erased before queued successors"
    );
    assert_eq!(done["attempts"], 2);
    assert_eq!(
        owner_call(&ui, OWNER, apply.clone(), 200).await,
        done,
        "lost ACK reuses the retained job"
    );
    assert_eq!(history.current().unwrap().history.len(), 2);
    assert_eq!(
        attested::Archive::verify_file(&f.db(), f.binding.clone())
            .unwrap()
            .erased_objects,
        3
    );
    assert_eq!(
        done["result"]["report"]["workspaces"][0]["state"], "pending",
        "active workspace must refuse cleanup"
    );
    assert!(
        held_workspace.get("annotation", &note).is_err(),
        "live custody advance fences managed reads before physical cleanup"
    );
    assert!(held_workspace
        .put(
            "view",
            "after-erasure",
            json!({"name":"refused until reconciliation"})
        )
        .is_err());
    drop(held_workspace);
    ui.stop().await;
    std::fs::copy(&backup, replica.path().join("archive.sqlite")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            replica.path().join("archive.sqlite"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    std::fs::copy(
        &publication_backup,
        publication_replica.path().join("archive.sqlite"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            publication_replica.path().join("archive.sqlite"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    // Normal managed delivery advances only the unrelated middle request.
    {
        let mut service = service::AdmittingService::new(
            attested::Archive::open(&queue_root, queue_binding.clone()).unwrap(),
            identity(8),
            vec![grant()],
        )
        .unwrap()
        .with_erasure_history(queue_history.clone())
        .unwrap()
        .with_policy(queue_policy.clone())
        .unwrap();
        let reply = service.dispatch(&queued_requests[1], 200).unwrap();
        let mut queue = kan::evidence_spool::Spool::open(&queue_path)
            .unwrap()
            .with_erasure_history(queue_history.clone())
            .unwrap();
        queue.acknowledge(&reply.bytes().unwrap()).unwrap();
        assert_eq!(queue.head().unwrap().as_ref(), Some(&queued_requests[2]));
    }
    let ui = Ui::start(readers()).await;
    let resumed = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(
        publication_history.current().unwrap().history.len(),
        2,
        "resume reuses journaled child authorization after its source bytes are gone"
    );
    assert_eq!(
        resumed["result"]["report"]["publications"]["destinations"][0]["archives"][1]["state"],
        "reconciled",
        "{resumed}"
    );
    assert_eq!(
        copied::Archive::open(publication_replica.path(), publications.binding.clone())
            .unwrap()
            .erasure_history()
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(
        resumed["result"]["report"]["publications"]["destinations"][1]["spools"][0]["cancellation"]
            ["state"],
        "queue-empty",
        "{resumed}"
    );
    assert_eq!(
        queue_history.current().unwrap().history.len(),
        4,
        "published promotion and two cancelled requests retain owner authorization"
    );
    let queue = kan::evidence_spool::Spool::open(&queue_path).unwrap();
    assert!(queue.head().unwrap().is_none());
    assert!(
        queue
            .operation(&service::hex(&[3; 16]))
            .unwrap()
            .unwrap()
            .erased,
        "queued correction follows journaled parent after restart"
    );
    assert!(
        !queue
            .operation(&service::hex(&[2; 16]))
            .unwrap()
            .unwrap()
            .erased
    );
    drop(queue);
    assert_eq!(
        attested::Archive::verify_file(&queue_root.join("archive.sqlite"), queue_binding.clone())
            .unwrap()
            .erased_objects,
        3
    );
    assert_eq!(resumed["attempts"], 3);
    assert_eq!(
        resumed["result"]["report"]["archives"][1]["state"], "payloads-erased",
        "{resumed}"
    );
    assert_eq!(
        resumed["state"], "configured-cleanup-complete",
        "completion covers configured destinations, not unregistered copies or backups"
    );
    assert_eq!(
        history.current().unwrap().history.len(),
        2,
        "resume never mints another authorization"
    );
    assert_eq!(
        attested::Archive::verify_file(&replica.path().join("archive.sqlite"), f.binding.clone())
            .unwrap()
            .erased_objects,
        3
    );
    assert_eq!(
        attested::Archive::verify_file(&backup, f.binding.clone())
            .unwrap()
            .erased_objects,
        0,
        "independent backup unchanged"
    );
    assert_eq!(
        resumed["result"]["report"]["workspaces"][0]["state"], "reconciled",
        "{resumed}"
    );
    {
        let cleaned =
            kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE).unwrap();
        for id in [&note, &correction, &promoted] {
            assert!(cleaned.get("annotation", id).unwrap().is_none());
        }
        for id in [&job, &retry] {
            for kind in ["analysis-job", "analysis-input", "analysis-result"] {
                assert!(cleaned.get(kind, id).unwrap().is_none());
                assert!(cleaned
                    .put(kind, id, json!({"late":"must not return"}))
                    .is_err());
            }
        }
        assert!(cleaned
            .get("analysis-input", "orphan-before-job")
            .unwrap()
            .is_none());
        assert!(cleaned
            .get("analysis-trigger", &format!("{note}/0"))
            .unwrap()
            .is_none());
        assert!(cleaned
            .get("search-page", "selected-cache")
            .unwrap()
            .is_none());
        assert!(
            cleaned.get("annotation", &keep).unwrap().is_some(),
            "unrelated assertion mentioning the erased CID is retained"
        );
        assert!(cleaned
            .get("search-page", "unrelated-cache")
            .unwrap()
            .is_some());
        assert!(
            cleaned.get("view", "snapshot-scope").unwrap().is_some(),
            "a snapshot frontier is not an erased-payload dependency"
        );
    }
    // Simulate late copies from an unenrolled sender after local annotation/job
    // bytes were removed. Resume must use retained identities and parent edges,
    // not merely replay the first frozen prefix or depend on deleted plaintext.
    let late_request = |position, previous, plaintext: &[u8]| {
        service::SignedRequest::sign(
            service::Request {
                version: 1,
                scope: service::hex(&queue_binding.scope),
                audience: queue_binding.issuer.clone(),
                principal: identity(9).did().to_string(),
                expires: None,
                command: service::Command::Append {
                    id: service::hex(&[100 + position as u8; 16]),
                    position,
                    previous,
                    ciphertext: service::hex(
                        &kan::evidence_crypto::seal(
                            &kan::evidence_crypto::public_key(&PRIVATE).unwrap(),
                            &queue_binding.scope,
                            plaintext,
                        )
                        .unwrap(),
                    ),
                },
            },
            &identity(9),
        )
        .unwrap()
        .bytes()
        .unwrap()
    };
    let late_summary = late_request(
        1,
        Some(service::append_manifest(&raw).unwrap().cid().to_string()),
        &plain,
    );
    let mut declaration = json!({"version":1,"author":identity(9).did().as_str(),"analysis_trigger_plan":[],
        "draft":{"subject":"workspace-erasure","text":"late descendant","tags":[],"cites":[unrelated],"supersedes":correction}});
    declaration["id"] = json!(service::hex(&Sha256::digest(
        serde_json::to_vec(&declaration).unwrap()
    )));
    declaration["recorded_at"] = json!("300");
    let late_correction = late_request(
        2,
        Some(
            service::append_manifest(&late_summary)
                .unwrap()
                .cid()
                .to_string(),
        ),
        &serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":declaration}))
            .unwrap(),
    );
    let mut declaration = json!({"version":1,"author":identity(6).did().as_str(),"analysis_trigger_plan":[],
        "draft":{"subject":"queue-erasure","text":"late queued descendant","tags":[],"cites":[unrelated],"supersedes":queued_parent}});
    declaration["id"] = json!(service::hex(&Sha256::digest(
        serde_json::to_vec(&declaration).unwrap()
    )));
    declaration["recorded_at"] = json!("300");
    let late_queued = encrypted_frame(
        3,
        8,
        Some(
            service::append_manifest(&queued_requests[2])
                .unwrap()
                .cid()
                .to_string(),
        ),
        &serde_json::to_vec(&json!({"format":"kan-annotation/1","declaration":declaration}))
            .unwrap(),
    );
    for (request, writer) in [(&late_summary, 9), (&late_correction, 9), (&late_queued, 6)] {
        attested::Archive::open(&queue_root, queue_binding.clone())
            .unwrap()
            .admit(
                request,
                &identity(8),
                &Grant {
                    principal: identity(writer).did().to_string(),
                    append: true,
                    inventory: false,
                },
                300,
            )
            .unwrap();
    }
    let late = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(late["attempts"], 4);
    assert_eq!(
        late["result"]["report"]["workspaces"][0]["state"], "reconciled",
        "{late}"
    );
    let late_history = attested::Archive::open(&queue_root, queue_binding.clone())
        .unwrap()
        .erasure_history()
        .unwrap();
    assert_eq!(
        late_history
            .records
            .last()
            .unwrap()
            .plan
            .targets
            .iter()
            .map(|t| t.sequence)
            .collect::<Vec<_>>(),
        vec![5, 6, 7],
        "later copies follow retained analysis and cancelled-queue lineage"
    );
    assert_eq!(
        attested::Archive::verify_file(&queue_root.join("archive.sqlite"), queue_binding.clone())
            .unwrap()
            .erased_objects,
        6
    );
    assert_eq!(
        late["result"]["report"]["publications"]["destinations"][1]["frontier"]["through"],
        "7"
    );

    // A managed old workspace restoration is reconciled from independent custody,
    // not trusted just because it predates the tombstone schema.
    std::fs::copy(&old_workspace, &derived_path).unwrap();
    assert!(
        kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE)
            .unwrap()
            .with_erasure_histories(vec![history.clone()])
            .is_err(),
        "old managed restore refuses activation before reconciliation"
    );
    let restored = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(
        restored["result"]["report"]["workspaces"][0]["state"], "reconciled",
        "{restored}"
    );
    assert_eq!(restored["attempts"], 5);
    assert_eq!(restored["state"], "configured-cleanup-complete");
    assert_eq!(
        restored["result"]["report"]["configured_cleanup"],
        "reconciled"
    );
    assert_eq!(
        restored["result"]["report"]["enrollment"],
        "operator-verification-required"
    );
    assert_eq!(
        restored["result"]["report"]["backup_purge"],
        "not-performed"
    );

    assert!(
        kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE)
            .unwrap()
            .get("annotation", &note)
            .unwrap()
            .is_none()
    );
    {
        let managed = kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE)
            .unwrap()
            .with_erasure_histories(vec![history.clone()])
            .unwrap();
        assert!(managed.get("annotation", &keep).unwrap().is_some());
        let fresh = "7".repeat(64);
        assert!(
            managed
                .put(
                    "annotation",
                    &fresh,
                    json!({"id":fresh,"draft":{"cites":[cite],"text":"forbidden new derivative"}})
                )
                .is_err(),
            "prospective writes must not recreate erased dependencies"
        );
        assert!(
            managed.get("annotation", &fresh).unwrap().is_none(),
            "failed prospective write rolls back atomically"
        );
        let old = rusqlite::Connection::open(&old_workspace).unwrap();
        let bytes: Vec<(String, Vec<u8>)> = old
            .prepare("SELECT id,body FROM entries WHERE kind='annotation'")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let live = rusqlite::Connection::open(&derived_path).unwrap();
        for (id, body) in bytes {
            live.execute(
                "INSERT OR REPLACE INTO entries VALUES('annotation',?,?)",
                rusqlite::params![id, body],
            )
            .unwrap();
        }
        assert!(
            managed.get("annotation", &keep).is_err(),
            "external SQLite changes invalidate the successful audit cache"
        );
    }
    std::fs::copy(&old_workspace, &derived_path).unwrap();
    {
        let journal =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let id = preview["digest"].as_str().unwrap();
        let key = |n| {
            if n == 0 {
                format!("erasure:{id}:publication-plan")
            } else {
                format!("erasure:{id}:publication-plan:{n}")
            }
        };
        let mut n = 0;
        let mut latest = None;
        while let Some(plan) = journal.get("owner-result", &key(n)).unwrap() {
            latest = Some(plan);
            n += 1;
        }
        let latest = latest.unwrap();
        assert!(latest["prior_coordinates"].is_array());
        for round in n..33 {
            journal
                .put("owner-result", &key(round), latest.clone())
                .unwrap();
        }
    }
    let repaired = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(
        repaired["result"]["report"]["workspaces"][0]["state"], "reconciled",
        "{repaired}"
    );
    assert_eq!(repaired["result"]["report"]["publications"]["pass"], 33);
    assert_eq!(
        repaired["state"], "configured-cleanup-complete",
        "latest cumulative plan retains earlier source lineage beyond the former pass limit"
    );
    {
        let damaged =
            kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE).unwrap();
        damaged
            .put(
                "analysis-result",
                "orphan-output",
                json!({"text":"unknown input lineage"}),
            )
            .unwrap();
    }
    let refused = owner_call(
        &ui,
        OWNER,
        json!({"action":"resume-erasure","id":preview["digest"],"wait":true}),
        200,
    )
    .await;
    assert_eq!(
        refused["result"]["report"]["workspaces"][0]["state"], "pending",
        "orphan model output must prevent a clean-destination report"
    );
    assert_eq!(refused["state"], "cleanup-pending");
    assert_eq!(
        refused["result"]["report"]["publications"]["error"],
        "corrupt"
    );
    assert_eq!(
        refused["result"]["report"]["workspaces"][0]["reason"],
        "publication-lineage-plan-not-retained"
    );
    assert_eq!(
        kan::evidence_workspace::Workspace::open(&derived_path, identity(9), PRIVATE)
            .unwrap()
            .get("analysis-result", "orphan-output")
            .unwrap()
            .unwrap()["text"],
        "unknown input lineage",
        "failed planning preserves unresolved evidence for repair"
    );
    let catalog = owner_call(&ui, OWNER, json!({"action":"catalog"}), 200).await;
    assert_eq!(catalog["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["jobs"][0]["attempts"], 7);
}

#[tokio::test]
async fn workspace_source_cleanup_batches_large_cache_and_keeps_job_lineage_until_outputs_are_fenced(
) {
    use kan::evidence_workspace::Workspace;
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 2).await.unwrap();
    let binding = serde_json::from_value(json!({"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer})).unwrap();
    let plan = attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .preview_erasure(
            &[page.records[0].sequence.parse().unwrap()],
            "b".repeat(64),
            200,
        )
        .unwrap();
    let record = kan::evidence_store::erasure::Record::sign(plan, &identity(8)).unwrap();
    let database = local.path().join("workspace.sqlite");
    {
        let workspace = Workspace::open(&database, identity(9), [84; 32]).unwrap();
        for n in 0..9 {
            workspace.put("search-page", &format!("large-{n}"), json!({"version":3,"documents":[{"record":page.records[0],"spans":[{"text":"x".repeat(8*1024*1024)}]}]})).unwrap();
        }
        workspace.put("search-page", "unrelated", json!({"version":3,"documents":[{"record":page.records[1],"spans":[{"text":"keep this"}]}]})).unwrap();
        let cite = json!({"source":"source","pin":pin,"selection":page.records[0].selection});
        workspace
            .put(
                "analysis-job",
                "job",
                json!({"id":"job","draft":{"cites":[cite]}}),
            )
            .unwrap();
        workspace
            .put("analysis-result", "job", json!({"text":"private output"}))
            .unwrap();
    }
    let workspace = Workspace::open_for_erasure(&database, identity(9), [84; 32]).unwrap();
    let first = workspace
        .preview_source_erasure(&binding, &record, "c".repeat(64))
        .unwrap()
        .unwrap();
    assert!(
        !first.targets.iter().any(|t| t.kind == "analysis-job"),
        "parent job remains until selected output/cache batches are covered"
    );
    workspace.apply_erasure(&first).unwrap();
    assert!(workspace.get("analysis-result", "job").unwrap().is_none());
    assert!(workspace.get("analysis-job", "job").unwrap().is_some());
    let second = workspace
        .preview_source_erasure(&binding, &record, "c".repeat(64))
        .unwrap()
        .unwrap();
    workspace.apply_erasure(&second).unwrap();
    assert!(workspace
        .preview_source_erasure(&binding, &record, "c".repeat(64))
        .unwrap()
        .is_none());
    assert!(workspace.get("analysis-job", "job").unwrap().is_none());
    assert!(workspace.get("analysis-input", "job").unwrap().is_none());
    for n in 0..9 {
        assert!(workspace
            .get("search-page", &format!("large-{n}"))
            .unwrap()
            .is_none());
    }
    assert!(workspace.get("search-page", "unrelated").unwrap().is_some());
    drop(workspace);
    let workspace = Workspace::open(&database, identity(9), [84; 32]).unwrap();
    assert!(workspace
        .put("analysis-result", "job", json!({"text":"late output"}))
        .is_err());
    assert!(workspace.get("search-page", "unrelated").unwrap().is_some());
    server.stop().await;
}

#[tokio::test]
async fn owner_publication_discovery_resumes_retained_pages_before_authorizing_cleanup() {
    use kan::evidence_erasure_history::{Access, Record};
    const OWNER: &str = "synthetic-publication-discovery-owner-token";
    let source_dir = private_workspace_directory();
    let publication_dir = private_workspace_directory();
    let local = private_workspace_directory();
    let custody = private_workspace_directory();
    let publication_custody = private_workspace_directory();
    let f = fixture_requests(
        source_dir.path(),
        Profile::Admitted,
        |n, audience, previous| {
            if n < 2 {
                return captured_request(n, audience, previous);
            }
            let header=serde_json::to_vec(&json!({"version":2,"attempt":"a".repeat(64),"observer":"collector","ordinal":n,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"terminal","outcome":"completed"}})).unwrap();
            let mut frame = b"KANC2".to_vec();
            frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
            frame.extend(header);
            encrypted_frame(n, audience, previous, &frame)
        },
    );
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 1).await.unwrap();
    let cite = json!({"source":"source","pin":pin,"selection":page.records[0].selection});
    let publication = fixture_requests(
        publication_dir.path(),
        Profile::Copied,
        |n, audience, previous| {
            use sha2::{Digest, Sha256};
            let mut declaration = json!({"version":1,"author":identity(6).did().as_str(),"analysis_trigger_plan":[],"draft":{"subject":"discovery-test","text":format!("body-secret-{n}"),"tags":[],"cites":[cite],"supersedes":null}});
            let id = service::hex(&Sha256::digest(serde_json::to_vec(&declaration).unwrap()));
            declaration["id"] = json!(id);
            declaration["recorded_at"] = json!("100");
            encrypted_frame(
                n,
                audience,
                previous,
                &serde_json::to_vec(
                    &json!({"format":"kan-annotation/1","declaration":declaration}),
                )
                .unwrap(),
            )
        },
    );
    let setup = |directory: &std::path::Path, binding: Value| {
        let mut access: Access = serde_json::from_value(
            json!({"directory":directory,"binding":binding,"owner":identity(9).did().as_str()}),
        )
        .unwrap();
        access.initialize().unwrap();
        let genesis =
            Record::sign(access.preview(None, "a".repeat(64)).unwrap(), &identity(9)).unwrap();
        let minimum = genesis.id().unwrap();
        access.append(genesis).unwrap();
        access.minimum = Some(minimum);
        access
    };
    let history = setup(
        custody.path(),
        json!({"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer}),
    );
    let publication_history = setup(
        publication_custody.path(),
        json!({"profile":"copied","archive":service::hex(&publication.binding.archive),"scope":service::hex(&publication.binding.scope),"issuer":publication.binding.issuer}),
    );
    let write = |name: &str, bytes: &[u8]| {
        let path = local.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let signer = write("owner.key", &[9; 32]);
    let issuer = write("issuer.key", &[8; 32]);
    let key = write("capture.key", &PRIVATE);
    let readers = || {
        let workspace = kan::evidence_workspace::Workspace::open(
            &local.path().join("owner.sqlite"),
            identity(9),
            [84; 32],
        )
        .unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"capture-erasure","id":"capture","root":f.root,"history":history,"signing_key":signer,"issuer_key":issuer,"private_keys":[key],"publications":[{"root":publication.root,"history":publication_history,"signing_key":signer,"issuer_key":issuer,"private_keys":[key],"discovery_page_records":1,"discovery_pages":1}]}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    let preview=owner_call(&ui,OWNER,json!({"action":"preview-erasure-selection","target":"capture","selection":{"kind":"capture","capture":{"writer":identity(6).did().as_str(),"observer":"collector","attempt":"a".repeat(64)}}}),200).await;
    let first=owner_call(&ui,OWNER,json!({"action":"apply-erasure","target":"capture","plan":preview["plan"],"preview":preview["digest"],"wait":true}),200).await;
    assert_eq!(first["state"], "cleanup-pending", "{first}");
    assert_eq!(
        first["result"]["report"]["publications"]["reason"],
        "publication-discovery"
    );
    assert_eq!(
        first["result"]["report"]["publications"]["progress"]["remaining_through"],
        "2"
    );
    assert_eq!(
        publication_history.current().unwrap().history.len(),
        1,
        "incomplete discovery creates no child authority"
    );
    assert_eq!(
        copied::Archive::verify_file(&publication.db(), publication.binding.clone())
            .unwrap()
            .contents
            .erased_objects,
        0
    );
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    let request = json!({"action":"resume-erasure","id":preview["digest"],"wait":true});
    let second = owner_call(&ui, OWNER, request.clone(), 200).await;
    assert_eq!(
        second["result"]["report"]["publications"]["progress"]["remaining_through"], "1",
        "{second}"
    );
    assert_eq!(
        second["result"]["report"]["publications"]["progress"]["retained_pages"],
        2
    );
    let done = owner_call(&ui, OWNER, request, 200).await;
    assert_eq!(done["state"], "configured-cleanup-complete", "{done}");
    assert_eq!(publication_history.current().unwrap().history.len(), 2);
    assert_eq!(
        copied::Archive::verify_file(&publication.db(), publication.binding.clone())
            .unwrap()
            .contents
            .erased_objects,
        3
    );
    ui.stop().await;
    server.stop().await;
}

#[test]
fn erasure_custody_keeps_accepting_new_work_and_fences_restores_after_1024_records() {
    use kan::{evidence_erasure_history as custody, evidence_store::erasure as storage};
    let dir = private_workspace_directory();
    let history_dir = private_workspace_directory();
    let backup_dir = private_workspace_directory();
    let restored_dir = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let issuer = identity(8);
    let owner = identity(9);
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    let backup = backup_dir.path().join("before-erasure.sqlite");
    archive.backup(&backup).unwrap();
    let binding = serde_json::from_value(json!({"profile":"admitted",
        "archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer})).unwrap();
    let mut access = custody::Access {
        directory: history_dir.path().to_owned(),
        binding,
        owner: owner.did().to_string(),
        minimum: None,
    };
    access.initialize().unwrap();
    let genesis =
        custody::Record::sign(access.preview(None, "a".repeat(64)).unwrap(), &owner).unwrap();
    let mut custody_tip = genesis.id().unwrap();
    access.append(genesis).unwrap();
    access.minimum = Some(custody_tip.clone());
    let template = archive.preview_erasure(&[1], "b".repeat(64), 100).unwrap();
    let mut storage_tip = None;
    // Seed canonical, fully signed prior history directly to avoid doing
    // quadratic fixture setup through 1,024 successive full-history audits.
    // Reauthorizing the same exact target is valid and does not invent objects.
    for n in 1..=1024 {
        let mut plan = template.clone();
        plan.previous = storage_tip;
        plan.nonce = format!("{n:064x}");
        let erasure = storage::Record::sign(plan, &issuer).unwrap();
        storage_tip = Some(erasure.id().unwrap());
        let record = custody::Record::sign(
            custody::Change {
                version: 1,
                binding: access.binding.clone(),
                owner: access.owner.clone(),
                sequence: n.to_string(),
                previous: Some(custody_tip),
                nonce: format!("{n:064x}"),
                recorded_at: "100".into(),
                erasure: Some(erasure),
            },
            &owner,
        )
        .unwrap();
        custody_tip = record.id().unwrap();
        let path = history_dir
            .path()
            .join(format!("erasure-{n:020}-{custody_tip}.json"));
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    assert_eq!(access.current().unwrap().history.len(), 1025);
    access.reconcile_archive(&f.root).unwrap();
    assert_eq!(archive.erasure_history().unwrap().records.len(), 1024);
    let fresh = archive.preview_erasure(&[2], "c".repeat(64), 101).unwrap();
    let fresh = storage::Record::sign(fresh, &issuer).unwrap();
    let authority = custody::Record::sign(
        access.preview(Some(fresh.clone()), "d".repeat(64)).unwrap(),
        &owner,
    )
    .unwrap();
    access.append(authority.clone()).unwrap();
    archive.apply_erasure(fresh).unwrap();
    assert_eq!(access.current().unwrap().history.len(), 1026);
    access
        .current()
        .unwrap()
        .check_archive(&f.db(), &access.binding)
        .unwrap();
    assert_eq!(
        access.append(authority).unwrap()["state"],
        "already-applied"
    );
    let package = archive.erasure_history().unwrap();
    assert_eq!(package.records.len(), 1025);
    // Current owner custody also applies to a separately recovered old backup.
    attested::Recovery::open(&backup, f.binding.clone())
        .unwrap()
        .rebuild(&restored_dir.path().join("archive.sqlite"))
        .unwrap();
    assert!(access
        .current()
        .unwrap()
        .check_archive(&restored_dir.path().join("archive.sqlite"), &access.binding)
        .is_err());
    access.reconcile_archive(restored_dir.path()).unwrap();
    let mut restored = attested::Archive::open(restored_dir.path(), f.binding.clone()).unwrap();
    assert_eq!(
        attested::Archive::verify_file(
            &restored_dir.path().join("archive.sqlite"),
            f.binding.clone()
        )
        .unwrap()
        .erased_objects,
        2
    );
    access
        .current()
        .unwrap()
        .check_archive(&restored_dir.path().join("archive.sqlite"), &access.binding)
        .unwrap();
    let mut changed = package.clone();
    changed.records[512].signature = "00".repeat(64);
    assert!(access.current().unwrap().check_package(&changed).is_err());
    assert!(restored
        .reconcile_erasure(&changed, package.tip.as_ref().unwrap())
        .is_err());
    assert_eq!(restored.erasure_history().unwrap().tip, package.tip);
}

#[tokio::test]
async fn saved_views_page_beyond_200_after_restart_and_recheck_current_access() {
    use kan::evidence_workspace::Workspace;
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let database = local.path().join("workspace.sqlite");
    let readers = || {
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(Workspace::open(&database, identity(6), [71; 32]).unwrap())
    };
    let ui = Ui::start(readers()).await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let target = json!({"source":catalog["scopes"][0]["id"],"pin":catalog["scopes"][0]["pin"]});
    let save =
        json!({"action":"save-view","name":"First","targets":[target],"filter":{"text":"needle"}});
    let template = ui.call(save.clone(), 200).await;
    ui.stop().await;
    {
        let workspace = Workspace::open(&database, identity(6), [71; 32]).unwrap();
        for n in 0..204 {
            let mut value = template.clone();
            value["name"] = json!(format!("Saved {n}"));
            value["id"] = json!(format!("{n:064x}"));
            workspace
                .put("view", value["id"].as_str().unwrap(), value.clone())
                .unwrap();
        }
    }
    let mut ui = Ui::start(readers()).await;
    let mut later = save.clone();
    later["name"] = json!("Saved after the former lifetime limit");
    let added = ui.call(later, 200).await;
    let mut seen = std::collections::BTreeSet::new();
    let mut cursor = Value::Null;
    let mut first_next = Value::Null;
    for page in 0..10 {
        let response = ui.call(json!({"action":"views","after":cursor}), 200).await;
        let views = response["views"].as_array().unwrap();
        assert!(!views.is_empty());
        assert!(views.len() <= 100);
        for view in views {
            assert!(seen.insert(view["id"].as_str().unwrap().to_string()));
        }
        cursor = response["next"].clone();
        if cursor.is_null() {
            break;
        }
        if page == 0 {
            first_next = cursor.clone();
            ui.stop().await;
            ui = Ui::start(readers()).await;
        }
    }
    assert!(cursor.is_null());
    assert_eq!(seen.len(), 206);
    assert!(seen.contains(added["id"].as_str().unwrap()));
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    let revoked = ui
        .call(json!({"action":"views","after":first_next}), 200)
        .await;
    assert!(revoked["views"].as_array().unwrap().is_empty());
    ui.call(json!({"action":"views","after":"invalid-cursor"}), 400)
        .await;
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn annotation_pages_cross_1000_keep_off_page_history_and_recheck_access() {
    use kan::evidence_workspace::Workspace;
    use sha2::{Digest, Sha256};
    let dir = private_workspace_directory();
    let local = private_workspace_directory();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let database = local.path().join("workspace.sqlite");
    let readers = || {
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_workspace(Workspace::open(&database, identity(6), [72; 32]).unwrap())
    };
    let ui = Ui::start(readers()).await;
    let catalog = ui.call(json!({"action":"catalog"}), 200).await;
    let entry = &catalog["scopes"][0];
    let page = ui
        .call(
            json!({"action":"proof-page","source":entry["id"],"pin":entry["pin"],"limit":1}),
            200,
        )
        .await;
    let draft = json!({"subject":"telos/paged-history","text":"Original note","tags":["selected"],
        "cites":[{"source":entry["id"],"pin":entry["pin"],"selection":page["records"][0]["selection"]}],"supersedes":null});
    let preview = ui
        .call(json!({"action":"annotation-preview","draft":draft}), 200)
        .await;
    let template = ui
        .call(
            json!({"action":"annotation-save","draft":draft,"preview":preview["id"]}),
            200,
        )
        .await;
    ui.stop().await;
    {
        let workspace = Workspace::open(&database, identity(6), [72; 32]).unwrap();
        for n in 0..1000 {
            let mut record = template.clone();
            record.as_object_mut().unwrap().remove("id");
            record.as_object_mut().unwrap().remove("recorded_at");
            record["draft"]["text"] = json!(format!("Retained note {n}"));
            let id = service::hex(&Sha256::digest(serde_json::to_vec(&record).unwrap()));
            record["id"] = json!(id);
            record["recorded_at"] = json!("100");
            workspace.put("annotation", &id, record).unwrap();
        }
    }
    let ui = Ui::start(readers()).await;
    let first = ui
        .call(json!({"action":"annotations","limit":1}), 200)
        .await;
    let parent = first["records"][0].clone();
    let mut correction = parent["draft"].clone();
    correction["text"] = json!("Later correction on another page");
    correction["tags"] = json!(["correction-only"]);
    correction["supersedes"] = parent["id"].clone();
    let preview = ui
        .call(
            json!({"action":"annotation-preview","draft":correction}),
            200,
        )
        .await;
    let correction = ui
        .call(
            json!({"action":"annotation-save","draft":correction,"preview":preview["id"]}),
            200,
        )
        .await;
    let mut withdrawal = parent["draft"].clone();
    withdrawal["text"] = json!("Withdraw while retaining provenance");
    withdrawal["tags"] = json!([]);
    withdrawal["withdraws"] = parent["id"].clone();
    let preview = ui
        .call(
            json!({"action":"annotation-preview","draft":withdrawal}),
            200,
        )
        .await;
    let withdrawal = ui
        .call(
            json!({"action":"annotation-save","draft":withdrawal,"preview":preview["id"]}),
            200,
        )
        .await;
    ui.stop().await;
    let ui = Ui::start(readers()).await;
    // Two new records may sort before the previously first row. A one-record
    // page guarantees both incoming links are outside the displayed parent page.
    let mut cursor = Value::Null;
    let mut checked = false;
    for _ in 0..3 {
        let result = ui
            .call(
                json!({"action":"annotations","limit":1,"after":cursor,"tag":"selected"}),
                200,
            )
            .await;
        if result["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == parent["id"])
        {
            let id = parent["id"].as_str().unwrap();
            assert_eq!(result["corrections"][id], json!([correction["id"]]));
            assert_eq!(result["withdrawals"][id], json!([withdrawal["id"]]));
            assert_eq!(result["records"].as_array().unwrap().len(), 1);
            checked = true;
            break;
        }
        cursor = result["next"].clone();
        assert!(!cursor.is_null());
    }
    assert!(checked);
    let mut cursor = Value::Null;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..100 {
        let page = ui
            .call(json!({"action":"annotations","after":cursor}), 200)
            .await;
        for note in page["records"].as_array().unwrap() {
            assert!(seen.insert(note["id"].as_str().unwrap().to_string()));
        }
        cursor = page["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert!(cursor.is_null());
    assert_eq!(seen.len(), 1003);
    let graph = ui
        .call(
            json!({"action":"knowledge-graph","subject":null,"day":true}),
            200,
        )
        .await;
    assert_eq!(graph["subjects"][0]["declarations"], 1003);
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    let revoked = ui
        .call(json!({"action":"annotations","limit":1}), 200)
        .await;
    assert!(revoked["records"].as_array().unwrap().is_empty());
    assert!(revoked["withdrawals"].as_object().unwrap().is_empty());
    assert!(revoked["corrections"].as_object().unwrap().is_empty());
    ui.call(json!({"action":"annotations","limit":0}), 400)
        .await;
    ui.call(json!({"action":"annotations","after":"invalid"}), 400)
        .await;
    ui.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn owner_complete_selection_resumes_batches_after_restart_and_intervening_custody() {
    use kan::evidence_erasure_history::{Access, Record};
    const OWNER: &str = "synthetic-complete-selection-owner-token";
    let source = private_workspace_directory();
    let local = private_workspace_directory();
    let custody = private_workspace_directory();
    // Deliberately an active capture: archive-prefix consent explicitly covers
    // all retained payloads, whereas closed-capture selection must refuse it.
    let f = fixture_requests(source.path(), Profile::Admitted, captured_request);
    let server = Server::start(&f).await;
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .rebuild_serving_index(&identity(8))
        .unwrap();
    let mut history:Access=serde_json::from_value(json!({"directory":custody.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer},"owner":identity(9).did().as_str()})).unwrap();
    history.initialize().unwrap();
    let genesis =
        Record::sign(history.preview(None, "a".repeat(64)).unwrap(), &identity(9)).unwrap();
    let minimum = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(minimum);
    let write = |name: &str, bytes: &[u8]| {
        let path = local.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let signer = write("owner.key", &[9; 32]);
    let issuer = write("issuer.key", &[8; 32]);
    let private = write("capture.key", &PRIVATE);
    let state = local.path().join("owner.sqlite");
    let readers = || {
        let workspace =
            kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
        let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":OWNER,"max_jobs":10,"targets":[{"kind":"capture-erasure","id":"capture","root":f.root,"history":history,"signing_key":signer,"issuer_key":issuer,"private_keys":[private],"root_batch_records":1}]})).unwrap(),workspace).unwrap();
        kan::evidence_library::Readers::new(None, vec![server.client(&f)])
            .unwrap()
            .with_owner(owner)
    };
    let ui = Ui::start(readers()).await;
    owner_call(&ui,OWNER,json!({"action":"preview-erasure-selection","target":"capture","selection":{"kind":"capture","capture":{"writer":identity(6).did().as_str(),"observer":"collector","attempt":"a".repeat(64)}}}),400).await;
    let query = json!({"action":"preview-erasure-selection","target":"capture","selection":{"kind":"archive-prefix"}});
    owner_call(&ui, TOKEN, query.clone(), 401).await;
    let preview = owner_call(&ui, OWNER, query, 200).await;
    assert_eq!(preview["summary"]["objects"], 3);
    assert_eq!(preview["summary"]["pages"], 1);
    assert!(preview["summary"]["coverage"]
        .as_str()
        .unwrap()
        .contains("active captures"));
    assert_eq!(
        preview["plan"].as_object().unwrap().len(),
        1,
        "approval submits a retained reference, not client coordinates"
    );
    let inspected=owner_call(&ui,OWNER,json!({"action":"inspect-erasure-selection","target":"capture","selection":preview["plan"]["selection"],"page":0}),200).await;
    assert_eq!(inspected["targets"].as_array().unwrap().len(), 3);
    assert!(inspected["next"].is_null());
    assert_eq!(
        history.current().unwrap().history.len(),
        1,
        "preview and inspection publish no deletion authority"
    );
    owner_call(&ui,OWNER,json!({"action":"apply-erasure","target":"capture","plan":preview["plan"],"preview":"0".repeat(64),"wait":true}),400).await;
    let apply = json!({"action":"apply-erasure","target":"capture","plan":preview["plan"],"preview":preview["digest"],"wait":true});
    let first = owner_call(&ui, OWNER, apply.clone(), 200).await;
    assert_eq!(first["state"], "cleanup-pending", "{first}");
    assert_eq!(first["result"]["report"]["root_erasure"]["remaining"], 2);
    assert_eq!(history.current().unwrap().history.len(), 2);
    owner_call(&ui, OWNER, apply, 200).await;
    assert_eq!(
        history.current().unwrap().history.len(),
        2,
        "retry of accepted approval creates no extra batch"
    );
    ui.stop().await;
    // A later archive append and a different legitimate owner erasure change
    // both chains. Resume must retain the original selection and safely rebase.
    let previous = service::append_manifest(f.requests.last().unwrap())
        .unwrap()
        .cid()
        .to_string();
    let bytes = encrypted_frame(3, 8, Some(previous), b"later unselected object");
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    archive.admit(&bytes, &identity(8), &grant(), 200).unwrap();
    let native = kan::evidence_store::erasure::Record::sign(
        archive.preview_erasure(&[4], "c".repeat(64), 200).unwrap(),
        &identity(8),
    )
    .unwrap();
    let extra = Record::sign(
        history.preview(Some(native), "d".repeat(64)).unwrap(),
        &identity(9),
    )
    .unwrap();
    history.append(extra).unwrap();
    history.reconcile_archive(&f.root).unwrap();
    drop(archive);
    let ui = Ui::start(readers()).await;
    let resume = json!({"action":"resume-erasure","id":preview["digest"],"wait":true});
    let second = owner_call(&ui, OWNER, resume.clone(), 200).await;
    assert_eq!(
        second["result"]["report"]["root_erasure"]["remaining"], 1,
        "{second}"
    );
    let done = owner_call(&ui, OWNER, resume.clone(), 200).await;
    assert_eq!(done["state"], "configured-cleanup-complete", "{done}");
    assert_eq!(done["result"]["report"]["root_erasure"]["selected"], 3);
    assert_eq!(done["result"]["report"]["root_erasure"]["remaining"], 0);
    assert_eq!(done["result"]["report"]["backup_purge"], "not-performed");
    let current = history.current().unwrap();
    assert_eq!(current.history.len(), 5);
    assert!(
        attested::Archive::open_indexed(
            &f.root,
            f.binding.clone(),
            current.storage_tip().unwrap().as_deref()
        )
        .is_ok(),
        "completed owner erasure refreshes indexed ingest custody"
    );
    let roots = current
        .history
        .iter()
        .filter_map(|r| r.change.erasure.as_ref())
        .filter(|r| r.plan.targets[0].sequence != 4)
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 3);
    assert!(roots.iter().all(|r| r.plan.targets.len() == 1));
    assert_eq!(
        roots
            .iter()
            .map(|r| r.plan.targets[0].sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    drop(current);
    owner_call(&ui, OWNER, resume, 200).await;
    assert_eq!(history.current().unwrap().history.len(), 5);
    ui.stop().await;
    let journal = kan::evidence_workspace::Workspace::open(&state, identity(9), [84; 32]).unwrap();
    let current = history.current().unwrap();
    for record in current
        .history
        .iter()
        .skip(1)
        .filter(|r| r.change.erasure.as_ref().unwrap().plan.targets[0].sequence != 4)
    {
        let intent = journal
            .get(
                "owner-result",
                &format!(
                    "erasure:{}:root-intent:{}",
                    preview["digest"].as_str().unwrap(),
                    record.id().unwrap()
                ),
            )
            .unwrap()
            .unwrap();
        assert_eq!(intent["consent"], preview["digest"]);
        assert_eq!(intent["record"], serde_json::to_value(record).unwrap());
    }
    drop(current);
    drop(journal);
    server.stop().await;
}

#[tokio::test]
async fn explicit_capture_union_refuses_stale_consent_and_keeps_unselected_archive_payloads() {
    use kan::evidence_erasure_history::{Access, Record};
    let source = private_workspace_directory();
    let local = private_workspace_directory();
    let custody = private_workspace_directory();
    let frame = |n: u8| {
        let ordinal = n % 2;
        let attempt = if n < 2 { "a" } else { "b" }.repeat(64);
        let event = if ordinal == 0 {
            json!({"type":"started","method":"POST","route":"test"})
        } else {
            json!({"type":"terminal","outcome":"completed"})
        };
        let header=serde_json::to_vec(&json!({"version":2,"attempt":attempt,"observer":"collector","ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":event})).unwrap();
        let mut frame = b"KANC2".to_vec();
        frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
        frame.extend(header);
        frame
    };
    let f = fixture_requests(source.path(), Profile::Admitted, |n, a, p| {
        encrypted_frame(n, a, p, &frame(n))
    });
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    let previous = service::append_manifest(f.requests.last().unwrap())
        .unwrap()
        .cid()
        .to_string();
    let terminal = encrypted_frame(3, 8, Some(previous), &frame(3));
    let previous = archive
        .admit(&terminal, &identity(8), &grant(), 200)
        .unwrap()
        .record
        .manifest
        .cid()
        .to_string();
    let mut history:Access=serde_json::from_value(json!({"directory":custody.path(),"binding":{"profile":"admitted","archive":service::hex(&f.binding.archive),"scope":service::hex(&f.binding.scope),"issuer":f.binding.issuer},"owner":identity(9).did().as_str()})).unwrap();
    history.initialize().unwrap();
    let genesis =
        Record::sign(history.preview(None, "a".repeat(64)).unwrap(), &identity(9)).unwrap();
    let minimum = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(minimum);
    let write = |name: &str, bytes: &[u8]| {
        let path = local.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let signer = write("owner.key", &[9; 32]);
    let issuer = write("issuer.key", &[8; 32]);
    let private = write("capture.key", &PRIVATE);
    let workspace = kan::evidence_workspace::Workspace::open(
        &local.path().join("owner.sqlite"),
        identity(9),
        [84; 32],
    )
    .unwrap();
    let owner=kan::evidence_library::Owner::new(serde_json::from_value(json!({"token":"synthetic-capture-union-owner-token","max_jobs":10,"targets":[{"kind":"capture-erasure","id":"capture","root":f.root,"history":history,"signing_key":signer,"issuer_key":issuer,"private_keys":[private]}]})).unwrap(),workspace).unwrap();
    let capture = |attempt: &str| json!({"writer":identity(6).did().as_str(),"observer":"collector","attempt":attempt.repeat(64)});
    let query = json!({"action":"preview-erasure-selection","target":"capture","selection":{"kind":"captures","captures":[capture("a"),capture("b")]}});
    let preview = owner
        .execute(serde_json::from_value(query.clone()).unwrap())
        .await
        .unwrap();
    assert_eq!(preview["summary"]["objects"], 4);
    let later = encrypted_frame(4, 8, Some(previous), b"keep this opaque later payload");
    archive.admit(&later, &identity(8), &grant(), 201).unwrap();
    let request = |p: &Value| {
        serde_json::from_value(json!({"action":"apply-erasure","target":"capture","plan":p["plan"],"preview":p["digest"],"wait":true})).unwrap()
    };
    assert!(matches!(
        owner.execute(request(&preview)).await,
        Err(service::Failure::Conflict)
    ));
    assert_eq!(
        history.current().unwrap().history.len(),
        1,
        "stale approval publishes no authority"
    );
    let preview = owner
        .execute(serde_json::from_value(query).unwrap())
        .await
        .unwrap();
    assert_eq!(preview["summary"]["objects"], 4);
    assert_eq!(preview["summary"]["through"], 5);
    let done = owner.execute(request(&preview)).await.unwrap();
    assert_eq!(done["state"], "configured-cleanup-complete", "{done}");
    let proof = attested::Archive::verify_file(&f.db(), f.binding.clone()).unwrap();
    assert_eq!(proof.erased_objects, 4);
    let inventory =
        Inventory::open(&f.db(), Profile::Admitted, f.binding.clone(), budget()).unwrap();
    let page = inventory
        .page(
            None,
            PageBudget {
                rows: 5,
                record_bytes: 1024 * 1024,
                payload_bytes: 16 * 1024 * 1024,
            },
            budget(),
        )
        .unwrap();
    assert_eq!(page.records[0].availability, Availability::Available);
    assert!(page
        .records
        .iter()
        .skip(1)
        .all(|r| r.availability == Availability::Erased));
}
