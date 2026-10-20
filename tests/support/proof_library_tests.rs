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
            .post(
                if value["action"] == "proof-content" || value["action"] == "proof-attempt" {
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
    let body = br#"{"messages":[{"role":"user","content":"Hello proof archive"}]}"#;
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
    // Reuse only an explicitly supplied synthetic fixture. Normal CI still
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
