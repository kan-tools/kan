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
                if value["action"] == "proof-content"
                    || value["action"] == "proof-attempt"
                    || value["action"] == "proof-session"
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
        2
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
