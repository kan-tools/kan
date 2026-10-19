#![cfg(feature = "v2-crypto")]
// Black-box contract intentionally uses only APIs that predate the Library.
// Whole-feature reversion must compile this test and fail a runtime assertion.
use kan::{
    evidence_crypto as crypto,
    evidence_service::{self as svc, Command, Grant, Request, Service, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command as Process, Stdio},
    time::Duration,
};
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct TaskGuard(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn library_cli_browses_authenticated_retained_source_without_storage_authority() {
    let dir = tempfile::tempdir().unwrap();
    let scope = [41; 32];
    let private = [42; 32];
    let owner = Identity::generate();
    let writer = Identity::generate();
    let reader = Identity::generate();
    let signer = dir.path().join("reader.identity");
    reader.save(&signer).unwrap();
    let key = dir.path().join("recipient.key");
    let token = dir.path().join("reader.token");
    let config = dir.path().join("reader.json");
    std::fs::write(&key, private).unwrap();
    std::fs::write(&token, b"synthetic-cli-library-reader-token").unwrap();
    let issuer = owner.did().to_string();
    let mut service = Service::new(
        Ledger::create(&dir.path().join("archive")).unwrap(),
        scope,
        owner,
        vec![
            Grant {
                principal: writer.did().to_string(),
                append: true,
                inventory: false,
            },
            Grant {
                principal: reader.did().to_string(),
                append: false,
                inventory: true,
            },
        ],
    )
    .unwrap();
    let plaintext = b"retained-source-black-box\0\xff<script>do not execute</script>";
    let append = SignedRequest::sign(
        Request {
            version: 1,
            scope: svc::hex(&scope),
            principal: writer.did().to_string(),
            audience: issuer.clone(),
            expires: None,
            command: Command::Append {
                id: svc::hex(&[1; 16]),
                position: 0,
                previous: None,
                ciphertext: svc::hex(
                    &crypto::seal(&crypto::public_key(&private).unwrap(), &scope, plaintext)
                        .unwrap(),
                ),
            },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert!(service
        .dispatch(&append, kan::evidence_operations::now())
        .unwrap()
        .reply
        .result
        .is_ok());
    let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let _service = TaskGuard(tokio::spawn(kan::evidence_http::serve(listener, service)));
    std::fs::write(&config,serde_json::to_vec(&serde_json::json!([{"scope":svc::hex(&scope),"endpoint":endpoint,"issuer":issuer,"private_key_file":key}])).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [&key, &token, &config] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut child = ChildGuard(
        Process::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args([
                "library",
                "--config",
                config.to_str().unwrap(),
                "--signing-key",
                signer.to_str().unwrap(),
                "--token-file",
                token.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let announced = std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stderr).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Library must announce startup within its fixture deadline");
    announced.join().unwrap();
    assert!(
        line.starts_with("library http://127.0.0.1:"),
        "Library CLI must start its real authenticated reader; got {line:?}"
    );
    let base = line.trim().strip_prefix("library ").unwrap();
    let url = format!("{base}/api/library");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let query = |value: serde_json::Value| {
        client
            .post(&url)
            .header("content-type", "application/json")
            .bearer_auth("synthetic-cli-library-reader-token")
            .body(value.to_string())
    };
    let response = query(serde_json::json!({"action":"catalog"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let catalog: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(catalog["scopes"].as_array().unwrap().len(), 1);
    let pin = &catalog["scopes"][0]["pin"];
    let response = query(serde_json::json!({"action":"page","pin":pin,"after":0,"limit":20}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    let response = query(
        serde_json::json!({"action":"source","pin":pin,"sequence":1,"offset":0,"length":100}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let source: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        svc::unhex(source["bytes_hex"].as_str().unwrap(), 100).unwrap() == plaintext,
        "source bytes must match the independently retained plaintext exactly"
    );
    assert_eq!(source["record"], page["records"][0]);
    assert!(source["utf8"].is_null());
    assert_eq!(
        query(serde_json::json!({"action":"rotate"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client.post(&url).body("{}").send().await.unwrap().status(),
        401
    );
    let html = client.get(base).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("/theme.js"));
    assert!(html.contains("Source inspector"));
}
