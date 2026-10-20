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

#[test]
fn owner_cli_initializes_and_applies_the_same_previewed_access_policy() {
    use serde_json::{json, Value};
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let policy_dir = dir.path().join("policy");
    std::fs::create_dir(&policy_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&policy_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let signer = Identity::generate();
    let key = dir.path().join("owner.identity");
    signer.save(&key).unwrap();
    let binding = json!({"profile":"admitted","archive":svc::hex(&[1;32]),"scope":svc::hex(&[2;32]),"issuer":Identity::generate().did().as_str()});
    let policy = json!({"directory":policy_dir,"binding":binding,"owner":signer.did().as_str()});
    let write = |name: &str, bytes: Vec<u8>| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let policy_config = write("policy.json", serde_json::to_vec(&policy).unwrap());
    let initialized = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(["init-access-policy", policy_config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let recipient = write("journal.key", vec![91; 32]);
    let config=write("owner.json",serde_json::to_vec(&json!({"journal":dir.path().join("owner.sqlite"),"signing_key":key,"recipient_key":recipient,"authority":{"token":"synthetic-cli-policy-owner-token-1234","max_jobs":10,"targets":[{"kind":"access-policy","id":"access","policy":policy,"signing_key":key}]}})).unwrap());
    let call = |request: Value| -> Value {
        let path = write("request.json", serde_json::to_vec(&request).unwrap());
        let out = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args([
                "owner",
                "--config",
                config.to_str().unwrap(),
                "--request",
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let grants = json!([{"principal":signer.did().as_str(),"append":true,"inventory":false}]);
    let preview = call(json!({"action":"preview-access","target":"access","grants":grants}));
    assert_eq!(preview["change"]["grants"], grants);
    let request = json!({"action":"apply-access","target":"access","change":preview["change"],"preview":preview["digest"]});
    assert_eq!(call(request.clone())["state"], "applied");
    assert_eq!(call(request)["state"], "already-applied");
    assert_eq!(
        call(json!({"action":"access","target":"access"}))["snapshot"]["changes"],
        1
    );
}

#[test]
fn owner_cli_initializes_rotates_and_exports_wrapped_epoch_history() {
    use serde_json::{json, Value};
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let policy_dir = dir.path().join("policy");
    std::fs::create_dir(&policy_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&policy_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let signer = Identity::generate();
    let key = dir.path().join("owner.identity");
    signer.save(&key).unwrap();
    let binding = json!({"profile":"admitted","archive":svc::hex(&[1;32]),"scope":svc::hex(&[2;32]),"issuer":Identity::generate().did().as_str()});
    let policy = json!({"directory":policy_dir,"binding":binding,"owner":signer.did().as_str(),"recovery_recipient":svc::hex(&crypto::public_key(&[91;32]).unwrap())});
    let write = |name: &str, bytes: Vec<u8>| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let policy_config = write("policy.json", serde_json::to_vec(&policy).unwrap());
    let initialized = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(["init-key-history", policy_config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let recipient = write("journal.key", vec![91; 32]);
    let config=write("owner.json",serde_json::to_vec(&json!({"journal":dir.path().join("owner.sqlite"),"signing_key":key,"recipient_key":recipient,"authority":{"token":"synthetic-cli-policy-owner-token-1234","max_jobs":10,"targets":[{"kind":"key-history","id":"keys","history":policy,"signing_key":key,"recovery_key":recipient}]}})).unwrap());
    let call = |request: Value| -> Value {
        let path = write("request.json", serde_json::to_vec(&request).unwrap());
        let out = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args([
                "owner",
                "--config",
                config.to_str().unwrap(),
                "--request",
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let preview = call(json!({"action":"preview-key-rotation","target":"keys"}));
    let apply = json!({"action":"apply-key-rotation","target":"keys","change":preview["change"],"preview":preview["digest"]});
    assert_eq!(call(apply.clone())["state"], "applied");
    assert_eq!(call(apply)["state"], "already-applied");
    let package = call(json!({"action":"export-keys","target":"keys"}));
    assert_eq!(package["package"]["version"], "kan-key-recovery/1");
    assert_eq!(package["package"]["records"].as_array().unwrap().len(), 1);
    let epochs = call(json!({"action":"keys","target":"keys"}))["epoch_ids"].clone();
    let preview = call(
        json!({"action":"preview-key-transfer","target":"keys","recipient":svc::hex(&crypto::public_key(&[92;32]).unwrap()),"epochs":epochs,"purpose":"share-epochs"}),
    );
    let transferred = call(
        json!({"action":"apply-key-transfer","target":"keys","plan":preview["plan"],"preview":preview["digest"]}),
    );
    let recovery: kan::evidence_keys::RecoveryPackage =
        serde_json::from_value(transferred["package"].clone()).unwrap();
    assert!(recovery.records[0].change.unlock(&[92; 32]).is_ok());
    assert!(recovery.records[0].change.unlock(&[91; 32]).is_err());

    assert_eq!(
        call(json!({"action":"keys","target":"keys"}))["snapshot"]["epochs"],
        1
    );
}
