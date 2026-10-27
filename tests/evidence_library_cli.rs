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
        Process::new(env!("CARGO_BIN_EXE_kan"))
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
    // The real stdio entry point uses these same Reader keys and remote grants,
    // without creating an HTTP listener or requiring a browser token.
    // A legacy-project reminder must not introduce any non-JSON MCP stdout.
    std::fs::create_dir(dir.path().join(".claims")).unwrap();
    for writes in [false, true] {
        use tokio::io::{AsyncWriteExt, BufReader as TokioBufReader};
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan"));
        command.args([
            "library",
            "--config",
            config.to_str().unwrap(),
            "--signing-key",
            signer.to_str().unwrap(),
            "--mcp",
        ]);
        if writes {
            command.arg("--mcp-writes");
        }
        let mut process = command
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = process.stdin.take().unwrap();
        let mut output = TokioBufReader::new(process.stdout.take().unwrap());
        let init=mcp_request(&mut input,&mut output,1,"initialize",serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"v2-test","version":"1"}})).await;
        assert!(init["result"]["capabilities"]["tools"].is_object());
        input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        let tools = mcp_request(
            &mut input,
            &mut output,
            2,
            "tools/list",
            serde_json::json!({}),
        )
        .await;
        let names: Vec<_> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"kan_v2_read"));
        assert_eq!(names.contains(&"kan_v2_write"), writes);
        assert!(!names.contains(&"kan_v2_owner"));
        let write=mcp_request(&mut input,&mut output,6,"tools/call",serde_json::json!({"name":"kan_v2_write","arguments":{"query":{"action":"unknown-future-action"}}})).await;
        if writes {
            assert_eq!(
                write["result"]["structuredContent"]["error"],
                "invalid-request"
            );
        } else {
            assert!(write["error"].is_object());
        }
        let result=mcp_request(&mut input,&mut output,3,"tools/call",serde_json::json!({"name":"kan_v2_read","arguments":{"query":{"action":"source","pin":pin,"sequence":1,"offset":0,"length":100}}})).await;
        assert_eq!(result["result"]["isError"], false);
        assert_eq!(result["result"]["structuredContent"], source);
        let refused=mcp_request(&mut input,&mut output,4,"tools/call",serde_json::json!({"name":"kan_v2_read","arguments":{"query":{"action":"annotation-drain","destination":"unapproved"}}})).await;
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(
            refused["result"]["structuredContent"]["error"],
            "capability-required"
        );
        let unknown=mcp_request(&mut input,&mut output,5,"tools/call",serde_json::json!({"name":"kan_v2_read","arguments":{"query":{"action":"unknown-future-action"}}})).await;
        assert_eq!(unknown["result"]["isError"], true);
        assert_eq!(
            unknown["result"]["structuredContent"]["error"],
            "invalid-request"
        );
        drop(input);
        assert!(tokio::time::timeout(Duration::from_secs(5), process.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
}
async fn mcp_request(
    input: &mut tokio::process::ChildStdin,
    output: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    id: u64,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    input
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["id"], id);
    value
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
    let initialized = Process::new(env!("CARGO_BIN_EXE_kan"))
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
        let out = Process::new(env!("CARGO_BIN_EXE_kan"))
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
    let reader_config=write("mcp-reader.json",serde_json::to_vec(&json!([{"scope":svc::hex(&[2;32]),"endpoint":"http://127.0.0.1:1/v1/rpc","issuer":binding["issuer"],"private_key_file":recipient}])).unwrap());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        use tokio::io::{AsyncWriteExt,BufReader as TokioBufReader};
        for enabled in [false,true] {
            let mut command=tokio::process::Command::new(env!("CARGO_BIN_EXE_kan"));
            command.args(["library","--config",reader_config.to_str().unwrap(),"--signing-key",key.to_str().unwrap(),"--owner-config",config.to_str().unwrap(),"--mcp"]);
            if enabled {command.arg("--mcp-owner");}
            let mut child=command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
            let mut input=child.stdin.take().unwrap();let mut output=TokioBufReader::new(child.stdout.take().unwrap());
            mcp_request(&mut input,&mut output,1,"initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"owner-test","version":"1"}})).await;
            input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
            let tools=mcp_request(&mut input,&mut output,2,"tools/list",json!({})).await;
            assert_eq!(tools["result"]["tools"].as_array().unwrap().iter().any(|t|t["name"]=="kan_v2_owner"),enabled);
            let result=mcp_request(&mut input,&mut output,3,"tools/call",json!({"name":"kan_v2_owner","arguments":{"query":{"action":"catalog"}}})).await;
            if enabled {assert_eq!(result["result"]["structuredContent"]["owner"],signer.did().as_str());assert_eq!(result["result"]["structuredContent"]["targets"][0]["id"],"access");}
            else {assert!(result["error"].is_object());}
            drop(input);assert!(tokio::time::timeout(Duration::from_secs(5),child.wait()).await.unwrap().unwrap().success());
        }
    });
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
    let initialized = Process::new(env!("CARGO_BIN_EXE_kan"))
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
        let out = Process::new(env!("CARGO_BIN_EXE_kan"))
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

#[test]
fn managed_owner_launch_requires_the_registered_cleanup_inventory() {
    use kan::{
        evidence_erasure_history as custody, evidence_store::attested,
        evidence_workspace::Workspace,
    };
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let signer = Identity::generate();
    let key = dir.path().join("owner.key");
    signer.save(&key).unwrap();
    let reader_key = dir.path().join("reader-signing.key");
    Identity::generate().save(&reader_key).unwrap();
    let private = write("recipient.key", &[37; 32]);
    let root = dir.path().join("archive");
    let offline = dir.path().join("offline-replica");
    let binding = attested::Binding {
        archive: [31; 32],
        scope: [32; 32],
        issuer: signer.did().to_string(),
    };
    attested::Archive::create(&root, binding.clone()).unwrap();
    let history_dir = tempfile::Builder::new()
        .prefix("custody-")
        .tempdir_in(dir.path())
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(history_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let mut history:custody::Access = serde_json::from_value(json!({"directory":history_dir.path(),"binding":{
        "profile":"admitted","archive":svc::hex(&binding.archive),"scope":svc::hex(&binding.scope),"issuer":binding.issuer},"owner":signer.did().as_str()})).unwrap();
    history.initialize().unwrap();
    let genesis =
        custody::Record::sign(history.preview(None, "a".repeat(64)).unwrap(), &signer).unwrap();
    let minimum = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(minimum);
    let history_file = write("custody.json", &serde_json::to_vec(&history).unwrap());
    let database = dir.path().join("reader.sqlite");
    drop(
        Workspace::open(
            &database,
            Identity::load_existing(&reader_key).unwrap(),
            [37; 32],
        )
        .unwrap(),
    );
    let guard = write("workspace.json", &serde_json::to_vec(&json!({"database":database,"signing_key":reader_key,"recipient_key":private,"sources":[history]})).unwrap());
    let deployment = write(
        "deployment.json",
        &serde_json::to_vec(&json!({"version":1,
        "archives":[{"root":root,"history":history_file},{"root":offline,"history":history_file}],
        "workspaces":[{"database":database,"guard":guard}]}))
        .unwrap(),
    );
    let journal = dir.path().join("owner.sqlite");
    let mut config = json!({"journal":journal,"signing_key":key,"recipient_key":private,
        "authority":{"token":"synthetic-managed-owner-cli-token-123","max_jobs":10,"targets":[{
            "kind":"capture-erasure","id":"capture","root":root,"history":history,
            "signing_key":key,"issuer_key":key,"private_keys":[private]}]}});
    let request = write("request.json", br#"{"action":"catalog"}"#);
    let run = |config: &serde_json::Value| {
        let file = write("owner.json", &serde_json::to_vec(config).unwrap());
        Process::new(env!("CARGO_BIN_EXE_kan"))
            .arg("--deployment")
            .arg(&deployment)
            .arg("owner")
            .arg("--config")
            .arg(file)
            .arg("--request")
            .arg(&request)
            .output()
            .unwrap()
    };
    let omitted_replica = run(&config);
    assert!(!omitted_replica.status.success());
    assert!(String::from_utf8_lossy(&omitted_replica.stderr)
        .contains("omits a registered archive replica"));
    assert!(
        !journal.exists(),
        "invalid coverage must not initialize an owner journal"
    );
    config["authority"]["targets"][0]["replicas"] = json!([offline]);
    let omitted_workspace = run(&config);
    assert!(!omitted_workspace.status.success());
    assert!(String::from_utf8_lossy(&omitted_workspace.stderr)
        .contains("omits a registered dependent workspace"));
    config["authority"]["targets"][0]["workspaces"] =
        json!([{"database":database,"signing_key":reader_key,"recipient_key":private}]);
    let complete = run(&config);
    assert!(
        complete.status.success(),
        "{}",
        String::from_utf8_lossy(&complete.stderr)
    );
    let catalog: serde_json::Value = serde_json::from_slice(&complete.stdout).unwrap();
    assert_eq!(catalog["targets"][0]["id"], "capture");
    assert!(
        !offline.exists(),
        "inventory validation does not fabricate an offline replica"
    );
    let mut reader_sources = json!([{"scope":svc::hex(&binding.scope),"endpoint":"http://127.0.0.1:1/v2/read",
        "issuer":binding.issuer,"private_key_file":private,"protocol":kan::evidence_proof_service::PROTOCOL,
        "profile":"admitted","archive":svc::hex(&binding.archive)}]);
    let reader_config = write("reader.json", &serde_json::to_vec(&reader_sources).unwrap());
    let owner_config = dir.path().join("owner.json");
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        use tokio::io::{AsyncWriteExt, BufReader as TokioBufReader};
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan"));
        command.arg("--deployment").arg(&deployment).arg("library")
            .arg("--config").arg(&reader_config).arg("--signing-key").arg(&reader_key)
            .arg("--workspace").arg(&database).arg("--workspace-key").arg(&private)
            .arg("--owner-config").arg(&owner_config).arg("--mcp").arg("--mcp-owner");
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = TokioBufReader::new(child.stdout.take().unwrap());
        mcp_request(&mut input,&mut output,1,"initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"managed-test","version":"1"}})).await;
        input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        let result = mcp_request(&mut input,&mut output,2,"tools/call",json!({"name":"kan_v2_owner","arguments":{"query":{"action":"catalog"}}})).await;
        assert_eq!(result["result"]["structuredContent"]["targets"][0]["id"],"capture");
        drop(input);
        assert!(tokio::time::timeout(Duration::from_secs(5),child.wait()).await.unwrap().unwrap().success());
    });
    reader_sources[0]["archive"] = json!(svc::hex(&[33; 32]));
    write("reader.json", &serde_json::to_vec(&reader_sources).unwrap());
    let omitted_source = Process::new(env!("CARGO_BIN_EXE_kan"))
        .arg("--deployment")
        .arg(&deployment)
        .arg("library")
        .arg("--config")
        .arg(&reader_config)
        .arg("--signing-key")
        .arg(&reader_key)
        .arg("--workspace")
        .arg(&database)
        .arg("--workspace-key")
        .arg(&private)
        .arg("--request")
        .arg(&request)
        .output()
        .unwrap();
    assert!(!omitted_source.status.success());
    assert!(String::from_utf8_lossy(&omitted_source.stderr)
        .contains("Library source is absent from managed custody"));
}
