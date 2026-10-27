#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_service::{hex, Grant, Service, SignedRequest},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Output, Stdio},
};
const SCOPE: [u8; 32] = [42; 32];
const PRIVATE: [u8; 32] = [29; 32];
const CANARY: &[u8] = b"raw-private-delivery-canary\0\xff\n{not-json}";
fn cli(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
struct Server(std::process::Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn server(root: &Path, signer: &Identity, grants: &[Grant]) -> (Server, String) {
    let archive = root.join("archive");
    drop(Ledger::create(&archive).unwrap());
    let key = root.join("server.key");
    signer.save(&key).unwrap();
    let config = root.join("grants.json");
    std::fs::write(&config, serde_json::to_vec(grants).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args([
            "serve",
            archive.to_str().unwrap(),
            "--scope",
            &hex(&SCOPE),
            "--signing-key",
            key.to_str().unwrap(),
            "--grants",
            config.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(!line.is_empty(), "server did not start");
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    (
        Server(child),
        format!("http://{}/v1/rpc", value["listen"].as_str().unwrap()),
    )
}
fn grant(writer: &Identity) -> Grant {
    Grant {
        principal: writer.did().to_string(),
        append: true,
        inventory: false,
    }
}
fn init(path: &Path, writer: &Identity, server: &Identity, budget: u64) {
    success(&cli(
        &[
            "spool-init",
            path.to_str().unwrap(),
            "--scope",
            &hex(&SCOPE),
            "--writer",
            writer.did().as_str(),
            "--audience",
            server.did().as_str(),
            "--budget",
            &budget.to_string(),
        ],
        &[],
    ));
}
fn queue(path: &Path, key: &Path, id: u8, input: &[u8]) -> Output {
    cli(
        &[
            "queue-input",
            path.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--operation",
            &hex(&[id; 16]),
        ],
        input,
    )
}
fn status(path: &Path, id: u8) -> serde_json::Value {
    let out = cli(
        &[
            "spool-status",
            path.to_str().unwrap(),
            "--operation",
            &hex(&[id; 16]),
        ],
        &[],
    );
    success(&out);
    serde_json::from_slice(&out.stdout).unwrap()
}
fn private_file(path: &Path, key: &[u8]) {
    std::fs::write(path, key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
#[tokio::test]
async fn cli_offline_admission_lost_reply_restart_bounded_drain_and_recovery() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("queue.sqlite");
    let writer = Identity::generate();
    let destination = Identity::generate();
    let key = t.path().join("writer.key");
    writer.save(&key).unwrap();
    init(&path, &writer, &destination, 10_000_000);
    assert!(status(&path, 1)["operation"].is_null());
    success(&queue(&path, &key, 1, CANARY));
    success(&queue(&path, &key, 2, b"second raw event"));
    let original = Spool::open(&path).unwrap().head().unwrap().unwrap();
    let exported = cli(&["spool-head", path.to_str().unwrap()], &[]);
    success(&exported);
    assert_eq!(exported.stdout, original);
    // A known unused local port: no server is available and exact pending bytes survive.
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let offline = format!("http://{}/v1/rpc", socket.local_addr().unwrap());
    drop(socket);
    assert!(!cli(
        &[
            "spool-drain",
            path.to_str().unwrap(),
            "--endpoint",
            &offline
        ],
        &[]
    )
    .status
    .success());
    assert_eq!(
        Spool::open(&path).unwrap().head().unwrap().unwrap(),
        original
    );
    let (_server, endpoint) = server(t.path(), &destination, &[grant(&writer)]);
    // Commit remotely but lose the acknowledgment before the client sees it.
    kan::evidence_http::send(&endpoint, destination.did().as_str(), &original)
        .await
        .unwrap();
    assert!(status(&path, 1)["operation"]["pending"].as_bool().unwrap());
    let first = cli(
        &[
            "spool-drain",
            path.to_str().unwrap(),
            "--endpoint",
            &endpoint,
            "--limit",
            "1",
        ],
        &[],
    );
    success(&first);
    assert_eq!(String::from_utf8(first.stdout).unwrap().lines().count(), 2);
    assert_eq!(status(&path, 1)["operation"]["pending"], false);
    assert_eq!(status(&path, 2)["status"]["pending"], 1);
    let mut concurrent = Spool::open(&path).unwrap();
    let second = concurrent.head().unwrap();
    assert!(
        matches!(
            delivery::deliver_expected(&mut concurrent, "not-an-endpoint", &original).await,
            Err(delivery::Error::Spool(kan::evidence_spool::Error::Conflict))
        ),
        "a previously checked head cannot authorize its successor"
    );
    assert_eq!(concurrent.head().unwrap(), second);
    drop(concurrent);
    assert!(!queue(&path, &key, 1, CANARY).status.success());
    success(&cli(
        &[
            "spool-drain",
            path.to_str().unwrap(),
            "--endpoint",
            &endpoint,
        ],
        &[],
    ));
    assert_eq!(status(&path, 2)["operation"]["pending"], false);
    assert_eq!(status(&path, 2)["status"]["pending"], 0);
    let ledger = Ledger::open(&t.path().join("archive")).unwrap();
    assert_eq!(ledger.verify().unwrap().commits, 2);
    ledger.backup(&t.path().join("backup.sqlite")).unwrap();
    for file in [&path, &t.path().join("backup.sqlite")] {
        assert!(!std::fs::read(file)
            .unwrap()
            .windows(CANARY.len())
            .any(|w| w == CANARY));
    }
    let request = t.path().join("request.json");
    std::fs::write(&request, &original).unwrap();
    let private = t.path().join("recipient.key");
    private_file(&private, &PRIVATE);
    let decrypted = cli(
        &[
            "decrypt-request",
            request.to_str().unwrap(),
            "--recipient-key",
            private.to_str().unwrap(),
            "--scope",
            &hex(&SCOPE),
            "--writer",
            writer.did().as_str(),
        ],
        &[],
    );
    success(&decrypted);
    assert_eq!(decrypted.stdout, CANARY);
    // A repeated empty drain is harmless, including after reopening the queue.
    success(&cli(
        &[
            "spool-drain",
            path.to_str().unwrap(),
            "--endpoint",
            &endpoint,
        ],
        &[],
    ));
}

#[test]
fn admission_errors_never_advance_the_frontier() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let destination = Identity::generate();
    let key = t.path().join("writer.key");
    writer.save(&key).unwrap();
    let wrong = t.path().join("wrong.key");
    Identity::generate().save(&wrong).unwrap();
    init(&path, &writer, &destination, 10_000_000);
    assert!(!queue(&path, &wrong, 1, CANARY).status.success());
    assert!(!queue(&path, &key, 1, &vec![7; crypto::MAX_PLAINTEXT + 1])
        .status
        .success());
    assert_eq!(status(&path, 1)["status"]["next"], 0);
    success(&queue(&path, &key, 1, CANARY));
    let original = Spool::open(&path).unwrap().head().unwrap().unwrap();
    assert!(!queue(&path, &key, 1, b"changed input").status.success());
    assert_eq!(status(&path, 1)["status"]["next"], 1);
    assert_eq!(
        Spool::open(&path).unwrap().head().unwrap().unwrap(),
        original
    );
    let tiny = t.path().join("tiny.sqlite");
    init(&tiny, &writer, &destination, 1);
    let full = queue(&tiny, &key, 2, CANARY);
    assert!(!full.status.success());
    assert!(String::from_utf8_lossy(&full.stderr).contains("capacity exhausted"));
    assert_eq!(status(&tiny, 2)["status"]["next"], 0);
    assert!(!cli(
        &[
            "spool-drain",
            path.to_str().unwrap(),
            "--endpoint",
            "http://127.0.0.1:1/v1/rpc",
            "--limit",
            "0"
        ],
        &[]
    )
    .status
    .success());
}

#[test]
fn offline_decryption_requires_all_pins_and_private_key_permissions() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let destination = Identity::generate();
    let mut spool = Spool::create(
        &path,
        &hex(&SCOPE),
        writer.did().as_str(),
        destination.did().as_str(),
        10_000_000,
    )
    .unwrap();
    delivery::queue(
        &mut spool,
        &writer,
        &crypto::public_key(&PRIVATE).unwrap(),
        &[1; 16],
        CANARY,
    )
    .unwrap();
    let bytes = spool.head().unwrap().unwrap();
    let request = t.path().join("request.json");
    std::fs::write(&request, &bytes).unwrap();
    let private = t.path().join("recipient.key");
    private_file(&private, &PRIVATE);
    let decrypt = |scope: &[u8; 32], who: &str| {
        cli(
            &[
                "decrypt-request",
                request.to_str().unwrap(),
                "--recipient-key",
                private.to_str().unwrap(),
                "--scope",
                &hex(scope),
                "--writer",
                who,
            ],
            &[],
        )
    };
    for output in [
        decrypt(&[0; 32], writer.did().as_str()),
        decrypt(&SCOPE, destination.did().as_str()),
    ] {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    private_file(&private, &[7; 32]);
    let out = decrypt(&SCOPE, writer.did().as_str());
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        private_file(&private, &PRIVATE);
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = decrypt(&SCOPE, writer.did().as_str());
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        std::fs::remove_file(&private).unwrap();
        let target = t.path().join("target.key");
        private_file(&target, &PRIVATE);
        std::os::unix::fs::symlink(&target, &private).unwrap();
        assert!(!decrypt(&SCOPE, writer.did().as_str()).status.success());
    }
    let mut malformed = bytes.clone();
    malformed.push(b'\n');
    assert!(
        delivery::decrypt_request(&malformed, &PRIVATE, &SCOPE, writer.did().as_str()).is_err()
    );
}

#[tokio::test]
async fn remote_rejections_preserve_head_and_stale_ack_cannot_remove_next() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let destination = Identity::generate();
    let mut spool = Spool::create(
        &path,
        &hex(&SCOPE),
        writer.did().as_str(),
        destination.did().as_str(),
        10_000_000,
    )
    .unwrap();
    let recipient = crypto::public_key(&PRIVATE).unwrap();
    delivery::queue(&mut spool, &writer, &recipient, &[1; 16], CANARY).unwrap();
    delivery::queue(&mut spool, &writer, &recipient, &[2; 16], b"next").unwrap();
    let original = spool.head().unwrap().unwrap();
    let denied = tempfile::tempdir().unwrap();
    let (_denied, endpoint) = server(denied.path(), &destination, &[]);
    assert!(delivery::deliver_one(&mut spool, &endpoint).await.is_err());
    assert_eq!(spool.head().unwrap().unwrap(), original);
    let impostor = tempfile::tempdir().unwrap();
    let (_impostor, endpoint) = server(impostor.path(), &Identity::generate(), &[grant(&writer)]);
    assert!(delivery::deliver_one(&mut spool, &endpoint).await.is_err());
    assert_eq!(spool.head().unwrap().unwrap(), original);
    let real = tempfile::tempdir().unwrap();
    let (_real, endpoint) = server(real.path(), &destination, &[grant(&writer)]);
    let reply = kan::evidence_http::send(&endpoint, destination.did().as_str(), &original)
        .await
        .unwrap()
        .bytes()
        .unwrap();
    delivery::deliver_one(&mut spool, &endpoint)
        .await
        .unwrap()
        .unwrap();
    let second = spool.head().unwrap().unwrap();
    assert!(spool.acknowledge(&reply).is_err());
    assert_eq!(spool.head().unwrap().unwrap(), second);
    assert_eq!(
        delivery::deliver_one(&mut spool, &endpoint)
            .await
            .unwrap()
            .unwrap()
            .position,
        1
    );
}

#[test]
fn maximum_and_empty_inputs_and_exact_request_provenance() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let destination = Identity::generate();
    let mut spool = Spool::create(
        &path,
        &hex(&SCOPE),
        writer.did().as_str(),
        destination.did().as_str(),
        10_000_000,
    )
    .unwrap();
    let mut service = Service::new(
        Ledger::create(&t.path().join("archive")).unwrap(),
        SCOPE,
        destination,
        vec![grant(&writer)],
    )
    .unwrap();
    for (i, input) in [vec![], vec![0xff; crypto::MAX_PLAINTEXT]]
        .iter()
        .enumerate()
    {
        let outcome = delivery::queue(
            &mut spool,
            &writer,
            &crypto::public_key(&PRIVATE).unwrap(),
            &[i as u8; 16],
            input,
        )
        .unwrap();
        let bytes = spool.head().unwrap().unwrap();
        SignedRequest::decode(&bytes).unwrap();
        assert_eq!(
            delivery::decrypt_request(&bytes, &PRIVATE, &SCOPE, writer.did().as_str()).unwrap(),
            *input
        );
        assert_eq!(outcome.position, i as u64);
        let reply = service.dispatch(&bytes, 1).unwrap().bytes().unwrap();
        spool.acknowledge(&reply).unwrap();
        assert!(
            !spool
                .operation(&hex(&[i as u8; 16]))
                .unwrap()
                .unwrap()
                .pending
        );
    }
}
