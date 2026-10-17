#![cfg(feature = "v2-service")]
use kan::{
    evidence_service::{hex, Command, Failure, Grant, Output, Request, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command as Process, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn http_roundtrip_and_rejections() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    drop(Ledger::create(&root).unwrap());
    let signer = Identity::generate();
    let writer = Identity::generate();
    let reader = Identity::generate();
    let key = t.path().join("server.key");
    signer.save(&key).unwrap();
    let grants = t.path().join("grants.json");
    std::fs::write(
        &grants,
        serde_json::to_vec(&vec![
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
        ])
        .unwrap(),
    )
    .unwrap();
    let child = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args([
            "serve",
            root.to_str().unwrap(),
            "--scope",
            &hex(&[1; 32]),
            "--signing-key",
            key.to_str().unwrap(),
            "--grants",
            grants.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Child(child);
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(!line.is_empty(), "service failed to start");
    let startup: serde_json::Value = serde_json::from_str(&line).unwrap();
    let endpoint = format!("http://{}/v1/rpc", startup["listen"].as_str().unwrap());
    let unsigned = Request {
        version: 1,
        scope: hex(&[1; 32]),
        audience: signer.did().to_string(),
        principal: writer.did().to_string(),
        expires: None,
        command: Command::Append {
            id: hex(&[1; 16]),
            position: 0,
            previous: None,
            ciphertext: hex(b"opaque HTTP fixture"),
        },
    };
    // Actual CLI signing, including exact newline-free wire output.
    let writerkey = t.path().join("writer.key");
    writer.save(&writerkey).unwrap();
    let mut signing = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(["sign-request", "--key", writerkey.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    signing
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&unsigned).unwrap())
        .unwrap();
    let signed = signing.wait_with_output().unwrap();
    assert!(signed.status.success());
    SignedRequest::decode(&signed.stdout).unwrap();
    let reply = kan::evidence_http::send(&endpoint, signer.did().as_str(), &signed.stdout)
        .await
        .unwrap();
    assert!(matches!(
        reply.reply.result,
        Ok(Output::Committed {
            duplicate: false,
            ..
        })
    ));
    let retry = kan::evidence_http::send(&endpoint, signer.did().as_str(), &signed.stdout)
        .await
        .unwrap();
    assert!(matches!(
        retry.reply.result,
        Ok(Output::Committed {
            duplicate: true,
            ..
        })
    ));
    assert!(
        kan::evidence_http::send(&endpoint, reader.did().as_str(), &signed.stdout)
            .await
            .is_err()
    );
    let file = t.path().join("request.json");
    std::fs::write(&file, &signed.stdout).unwrap();
    let rpc = Process::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args([
            "rpc",
            file.to_str().unwrap(),
            "--endpoint",
            &endpoint,
            "--issuer",
            signer.did().as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        rpc.status.success(),
        "{}",
        String::from_utf8_lossy(&rpc.stderr)
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let read = |who: &Identity| {
        SignedRequest::sign(
            Request {
                version: 1,
                scope: hex(&[1; 32]),
                audience: signer.did().to_string(),
                principal: who.did().to_string(),
                expires: Some(now + 120),
                command: Command::Read { sequence: 1 },
            },
            who,
        )
        .unwrap()
        .bytes()
        .unwrap()
    };
    assert_eq!(
        kan::evidence_http::send(&endpoint, signer.did().as_str(), &read(&writer))
            .await
            .unwrap()
            .reply
            .result,
        Err(Failure::AccessLimited)
    );
    assert!(matches!(
        kan::evidence_http::send(&endpoint, signer.did().as_str(), &read(&reader))
            .await
            .unwrap()
            .reply
            .result,
        Ok(Output::Evidence { .. })
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(client.get(&endpoint).send().await.unwrap().status(), 404);
    assert_eq!(
        client
            .post(&endpoint)
            .body(vec![0; kan::evidence_service::MAX_REQUEST + 1])
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        kan::evidence_http::send(&endpoint, signer.did().as_str(), b"broken")
            .await
            .unwrap()
            .reply
            .result,
        Err(Failure::Invalid)
    );
    assert!(kan::evidence_http::bind("0.0.0.0:0".parse().unwrap())
        .await
        .is_err());
    assert!(kan::evidence_http::send(
        "http://example.com/v1/rpc",
        signer.did().as_str(),
        &signed.stdout
    )
    .await
    .is_err());
    assert!(kan::evidence_http::send(
        &format!("{endpoint}?unexpected=1"),
        signer.did().as_str(),
        &signed.stdout
    )
    .await
    .is_err());
    drop(child);
    assert_eq!(Ledger::open(&root).unwrap().verify().unwrap().commits, 1);
}
