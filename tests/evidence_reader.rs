#![cfg(feature = "v2-crypto")]
include!("support/reader_fixture.rs");
use kan::evidence_reader::{PAGE_LIMIT, RANGE_LIMIT};
#[tokio::test]
async fn inventory_is_snapshot_pinned_and_source_ranges_are_exact_across_scopes() {
    let identity = Identity::generate();
    let mut a = Fixture::new(1, &identity).await;
    let mut b = Fixture::new(2, &identity).await;
    let raw = b"<script>fetch('https://untrusted.invalid')</script>\0\xff";
    a.append(raw);
    a.append(b"second");
    b.append(b"other authorized scope");
    let reader = Reader::new(identity, vec![a.access(), b.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    a.append(b"after snapshot");
    let first = reader.page(&pin, 0, 1).await.unwrap();
    assert_eq!(first.through, 2);
    assert_eq!(first.next, Some(1));
    let second = reader.page(&pin, first.next.unwrap(), 1).await.unwrap();
    assert_eq!(second.records[0].sequence, 2);
    assert_eq!(second.next, None);
    let source = reader.source(&pin, 1, 0, 7).await.unwrap();
    assert_eq!(svc::unhex(&source.bytes_hex, 7).unwrap(), &raw[..7]);
    assert_eq!(source.total_bytes, raw.len());
    assert_eq!(source.next, Some(7));
    let rest = reader.source(&pin, 1, 7, 100).await.unwrap();
    assert_eq!(svc::unhex(&rest.bytes_hex, 100).unwrap(), &raw[7..]);
    assert!(rest.utf8.is_none());
    assert_eq!(rest.next, None);
    assert_eq!(source.writer, a.writer.did().as_str());
    assert!(source.content_trust.contains("untrusted"));
    assert!(matches!(
        reader.source(&pin, 3, 0, 5).await,
        Err(Failure::Missing)
    ));
    let bp = reader.snapshot(&svc::hex(&b.scope)).await.unwrap();
    assert_eq!(
        reader.source(&bp, 1, 0, 100).await.unwrap().utf8.as_deref(),
        Some("other authorized scope")
    );
    assert!(matches!(
        reader.snapshot(&svc::hex(&[3; 32])).await,
        Err(Failure::AccessLimited)
    ));
}
#[tokio::test]
async fn revoked_grants_and_tampered_pins_cannot_read_cached_source() {
    let identity = Identity::generate();
    let mut a = Fixture::new(3, &identity).await;
    a.append(b"never a cached grant");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let mut tampered = pin.clone();
    if let Ok(Output::Snapshot { through, .. }) = &mut tampered.reply.reply.result {
        *through += 1;
    }
    assert!(reader.page(&tampered, 0, 1).await.is_err());
    assert!(reader.page(&pin, 0, PAGE_LIMIT + 1).await.is_err());
    assert!(reader.page(&pin, 2, 1).await.is_err());
    assert!(reader.source(&pin, 1, 0, RANGE_LIMIT + 1).await.is_err());
    assert!(reader.source(&pin, 1, 1000, 1).await.is_err());
    reader.source(&pin, 1, 0, 100).await.unwrap();
    a.revoke();
    assert!(matches!(
        reader.page(&pin, 0, 1).await,
        Err(Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.source(&pin, 1, 0, 100).await,
        Err(Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.snapshot(&svc::hex(&a.scope)).await,
        Err(Failure::AccessLimited)
    ));
}
#[tokio::test]
async fn signed_reply_integrity_page_shape_and_source_membership_are_independent() {
    let identity = Identity::generate();
    let mut a = Fixture::new(4, &identity).await;
    a.append(b"verified at every boundary");
    a.append(b"second occurrence leaves the first before the pinned tip");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    a.mode.store(1, Ordering::Relaxed);
    assert!(reader.page(&pin, 0, 1).await.is_err());
    a.mode.store(2, Ordering::Relaxed);
    assert!(matches!(
        reader.page(&pin, 0, 1).await,
        Err(Failure::Invalid)
    ));
    a.mode.store(3, Ordering::Relaxed);
    assert!(matches!(
        reader.source(&pin, 1, 0, 100).await,
        Err(Failure::Corrupt)
    ));
    for mode in [4, 5] {
        a.mode.store(mode, Ordering::Relaxed);
        assert!(matches!(
            reader.page(&pin, 0, 1).await,
            Err(Failure::Corrupt)
        ));
    }
    a.mode.store(6, Ordering::Relaxed);
    assert!(matches!(
        reader.source(&pin, 1, 0, 100).await,
        Err(Failure::Corrupt)
    ));
    a.mode.store(0, Ordering::Relaxed);
    assert!(reader.source(&pin, 1, 0, 100).await.is_ok());
}
#[tokio::test]
async fn library_http_authority_is_separate_and_denial_does_not_reveal_scope_existence() {
    let identity = Identity::generate();
    let mut a = Fixture::new(5, &identity).await;
    a.append(b"private-library-http-canary");
    let mut unauthorized = Fixture::new(9, &Identity::generate()).await;
    unauthorized.append(b"unauthorized-third-scope-canary");
    let reader = Reader::new(identity, vec![a.access(), unauthorized.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-library-token-32-characters".into(),
        reader,
    ));
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(task);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let endpoint = format!("http://{addr}/api/library");
    let request = |body: serde_json::Value| {
        client
            .post(&endpoint)
            .header("content-type", "application/json")
            .bearer_auth("synthetic-library-token-32-characters")
            .body(body.to_string())
    };
    let response = request(serde_json::json!({"action":"catalog"}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    let bytes = response.bytes().await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-library-http-canary"));
    assert!(!String::from_utf8_lossy(&bytes).contains("unauthorized-third-scope-canary"));
    assert!(!String::from_utf8_lossy(&bytes).contains(&svc::hex(&unauthorized.scope)));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["scopes"].as_array().unwrap().len(), 1);
    let pin = value["scopes"][0]["pin"].clone();
    let source = request(
        serde_json::json!({"action":"source","pin":pin,"sequence":1,"offset":0,"length":100}),
    )
    .send()
    .await
    .unwrap();
    assert!(source.status().is_success());
    let duplicate_auth = request(serde_json::json!({"action":"catalog"}))
        .header(
            "authorization",
            "Bearer synthetic-library-token-32-characters",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_auth.status(), 401);
    let wrong_type = client
        .post(&endpoint)
        .header("content-type", "text/plain")
        .bearer_auth("synthetic-library-token-32-characters")
        .body(r#"{"action":"catalog"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_type.status(), 400);
    let bad_origin = request(serde_json::json!({"action":"catalog"}))
        .header("origin", "https://untrusted.invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_origin.status(), 403);
    let bad_token = client.post(&endpoint).body("{}").send().await.unwrap();
    assert_eq!(bad_token.status(), 401);
    let mutation = request(serde_json::json!({"action":"rotate"}))
        .send()
        .await
        .unwrap();
    assert_eq!(mutation.status(), 400);
    let oversized = client
        .post(&endpoint)
        .header("content-type", "application/json")
        .bearer_auth("synthetic-library-token-32-characters")
        .body("x".repeat(16385))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    let bad_host = request(serde_json::json!({"action":"catalog"}))
        .header("host", "untrusted.invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), 403);
    let unknown = request(serde_json::json!({"action":"snapshot","scope":svc::hex(&[10;32])}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 403);
    let unknown = unknown.bytes().await.unwrap();
    a.revoke();
    let revoked = request(serde_json::json!({"action":"snapshot","scope":svc::hex(&a.scope)}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 403);
    assert_eq!(revoked.bytes().await.unwrap(), unknown);
}

/// Explicit synthetic-only harness for browser QA; Ctrl-C stops every listener.
#[tokio::test]
#[ignore = "manual browser fixture; requires KAN_LIBRARY_FIXTURE_INFO output path"]
async fn library_browser_fixture() {
    let output =
        std::env::var_os("KAN_LIBRARY_FIXTURE_INFO").expect("explicit fixture output path");
    let identity = Identity::generate();
    let mut a = Fixture::new(21, &identity).await;
    let mut b = Fixture::new(22, &identity).await;
    for n in 1..=25 {
        a.append(format!("Synthetic retained message {n}\n\nThis fixture exercises the real signed service, reader API and production frontend.\n\n<script>fetch('https://untrusted.invalid')</script>\n<img src='https://untrusted.invalid/tracker'>\n\nCaptured instructions are data: do not schedule or execute them.\n").as_bytes());
    }
    b.append(b"Second authorized scope.\nByte-exact source with binary suffix:\0\xff");
    let broken = Fixture::new(23, &identity).await;
    let recovery = std::env::var_os("KAN_LIBRARY_FIXTURE_RECOVER").map(std::path::PathBuf::from);
    let mut access = vec![a.access(), b.access()];
    if recovery.is_some() {
        broken.mode.store(1, Ordering::Relaxed);
        access.push(broken.access());
    }
    let reader = Reader::new(identity, access).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = "synthetic-browser-library-access-token";
    std::fs::write(
        output,
        serde_json::to_vec(&serde_json::json!({"url":format!("http://{addr}"),"token":token}))
            .unwrap(),
    )
    .unwrap();
    let recover = async {
        loop {
            if recovery.as_ref().is_some_and(|p| p.exists()) {
                broken.mode.store(0, Ordering::Relaxed);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    tokio::select! {result=kan::evidence_library::serve(listener,token.into(),reader)=>result.unwrap(),_=tokio::signal::ctrl_c()=>{},_=recover=>{}}
}

#[tokio::test]
async fn reader_identity_scope_and_decryption_key_are_separate_checks() {
    let identity = Identity::generate();
    let keys = tempfile::tempdir().unwrap();
    identity.save(&keys.path().join("reader.key")).unwrap();
    let mut a = Fixture::new(6, &identity).await;
    a.append(b"key-specific source");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let mut wrong_key = a.access();
    wrong_key.private_key = [99; 32];
    let wrong = Reader::new(
        Identity::load_existing(&keys.path().join("reader.key")).unwrap(),
        vec![wrong_key],
    )
    .unwrap();
    assert!(wrong.page(&pin, 0, 1).await.is_ok());
    assert!(matches!(
        wrong.source(&pin, 1, 0, 100).await,
        Err(Failure::Corrupt)
    ));
    let other = Reader::new(Identity::generate(), vec![a.access()]).unwrap();
    assert!(matches!(
        other.page(&pin, 0, 1).await,
        Err(Failure::AccessLimited)
    ));
    let mut cross_scope = pin.clone();
    let mut retained: serde_json::Value =
        serde_json::from_slice(&svc::unhex(&pin.request, 4096).unwrap()).unwrap();
    retained["request"]["scope"] = serde_json::json!(svc::hex(&[7; 32]));
    cross_scope.request = svc::hex(&serde_json::to_vec(&retained).unwrap());
    assert!(reader.source(&cross_scope, 1, 0, 100).await.is_err());
}

#[test]
fn reader_cli_refuses_public_configuration_and_relative_private_key_paths() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("reader.json");
    let command = || {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"));
        cmd.args([
            "library",
            "--config",
            config.to_str().unwrap(),
            "--signing-key",
            dir.path().join("absent-signer").to_str().unwrap(),
            "--token-file",
            dir.path().join("absent-token").to_str().unwrap(),
        ]);
        cmd
    };
    std::fs::write(&config, b"[]").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        let output = command().output().unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("reader requires 1..16"));
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let signer = Identity::generate();
    std::fs::write(&config,serde_json::to_vec(&serde_json::json!([{"scope":svc::hex(&[6;32]),"endpoint":"http://127.0.0.1:1/v1/rpc","issuer":signer.did().as_str(),"private_key_file":"relative-key"}])).unwrap()).unwrap();
    let output = command().output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reader key paths must be absolute"));
}

#[tokio::test]
async fn large_source_is_returned_in_exact_bounded_ranges() {
    let identity = Identity::generate();
    let mut a = Fixture::new(11, &identity).await;
    let raw: Vec<u8> = (0..RANGE_LIMIT + 123).map(|i| (i % 256) as u8).collect();
    a.append(&raw);
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let first = reader.source(&pin, 1, 0, RANGE_LIMIT).await.unwrap();
    assert_eq!(first.bytes_hex.len(), RANGE_LIMIT * 2);
    assert_eq!(first.next, Some(RANGE_LIMIT));
    let last = reader
        .source(&pin, 1, first.next.unwrap(), RANGE_LIMIT)
        .await
        .unwrap();
    assert_eq!(last.next, None);
    let mut combined = svc::unhex(&first.bytes_hex, RANGE_LIMIT).unwrap();
    combined.extend(svc::unhex(&last.bytes_hex, RANGE_LIMIT).unwrap());
    assert!(
        combined == raw,
        "range reconstruction differs from retained plaintext"
    );
}

#[tokio::test]
async fn source_refuses_a_valid_read_from_a_different_snapshot_history() {
    let identity = Identity::generate();
    let reader_did = identity.did().to_string();
    let mut a = Fixture::new(12, &identity).await;
    a.append(b"original history");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let old = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let fork = Service::new(
        Ledger::create(&a.dir.path().join("fork")).unwrap(),
        a.scope,
        Identity::load_existing(&a.dir.path().join("server.key")).unwrap(),
        vec![
            Grant {
                principal: reader_did,
                append: false,
                inventory: true,
            },
            Grant {
                principal: a.writer.did().to_string(),
                append: true,
                inventory: false,
            },
        ],
    )
    .unwrap();
    *a.service.lock().unwrap() = fork;
    a.position = 0;
    a.previous = None;
    a.append(b"replacement history at the same sequence");
    assert!(
        reader.source(&old, 1, 0, 100).await.is_err(),
        "a valid Read must not bypass selected snapshot membership"
    );
    let fresh = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    assert_eq!(
        reader
            .source(&fresh, 1, 0, 100)
            .await
            .unwrap()
            .utf8
            .as_deref(),
        Some("replacement history at the same sequence")
    );
}

#[tokio::test]
async fn catalog_verification_failure_is_not_an_empty_authorized_inventory() {
    let identity = Identity::generate();
    let a = Fixture::new(31, &identity).await;
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api/library", listener.local_addr().unwrap());
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-reader-catalog-token-32".into(),
        reader,
    )));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let request = || {
        client
            .post(&endpoint)
            .header("content-type", "application/json")
            .bearer_auth("synthetic-reader-catalog-token-32")
            .body(r#"{"action":"catalog"}"#)
    };
    let honest = request().send().await.unwrap();
    assert_eq!(honest.status(), 200);
    let value: serde_json::Value = serde_json::from_slice(&honest.bytes().await.unwrap()).unwrap();
    assert_eq!(value["scopes"].as_array().unwrap().len(), 1);
    assert_eq!(value["coverage"], "complete");
    assert_eq!(
        value["capabilities"],
        serde_json::json!([
            "snapshot-inventory",
            "source-ranges",
            "provenance",
            "content-inspection"
        ])
    );
    assert_eq!(
        value["unavailable"],
        serde_json::json!([
            "semantic-search",
            "normalized-sessions",
            "annotations",
            "saved-views",
            "analysis",
            "administrative-jobs"
        ])
    );
    a.mode.store(1, Ordering::Relaxed);
    let forged = request().send().await.unwrap();
    assert_eq!(forged.status(), 200);
    let value: serde_json::Value = serde_json::from_slice(&forged.bytes().await.unwrap()).unwrap();
    assert_eq!(
        value["coverage"], "partial",
        "unverified replies must not become complete empty catalogs"
    );
    assert_eq!(value["scopes"].as_array().unwrap().len(), 0);
    assert!(!value.to_string().contains(&svc::hex(&a.scope)));
    a.mode.store(0, Ordering::Relaxed);
    a.revoke();
    let denied = request().send().await.unwrap();
    assert_eq!(denied.status(), 200);
    let value: serde_json::Value = serde_json::from_slice(&denied.bytes().await.unwrap()).unwrap();
    assert_eq!(
        value["scopes"].as_array().unwrap().len(),
        0,
        "verified grant denial may exclude the scope"
    );
    assert_eq!(
        value["coverage"], "complete",
        "verified denial is not an availability failure"
    );
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "capabilities",
            "coverage",
            "scopes",
            "unavailable",
            "version"
        ],
        "catalog has no failure-count or failed-source field"
    );
    a.mode.store(10, Ordering::Relaxed);
    let timed_out = request().send().await.unwrap();
    assert_eq!(timed_out.status(), 200);
    let timed_out: serde_json::Value =
        serde_json::from_slice(&timed_out.bytes().await.unwrap()).unwrap();
    assert_eq!(
        timed_out["coverage"], "partial",
        "a timeout is not an authenticated denial, even with no other errors"
    );
    assert_eq!(timed_out["scopes"].as_array().unwrap().len(), 0);
    assert_eq!(
        timed_out
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "capabilities",
            "coverage",
            "scopes",
            "unavailable",
            "version"
        ]
    );
}

#[tokio::test]
async fn reader_refuses_reusing_the_storage_issuer_signing_key() {
    let a = Fixture::new(32, &Identity::generate()).await;
    let storage_key = Identity::load_existing(&a.dir.path().join("server.key")).unwrap();
    assert!(matches!(
        Reader::new(storage_key, vec![a.access()]),
        Err(Failure::Invalid)
    ));
}

#[test]
fn reader_configuration_scope_count_and_duplicates_are_bounded() {
    let issuer = Identity::generate().did().to_string();
    let access = |n| ScopeAccess {
        scope: [n; 32],
        endpoint: "http://127.0.0.1:1/v1/rpc".into(),
        issuer: issuer.clone(),
        private_key: [27; 32],
    };
    assert!(Reader::new(Identity::generate(), (0..16).map(access).collect()).is_ok());
    for values in [
        vec![],
        (0..17).map(access).collect(),
        vec![access(1), access(1)],
    ] {
        assert!(matches!(
            Reader::new(Identity::generate(), values),
            Err(Failure::Invalid)
        ));
    }
}

#[tokio::test]
async fn reader_rejects_signed_page_completeness_and_tip_mismatches() {
    let identity = Identity::generate();
    let mut a = Fixture::new(33, &identity).await;
    a.append(b"one");
    a.append(b"two");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    for mode in [7, 8] {
        a.mode.store(mode, Ordering::Relaxed);
        assert!(matches!(
            reader.page(&pin, 0, 1).await,
            Err(Failure::Invalid)
        ));
    }
    a.mode.store(9, Ordering::Relaxed);
    assert!(matches!(
        reader.page(&pin, 1, 1).await,
        Err(Failure::Corrupt)
    ));
    a.mode.store(0, Ordering::Relaxed);
    assert_eq!(reader.page(&pin, 1, 1).await.unwrap().records.len(), 1);
}

#[tokio::test]
async fn pin_principal_and_audience_are_checked_even_with_valid_signatures() {
    use sha2::{Digest, Sha256};
    let identity = Identity::generate();
    let keys = tempfile::tempdir().unwrap();
    identity.save(&keys.path().join("reader.key")).unwrap();
    let mut a = Fixture::new(34, &identity).await;
    a.append(b"pin-check");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let mut forged = pin.clone();
    forged.reply.signature = "00".repeat(64);
    assert!(matches!(
        reader.page(&forged, 0, 1).await,
        Err(Failure::AccessLimited)
    ));
    for wrong_principal in [true, false] {
        let mut altered = pin.clone();
        let mut request = SignedRequest::decode(&svc::unhex(&altered.request, 4096).unwrap())
            .unwrap()
            .request;
        let signer = if wrong_principal {
            Identity::generate()
        } else {
            Identity::load_existing(&keys.path().join("reader.key")).unwrap()
        };
        if wrong_principal {
            request.principal = signer.did().to_string();
        } else {
            request.audience = a.writer.did().to_string();
        }
        let bytes = SignedRequest::sign(request, &signer)
            .unwrap()
            .bytes()
            .unwrap();
        altered.request = svc::hex(&bytes);
        altered.reply.reply.request = svc::hex(&Sha256::digest(&bytes));
        let mut preimage = b"tools.kan.service.reply.v1\0".to_vec();
        preimage.extend_from_slice(&Sha256::digest(
            serde_json::to_vec(&altered.reply.reply).unwrap(),
        ));
        altered.reply.signature = svc::hex(
            &Identity::load_existing(&a.dir.path().join("server.key"))
                .unwrap()
                .sign(&preimage)
                .unwrap(),
        );
        assert!(matches!(
            reader.page(&altered, 0, 1).await,
            Err(Failure::AccessLimited)
        ));
    }
    assert_eq!(reader.page(&pin, 0, 1).await.unwrap().records.len(), 1);
}

#[tokio::test]
async fn library_queues_a_browser_request_behind_four_idle_connections() {
    use tokio::io::AsyncWriteExt;
    let identity = Identity::generate();
    let a = Fixture::new(35, &identity).await;
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-browser-queue-token-32".into(),
        reader,
    )));
    let mut idle = Vec::new();
    for _ in 0..4 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        idle.push(socket);
        tokio::task::yield_now().await;
    }
    // Give accepted partial headers time to enter their five-second deadline.
    // Whole-fix reversion independently proves the old immediate drop is caught.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let result = client.get(format!("http://{addr}/")).send().await;
    assert!(
        result.is_ok(),
        "the fifth connection must wait rather than be dropped: {result:?}"
    );
    assert_eq!(result.unwrap().status(), 200);
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(4),
        "fifth socket must actually queue behind the execution bound"
    );
    drop(idle);
}

#[tokio::test]
async fn library_refuses_public_listeners_and_short_tokens_before_serving() {
    for (address, token) in [
        ("0.0.0.0:0", "synthetic-private-reader-token-32"),
        ("127.0.0.1:0", "short"),
    ] {
        let identity = Identity::generate();
        let a = Fixture::new(36, &identity).await;
        let reader = Reader::new(identity, vec![a.access()]).unwrap();
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            kan::evidence_library::serve(listener, token.into(), reader),
        )
        .await;
        assert!(
            matches!(result,Ok(Err(ref e)) if e.kind()==std::io::ErrorKind::Other),
            "invalid configuration must be refused before accepting requests"
        );
    }
}

#[tokio::test]
async fn catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources() {
    let identity = Identity::generate();
    let mut healthy = Fixture::new(45, &identity).await;
    healthy.append(b"healthy source remains browsable");
    let forged = Fixture::new(41, &identity).await;
    let denied = Fixture::new(42, &identity).await;
    let stalled = Fixture::new(37, &identity).await;
    let mut more_stalled = Vec::new();
    for n in [38, 39, 40] {
        let f = Fixture::new(n, &identity).await;
        f.mode.store(10, Ordering::Relaxed);
        more_stalled.push(f);
    }
    let refused = Fixture::new(44, &identity).await;
    forged.mode.store(1, Ordering::Relaxed);
    denied.revoke();
    stalled.mode.store(10, Ordering::Relaxed);
    refused.server.abort();
    let mut access = vec![
        healthy.access(),
        forged.access(),
        denied.access(),
        stalled.access(),
        refused.access(),
    ];
    access.extend(more_stalled.iter().map(Fixture::access));
    let reader = Reader::new(identity, access).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api/library", listener.local_addr().unwrap());
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-partial-catalog-token-32".into(),
        reader,
    )));
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap();
    let call = |body: serde_json::Value| {
        client
            .post(&endpoint)
            .header("content-type", "application/json")
            .bearer_auth("synthetic-partial-catalog-token-32")
            .body(body.to_string())
    };
    let started = std::time::Instant::now();
    let response = call(serde_json::json!({"action":"catalog"}))
        .send()
        .await
        .expect("stalled source must not hold whole catalog past its budget");
    assert_eq!(response.status(), 200);
    let value: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    assert_eq!(value["coverage"], "partial");
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "capabilities",
            "coverage",
            "scopes",
            "unavailable",
            "version"
        ],
        "partial coverage must not expose failure counts"
    );
    assert_eq!(value["scopes"].as_array().unwrap().len(), 1);
    assert_eq!(value["scopes"][0]["scope"], svc::hex(&healthy.scope));
    for fixture in [&forged, &denied, &stalled, &refused] {
        assert!(
            !value.to_string().contains(&svc::hex(&fixture.scope)),
            "unverified/denied scope identity must not be exposed"
        );
        assert!(!value.to_string().contains(&fixture.endpoint));
    }
    let pin = value["scopes"][0]["pin"].clone();
    let source =
        call(serde_json::json!({"action":"source","pin":pin,"sequence":1,"offset":0,"length":100}))
            .send()
            .await
            .unwrap();
    assert_eq!(source.status(), 200);
    let source: serde_json::Value = serde_json::from_slice(&source.bytes().await.unwrap()).unwrap();
    assert_eq!(source["utf8"], "healthy source remains browsable");
    forged.mode.store(0, Ordering::Relaxed);
    stalled.mode.store(0, Ordering::Relaxed);
    for f in &more_stalled {
        f.mode.store(0, Ordering::Relaxed);
    }
    let recovered = call(serde_json::json!({"action":"catalog"}))
        .send()
        .await
        .unwrap();
    let recovered: serde_json::Value =
        serde_json::from_slice(&recovered.bytes().await.unwrap()).unwrap();
    assert_eq!(recovered["scopes"].as_array().unwrap().len(), 6);
    assert_eq!(
        recovered["coverage"], "partial",
        "refused source remains visibly incomplete"
    );
}

#[tokio::test]
async fn library_body_read_deadline_returns_an_explicit_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let identity = Identity::generate();
    let a = Fixture::new(49, &identity).await;
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-body-deadline-token-32".into(),
        reader,
    )));
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(format!("POST /api/library HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer synthetic-body-deadline-token-32\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{").as_bytes()).await.unwrap();
    let started = std::time::Instant::now();
    let mut output = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.read_to_end(&mut output),
    )
    .await
    .expect("body deadline must return before whole connection timeout")
    .unwrap();
    assert!(String::from_utf8_lossy(&output).starts_with("HTTP/1.1 408"));
    assert!(started.elapsed() >= std::time::Duration::from_secs(2));
}

#[tokio::test]
async fn library_refuses_thirteenth_socket_at_the_live_admission_boundary() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let identity = Identity::generate();
    let a = Fixture::new(50, &identity).await;
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-socket-cap-reader-token-32".into(),
        reader,
    )));
    let mut held = Vec::new();
    for index in 0..12 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let wrote = socket.write_all(b"GET / HTTP/1.1\r\n").await;
        assert!(
            wrote.is_ok(),
            "socket {index} among the first twelve must accept a partial request: {wrote:?}"
        );
        held.push(socket);
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    let closed =
        tokio::time::timeout(std::time::Duration::from_secs(2), excess.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0)))
            || matches!(closed,Ok(Err(ref e)) if matches!(e.kind(),std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionAborted)),
        "thirteenth socket must close at admission, not join an unbounded queue: {closed:?}"
    );
    // Pin the lower bound too: a server admitting only five or eleven sockets
    // must not pass merely because it also refuses the thirteenth one.
    for (index, socket) in held.iter_mut().enumerate() {
        let state =
            tokio::time::timeout(std::time::Duration::from_millis(50), socket.read(&mut byte))
                .await;
        assert!(
            state.is_err(),
            "admitted socket {index} closed or responded early: {state:?}"
        );
    }
    drop(held);
}

fn content_frame(attempt: char, ordinal: u64, event: serde_json::Value, body: &[u8]) -> Vec<u8> {
    let header = serde_json::to_vec(
        &serde_json::json!({"version":2,"attempt":attempt.to_string().repeat(64),
        "observer":"collector","ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":0,
        "unconfirmed_before":0,"event":event}),
    )
    .unwrap();
    let mut out = b"KANC2".to_vec();
    out.extend((header.len() as u32).to_be_bytes());
    out.extend(header);
    out.extend(body);
    out
}
#[tokio::test]
async fn content_preserves_authorized_occurrences_duplicates_unplaced_inputs_and_exact_spans() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(31, &identity).await;
    let body = br#"{"messages":[{"role":"user","content":"<script>hostile()</script>"}]}"#;
    let frame = content_frame(
        '1',
        9007199254740993,
        serde_json::json!({"type":"request-chunk","offset":0}),
        body,
    );
    a.append(&frame);
    a.append(b"opaque input");
    a.append(&frame);
    a.append(&content_frame(
        '2',
        0,
        serde_json::json!({"type":"future-event"}),
        b"",
    ));
    a.append(&content_frame(
        '2',
        1,
        serde_json::json!({"type":"request-chunk","offset":"bad"}),
        b"x",
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let result = reader
        .content(
            &pin,
            &["1", "2", "3", "4", "5"].map(String::from),
            Format::AnthropicMessagesJson,
        )
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(value["version"], "kan-content/1");
    assert_eq!(value["occurrences"].as_array().unwrap().len(), 5);
    assert_eq!(value["observations"][1]["kind"], "opaque");
    assert_eq!(value["observations"][3]["kind"], "unsupported");
    assert_eq!(value["observations"][4]["kind"], "malformed");
    let group = &value["groups"][0];
    assert_eq!(group["ordinals"][0]["value"], "9007199254740993");
    assert_eq!(
        group["ordinals"][0]["inputs"],
        serde_json::json!(["0", "2"])
    );
    assert_eq!(group["terminal"], "unknown");
    assert_eq!(
        group["ordinal_gaps"][0],
        serde_json::json!(["0", "9007199254740993"])
    );
    let item = group["request"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "context")
        .unwrap();
    assert_eq!(item["kind"], "context");
    assert_eq!(item["coarse"], true);
    let citations = item["citations"].as_array().unwrap();
    assert_eq!(citations.len(), 2);
    for (citation, sequence) in citations.iter().zip([1, 3]) {
        let bounds = citation["bytes"].as_array().unwrap();
        let start: usize = bounds[0].as_str().unwrap().parse().unwrap();
        let end: usize = bounds[1].as_str().unwrap().parse().unwrap();
        let source = reader
            .source(&pin, sequence, start, end - start)
            .await
            .unwrap();
        assert_eq!(svc::unhex(&source.bytes_hex, 1000).unwrap(), body);
        assert_eq!(
            source.record.manifest,
            value["occurrences"][(sequence - 1) as usize]["record"]["manifest"]
                .as_str()
                .unwrap()
        );
    }
    let opaque = kan::evidence_content::pin(value["pin_wire"].as_str().unwrap()).unwrap();
    assert_eq!(
        kan::evidence_content::pin_wire(&opaque).unwrap(),
        kan::evidence_content::pin_wire(&pin).unwrap()
    );
}
#[tokio::test]
async fn content_refuses_invalid_selections_tampering_and_revocation_without_partial_success() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(32, &identity).await;
    a.append(b"secret-selection-canary");
    a.append(b"second");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let format = Format::AnthropicMessagesSse;
    for sequences in [
        vec![],
        vec!["0".into()],
        vec!["01".into()],
        vec!["1".into(), "1".into()],
        vec!["1".into(); 41],
        vec!["18446744073709551616".into()],
    ] {
        assert_eq!(
            reader.content(&pin, &sequences, format).await.unwrap_err(),
            Failure::Invalid
        );
    }
    assert_eq!(
        reader
            .content(&pin, &["1".into(), "3".into()], format)
            .await
            .unwrap_err(),
        Failure::Missing
    );
    for mode in 1..=9 {
        a.mode.store(mode, Ordering::Relaxed);
        assert!(
            reader.content(&pin, &["1".into()], format).await.is_err(),
            "mode {mode}"
        );
    }
    a.mode.store(0, Ordering::Relaxed);
    let mut bad = pin.clone();
    if let Ok(Output::Snapshot { through, .. }) = &mut bad.reply.reply.result {
        *through += 1;
    }
    assert!(reader.content(&bad, &["1".into()], format).await.is_err());
    reader.content(&pin, &["1".into()], format).await.unwrap();
    a.revoke();
    assert_eq!(
        reader
            .content(&pin, &["1".into()], format)
            .await
            .unwrap_err(),
        Failure::AccessLimited
    );
}
#[tokio::test]
async fn content_cancelling_acquisition_releases_admission_and_does_not_cache_a_grant() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(33, &identity).await;
    a.append(b"cancel-canary");
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    a.mode.store(10, Ordering::Relaxed);
    let sequences = ["1".into()];
    let format = Format::AnthropicMessagesSse;
    let mut first = Box::pin(reader.content(&pin, &sequences, format));
    let mut second = Box::pin(reader.content(&pin, &sequences, format));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut first)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut second)
            .await
            .is_err()
    );
    // Admission must refuse immediately: a stalled upstream timeout is not
    // evidence that the third operation was refused rather than admitted.
    let mut third = Box::pin(reader.content(&pin, &sequences, format));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert_eq!(
        std::future::Future::poll(third.as_mut(), &mut cx),
        std::task::Poll::Ready(Err(Failure::Unavailable))
    );
    drop(third);
    drop(first);
    drop(second);
    a.mode.store(0, Ordering::Relaxed);
    assert!(reader.content(&pin, &sequences, format).await.is_ok());
    a.revoke();
    assert_eq!(
        reader.content(&pin, &sequences, format).await.unwrap_err(),
        Failure::AccessLimited
    );
}

#[tokio::test]
async fn content_http_routes_share_authority_and_return_exact_coordinates() {
    let identity = Identity::generate();
    let mut a = Fixture::new(34, &identity).await;
    let body = br#"{"messages":[{"role":"user","content":"content-http-canary"}]}"#;
    a.append(&content_frame(
        '3',
        0,
        serde_json::json!({"type":"request-chunk","offset":0}),
        body,
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-content-library-token-32-chars".into(),
        reader,
    )));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/api/library");
    let request = |v: serde_json::Value| {
        client
            .post(&url)
            .header("content-type", "application/json")
            .bearer_auth("synthetic-content-library-token-32-chars")
            .body(v.to_string())
    };
    let catalog: serde_json::Value = serde_json::from_slice(
        &request(serde_json::json!({"action":"catalog"}))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let wire = catalog["scopes"][0]["pin_wire"].as_str().unwrap();
    assert!(!wire.contains("content-http-canary"));
    let page = request(
        serde_json::json!({"action":"content-page","pin_wire":wire,"after":"0","limit":40}),
    )
    .send()
    .await
    .unwrap();
    assert!(page.status().is_success());
    let value: serde_json::Value = serde_json::from_slice(&page.bytes().await.unwrap()).unwrap();
    assert_eq!(value["through"], "1");
    assert_eq!(value["records"][0]["sequence"], "1");
    let query = serde_json::json!({"action":"content","pin_wire":wire,"sequences":["1"],"format":"anthropic-messages-json"});
    let output = request(query.clone()).send().await.unwrap();
    assert!(output.status().is_success());
    assert_eq!(output.headers()["cache-control"], "no-store");
    let value: serde_json::Value = serde_json::from_slice(&output.bytes().await.unwrap()).unwrap();
    assert!(value["groups"][0]["request"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["text"] == "content-http-canary"));
    let source=request(serde_json::json!({"action":"source-exact","pin_wire":wire,"sequence":"1","offset":"0","length":"65536"})).send().await.unwrap();
    assert!(source.status().is_success());
    let source: serde_json::Value = serde_json::from_slice(&source.bytes().await.unwrap()).unwrap();
    assert_eq!(source["offset"], "0");
    assert_eq!(source["record"]["sequence"], "1");
    assert!(source["total_bytes"].is_string());
    for bad in [
        serde_json::json!({"action":"content","pin_wire":wire,"sequences":[1],"format":"anthropic-messages-json"}),
        serde_json::json!({"action":"content-page","pin_wire":wire,"after":"00","limit":40}),
        serde_json::json!({"action":"source-exact","pin_wire":wire,"sequence":"1.0","offset":"0","length":"1"}),
    ] {
        let response = request(bad).send().await.unwrap();
        assert_eq!(response.status(), 400);
        assert!(!String::from_utf8_lossy(&response.bytes().await.unwrap())
            .contains("content-http-canary"));
    }
    assert_eq!(
        request(query.clone())
            .header("origin", "https://evil.invalid")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&url)
            .header("content-type", "application/json")
            .body(query.to_string())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Verified but over-budget presentation has a fixed, non-disclosing reason.
    let many = serde_json::to_vec(&serde_json::json!({"messages":(0..1100).map(|_|serde_json::json!({"role":"user","content":"x"})).collect::<Vec<_>>()})).unwrap();
    a.append(&content_frame(
        '4',
        0,
        serde_json::json!({"type":"request-chunk","offset":0}),
        &many,
    ));
    let snap = request(serde_json::json!({"action":"snapshot","scope":svc::hex(&a.scope)}))
        .send()
        .await
        .unwrap();
    let snap: serde_json::Value = serde_json::from_slice(&snap.bytes().await.unwrap()).unwrap();
    let limited=request(serde_json::json!({"action":"content","pin_wire":snap["pin_wire"],"sequences":["2"],"format":"anthropic-messages-json"})).send().await.unwrap();
    assert_eq!(limited.status(), 422);
    assert_eq!(limited.headers()["cache-control"], "no-store");
    assert_eq!(
        limited.text().await.unwrap(),
        r#"{"error":"content-limit"}"#
    );
    a.revoke();
    let denied = request(query).send().await.unwrap();
    assert_eq!(denied.status(), 403);
    assert!(
        !String::from_utf8_lossy(&denied.bytes().await.unwrap()).contains("content-http-canary")
    );
}

/// Real encrypted/signed synthetic captures for Content browser qualification.
#[tokio::test]
#[ignore = "manual Content browser fixture; requires KAN_LIBRARY_FIXTURE_INFO"]
async fn content_browser_fixture() {
    let output = std::env::var_os("KAN_LIBRARY_FIXTURE_INFO").expect("explicit output path");
    let identity = Identity::generate();
    let mut a = Fixture::new(35, &identity).await;
    a.append(&content_frame(
        '4',
        0,
        serde_json::json!({"type":"started","method":"POST","route":"/v1/messages"}),
        b"",
    ));
    let request=br#"{"system":"You are a helpful assistant.","messages":[{"role":"user","content":[{"type":"text","text":"Explain provenance. <img src=https://untrusted.invalid/tracker onerror=alert(1)>"},{"type":"image","source":{"type":"url","url":"https://untrusted.invalid/attachment"}},{"type":"future-widget","note":"retained, unsupported"}]}]}"#;
    a.append(&content_frame(
        '4',
        1,
        serde_json::json!({"type":"request-chunk","offset":0}),
        request,
    ));
    a.append(&content_frame(
        '4',
        2,
        serde_json::json!({"type":"request-end","bytes":request.len()}),
        b"",
    ));
    let events = [
        serde_json::json!({"type":"message_start","message":{"type":"message","role":"assistant","content":[]}}),
        serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Provenance connects an interpretation to the exact retained evidence. Inspect the source before trusting a claim. ☃"}}),
        serde_json::json!({"type":"content_block_stop","index":0}),
        serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}}),
        serde_json::json!({"type":"message_stop"}),
    ];
    let response = events
        .iter()
        .map(|v| format!("event: {}\ndata: {v}\n\n", v["type"].as_str().unwrap()))
        .collect::<String>();
    let split = response.len() / 2;
    let first = content_frame(
        '4',
        3,
        serde_json::json!({"type":"response-chunk","offset":0}),
        &response.as_bytes()[..split],
    );
    a.append(&first);
    a.append(&content_frame(
        '4',
        4,
        serde_json::json!({"type":"response-chunk","offset":split}),
        &response.as_bytes()[split..],
    ));
    a.append(&first);
    a.append(&content_frame(
        '4',
        5,
        serde_json::json!({"type":"terminal","outcome":"completed"}),
        b"",
    ));
    a.append(&content_frame(
        '5',
        0,
        serde_json::json!({"type":"future-event"}),
        b"",
    ));
    a.append(b"Opaque imported note\0\xff");
    a.append(&content_frame(
        '6',
        3,
        serde_json::json!({"type":"response-chunk","offset":8}),
        b"gap",
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = "synthetic-browser-content-access-token";
    std::fs::write(
        output,
        serde_json::to_vec(&serde_json::json!({"url":format!("http://{addr}"),"token":token}))
            .unwrap(),
    )
    .unwrap();
    // Optional test-only owner control; never exposed by the production server.
    let control = std::env::var_os("KAN_CONTENT_FIXTURE_CONTROL").map(std::path::PathBuf::from);
    let controls = async {
        let mut previous = String::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            if let Some(path) = &control {
                if let Ok(command) = std::fs::read_to_string(path) {
                    if command != previous {
                        match command.trim() {
                            "stall" => a.mode.store(10, Ordering::Relaxed),
                            "normal" => a.mode.store(0, Ordering::Relaxed),
                            "revoke" => {
                                a.mode.store(0, Ordering::Relaxed);
                                a.revoke();
                            }
                            _ => panic!("unknown synthetic fixture command"),
                        }
                        previous = command;
                        std::fs::write(path.with_extension("ack"), &previous).unwrap();
                    }
                }
            }
        }
    };
    tokio::select! {r=kan::evidence_library::serve(listener,token.into(),reader)=>r.unwrap(),_=controls=>{},_=tokio::signal::ctrl_c()=>{}}
}

#[tokio::test]
async fn content_rechecks_current_grant_after_successful_acquisition() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(36, &identity).await;
    a.append(&content_frame(
        '7',
        0,
        serde_json::json!({"type":"request-chunk","offset":0}),
        br#"{"messages":[{"role":"user","content":"late-revocation-canary"}]}"#,
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    a.mode.store(11, Ordering::Relaxed);
    assert_eq!(
        reader
            .content(&pin, &["1".into()], Format::AnthropicMessagesJson)
            .await
            .unwrap_err(),
        Failure::AccessLimited
    );
}

#[tokio::test]
async fn content_has_an_independent_item_limit_with_no_partial_success() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(37, &identity).await;
    a.append(&content_frame(
        '8',
        0,
        serde_json::json!({"type":"response-chunk","offset":0}),
        &vec![b'\n'; 1024],
    ));
    a.append(&content_frame(
        '9',
        0,
        serde_json::json!({"type":"response-chunk","offset":0}),
        &vec![b'\n'; 1025],
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let bytes = reader
        .content(&pin, &["1".into()], Format::AnthropicMessagesSse)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["groups"][0]["response"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1024
    );
    assert_eq!(
        reader
            .content(&pin, &["2".into()], Format::AnthropicMessagesSse)
            .await
            .unwrap_err(),
        Failure::Unavailable
    );
}
#[tokio::test]
async fn content_accumulated_tool_input_cites_all_fragments_instead_of_only_the_stop() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut a = Fixture::new(38, &identity).await;
    let events = [
        serde_json::json!({"type":"message_start","message":{"type":"message","role":"assistant","content":[]}}),
        serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","name":"f","input":{}}}),
        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":"}}),
        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"1}"}}),
        serde_json::json!({"type":"content_block_stop","index":0}),
    ];
    let raw = events
        .iter()
        .map(|v| format!("data: {v}\n\n"))
        .collect::<String>();
    let split = raw.len() / 2;
    a.append(&content_frame(
        'a',
        0,
        serde_json::json!({"type":"response-chunk","offset":0}),
        &raw.as_bytes()[..split],
    ));
    a.append(&content_frame(
        'a',
        1,
        serde_json::json!({"type":"response-chunk","offset":split}),
        &raw.as_bytes()[split..],
    ));
    let reader = Reader::new(identity, vec![a.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&a.scope)).await.unwrap();
    let result = reader
        .content(
            &pin,
            &["1".into(), "2".into()],
            Format::AnthropicMessagesSse,
        )
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&result).unwrap();
    let items = value["groups"][0]["response"]["items"].as_array().unwrap();
    let item = items.iter().find(|i| i["tool"].is_object()).unwrap();
    let tool = &item["tool"];
    assert_eq!(tool["json"], "{\"x\":1}");
    let start: usize = tool["region"][0].as_str().unwrap().parse().unwrap();
    let end: usize = tool["region"][1].as_str().unwrap().parse().unwrap();
    assert!(
        start
            < item["region"][0]
                .as_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
    );
    let mut retained = Vec::new();
    for c in tool["citations"].as_array().unwrap() {
        let input: usize = c["input"].as_str().unwrap().parse().unwrap();
        let seq = value["occurrences"][input]["record"]["sequence"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let begin = c["bytes"][0].as_str().unwrap().parse().unwrap();
        let finish: usize = c["bytes"][1].as_str().unwrap().parse().unwrap();
        let source = reader
            .source(&pin, seq, begin, finish - begin)
            .await
            .unwrap();
        retained.extend(svc::unhex(&source.bytes_hex, 65536).unwrap());
    }
    assert_eq!(retained, &raw.as_bytes()[start..end]);
    assert!(String::from_utf8_lossy(&retained).contains("partial_json"));
}

#[tokio::test]
async fn content_handles_realistic_multiturn_history_and_streams_without_repeated_source_scans() {
    use kan::evidence_content::Format;
    let identity = Identity::generate();
    let mut fixture = Fixture::new(92, &identity).await;
    let request=serde_json::to_vec(&serde_json::json!({"messages":(0..130).map(|k|serde_json::json!({"role":if k%2==0 {"user"}else{"assistant"},"content":"a".repeat(1000)})).collect::<Vec<_>>()})).unwrap();
    let request_first = fixture.position + 1;
    for (n, chunk) in request.chunks(65536).enumerate() {
        fixture.append(&content_frame(
            'a',
            n as u64,
            serde_json::json!({"type":"request-chunk","offset":n*65536}),
            chunk,
        ));
    }
    let request_sequences = (request_first..=fixture.position)
        .map(|n| n.to_string())
        .collect::<Vec<_>>();
    let mut events = vec![
        serde_json::json!({"type":"message_start","message":{"type":"message","role":"assistant","content":[]}}),
        serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
    ];
    events.extend((0..500).map(|_|serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"word word word word word word "}})));
    events.extend([
        serde_json::json!({"type":"content_block_stop","index":0}),
        serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}}),
        serde_json::json!({"type":"message_stop"}),
    ]);
    let sse = events
        .iter()
        .map(|value| {
            format!(
                "event: {}\ndata: {value}\n\n",
                value["type"].as_str().unwrap()
            )
        })
        .collect::<String>();
    let response_first = fixture.position + 1;
    for (n, chunk) in sse.as_bytes().chunks(65536).enumerate() {
        fixture.append(&content_frame(
            'b',
            n as u64,
            serde_json::json!({"type":"response-chunk","offset":n*65536}),
            chunk,
        ));
    }
    let response_sequences = (response_first..=fixture.position)
        .map(|n| n.to_string())
        .collect::<Vec<_>>();
    let reader = Reader::new(identity, vec![fixture.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&fixture.scope)).await.unwrap();
    for (sequences, format, direction, count) in [
        (
            request_sequences,
            Format::AnthropicMessagesJson,
            "request",
            261,
        ),
        (
            response_sequences,
            Format::AnthropicMessagesSse,
            "response",
            505,
        ),
    ] {
        let bytes = reader.content(&pin, &sequences, format).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result["groups"][0][direction]["items"]
                .as_array()
                .unwrap()
                .len(),
            count
        );
        let scan = result["scan_bytes"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(
            scan < 2 * 1024 * 1024,
            "source correspondence must be charged once: {scan}"
        );
        for item in result["groups"][0][direction]["items"].as_array().unwrap() {
            let citations = item["citations"].as_array().unwrap();
            assert!(!citations.is_empty() && citations.len() <= sequences.len());
            for citation in citations {
                let index = citation["input"]
                    .as_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert_eq!(
                    result["occurrences"][index]["record"]["sequence"],
                    sequences[index]
                );
            }
        }
    }
}
