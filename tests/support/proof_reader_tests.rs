use super::*;
use kan::evidence_reader::proof as client;
use kan::evidence_service::Failure;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

const PRIVATE: [u8; 32] = [71; 32];
const RAW: &[u8] = b"<script>untrusted capture</script>\0\xff";
fn encrypted(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
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
            RAW,
        )
        .unwrap(),
    );
    service::SignedRequest::sign(req, &identity(6))
        .unwrap()
        .bytes()
        .unwrap()
}
fn resign(reply: &mut wire::SignedReply) {
    use sha2::{Digest, Sha256};
    let mut pre = b"tools.kan.proof-read.reply.v2\0".to_vec();
    pre.extend_from_slice(&Sha256::digest(serde_json::to_vec(&reply.reply).unwrap()));
    reply.signature = service::hex(&identity(8).sign(&pre).unwrap());
}
struct Server {
    endpoint: String,
    service: Arc<Mutex<wire::Service>>,
    mode: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(f: &Fixture) -> Self {
        Self::start_with(reader(f)).await
    }
    async fn start_indexed(f: &Fixture) -> Self {
        match f.profile {
            Profile::Admitted => attested::Archive::open(&f.root, f.binding.clone())
                .unwrap()
                .rebuild_serving_index(&identity(8))
                .unwrap(),
            Profile::Copied => copied::Archive::open(&f.root, f.binding.clone())
                .unwrap()
                .rebuild_serving_index(&identity(8))
                .unwrap(),
        };
        Self::start_with(
            wire::Service::new_indexed(
                f.db(),
                binding(f),
                identity(8),
                vec![grant()],
                budget(),
                None,
            )
            .unwrap(),
        )
        .await
    }
    async fn start_with(reader: wire::Service) -> Self {
        let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let endpoint = format!("http://{}/v2/read", listener.local_addr().unwrap());
        let service = Arc::new(Mutex::new(reader));
        let mode = Arc::new(AtomicUsize::new(0));
        let inner = service.clone();
        let selected = mode.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let service = inner.clone();
                let mode = selected.clone();
                connections.spawn(async move {
                    use http_body_util::{BodyExt, Full, Limited};
                    use hyper::{
                        body::{Bytes, Incoming},
                        Request, Response,
                    };
                    let handler = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let service = service.clone();
                        let mode = mode.clone();
                        async move {
                            let bytes = Limited::new(request.into_body(), wire::MAX_REQUEST)
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let mut reply = service.lock().unwrap().dispatch(&bytes, now).unwrap();
                            let selected = mode.load(Ordering::Relaxed);
                            match &mut reply.reply.result {
                                Ok(wire::Output::Capabilities { protocol, .. })
                                    if selected == 1 =>
                                {
                                    *protocol = "unsupported".into()
                                }
                                Ok(wire::Output::Page { records, .. }) if selected == 2 => {
                                    records.clear()
                                }
                                Ok(wire::Output::Page { records, .. }) if selected == 3 => {
                                    records[0].sequence = "01".into()
                                }
                                Ok(wire::Output::Page { next, .. }) if selected == 4 => {
                                    *next = None
                                }
                                Ok(wire::Output::Page { records, .. }) if selected == 5 => {
                                    records[0].proof = "00".into()
                                }
                                Ok(wire::Output::Evidence {
                                    source: wire::Source::Available { writer, .. },
                                    ..
                                }) if selected == 6 => *writer = identity(7).did().to_string(),
                                Ok(wire::Output::Evidence { record, .. }) if selected == 7 => {
                                    record.availability = wire::Availability::Missing
                                }
                                Ok(wire::Output::Evidence {
                                    source: wire::Source::Available { signed_request, .. },
                                    ..
                                }) if selected == 8 => *signed_request = "00".into(),
                                Ok(wire::Output::Snapshot { plan, .. }) if selected == 9 => {
                                    *plan = None
                                }
                                Ok(wire::Output::Capabilities { operations, .. })
                                    if selected == 16 =>
                                {
                                    operations.retain(|op| op != "read-batch");
                                }
                                Ok(wire::Output::EvidenceBatch { records }) => match selected {
                                    11 => records.clear(),
                                    12 => records.swap(0, 1),
                                    13 => {
                                        if let wire::Source::Available { writer, .. } =
                                            &mut records[0].source
                                        {
                                            *writer = identity(7).did().to_string();
                                        }
                                    }
                                    14 => {
                                        if let wire::Source::Available { signed_request, .. } =
                                            &mut records[0].source
                                        {
                                            *signed_request = "00".into();
                                        }
                                    }
                                    15 => records.truncate(1),
                                    _ => {}
                                },
                                _ => {}
                            }
                            resign(&mut reply);
                            if selected == 10 {
                                reply.signature = "00".repeat(64);
                            }
                            let mut response =
                                Response::new(Full::new(Bytes::from(reply.bytes().unwrap())));
                            response.headers_mut().insert(
                                "cache-control",
                                hyper::header::HeaderValue::from_static("no-store"),
                            );
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), handler)
                        .await;
                });
                while connections.try_join_next().is_some() {}
            }
        });
        Self {
            endpoint,
            service,
            mode,
            task,
        }
    }
    fn client(&self, f: &Fixture) -> client::Reader {
        client::Reader::new(
            identity(6),
            client::Access {
                binding: binding(f),
                endpoint: self.endpoint.clone(),
                private_key: PRIVATE,
            },
        )
        .unwrap()
    }
    async fn stop(self) {
        self.task.abort();
        assert!(self.task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn proof_reader_verifies_pages_decrypts_exact_bytes_and_reports_fresh_loss() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, encrypted);
        let server = Server::start(&f).await;
        let reader = server.client(&f);
        let pin = reader.snapshot().await.unwrap();
        let first = reader.page(&pin, None, 1).await.unwrap();
        assert_eq!(first.records[0].sequence, "3");
        assert_eq!(
            first.records[0].receipt_issuer,
            identity(if profile == Profile::Copied { 7 } else { 8 })
                .did()
                .as_str()
        );
        assert_eq!(
            first.records[0].purpose,
            if profile == Profile::Copied {
                "retained-verified"
            } else {
                "admitted"
            }
        );
        let client::Source::Available {
            plaintext, writer, ..
        } = reader
            .source(&pin, &first.records[0].selection)
            .await
            .unwrap()
        else {
            panic!("available")
        };
        assert_eq!(plaintext, RAW);
        assert_eq!(writer, identity(6).did().as_str());
        let second = reader.page(&pin, first.next.as_ref(), 40).await.unwrap();
        assert_eq!(
            second
                .records
                .iter()
                .map(|r| r.sequence.as_str())
                .collect::<Vec<_>>(),
            ["2", "1"]
        );
        assert!(second.next.is_none());
        f.remove(2);
        assert!(matches!(
            reader
                .source(&pin, &first.records[0].selection)
                .await
                .unwrap(),
            client::Source::Missing { .. }
        ));
        f.edit(&format!(
            "UPDATE objects SET bytes=x'00' WHERE cid='{}'",
            f.id(1)
        ));
        assert!(matches!(
            reader
                .source(&pin, &second.records[0].selection)
                .await
                .unwrap(),
            client::Source::Corrupt { .. }
        ));
        let rows = reader.page(&pin, None, 40).await.unwrap();
        assert_eq!(
            rows.records
                .iter()
                .map(|r| r.availability)
                .collect::<Vec<_>>(),
            [
                wire::Availability::Missing,
                wire::Availability::Corrupt,
                wire::Availability::Available
            ]
        );
        server.stop().await;
    }
}

#[tokio::test]
async fn proof_reader_rejects_signed_malformed_capabilities_pages_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Copied, encrypted);
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 1).await.unwrap();
    for mode in [1, 9, 10] {
        server.mode.store(mode, Ordering::Relaxed);
        assert!(reader.snapshot().await.is_err(), "snapshot mode{mode}");
    }
    for mode in [2, 3, 4, 5, 10] {
        server.mode.store(mode, Ordering::Relaxed);
        assert!(reader.page(&pin, None, 1).await.is_err(), "page mode{mode}");
    }
    for mode in [6, 7, 8, 10] {
        server.mode.store(mode, Ordering::Relaxed);
        assert!(
            reader
                .source(&pin, &page.records[0].selection)
                .await
                .is_err(),
            "source mode{mode}"
        );
    }
    server.mode.store(0, Ordering::Relaxed);
    assert!(reader
        .source(&pin, &page.records[0].selection)
        .await
        .is_ok());
    server.stop().await;
}

#[tokio::test]
async fn proof_reader_tokens_bind_snapshot_purpose_principal_and_exact_coordinates() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 1).await.unwrap();
    let cursor = page.next.as_ref().unwrap();
    let selection = &page.records[0].selection;
    assert!(matches!(
        reader.source(&pin, cursor).await,
        Err(service::Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.page(&pin, Some(selection), 1).await,
        Err(service::Failure::AccessLimited)
    ));
    for field in ["through", "manifest", "attestation"] {
        let mut value = serde_json::to_value(cursor).unwrap();
        value["body"]["coordinate"][field] = if field == "through" {
            "1".into()
        } else {
            pin.reply.reply.request.clone().into()
        };
        let changed = serde_json::from_value(value).unwrap();
        assert!(
            reader.page(&pin, Some(&changed), 1).await.is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(cursor).unwrap();
    value["signature"] = "00".repeat(64).into();
    let changed = serde_json::from_value(value).unwrap();
    assert!(matches!(
        reader.page(&pin, Some(&changed), 1).await,
        Err(service::Failure::AccessLimited)
    ));
    let record = encrypted(3, 8, Some(page.records[0].manifest.clone()));
    attested::Archive::open(&f.root, f.binding.clone())
        .unwrap()
        .admit(&record, &identity(8), &grant(), 2000)
        .unwrap();
    let fresh = reader.snapshot().await.unwrap();
    assert!(matches!(
        reader.page(&fresh, Some(cursor), 1).await,
        Err(service::Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.source(&fresh, selection).await,
        Err(service::Failure::AccessLimited)
    ));
    assert_eq!(
        reader
            .page(&pin, Some(cursor), 40)
            .await
            .unwrap()
            .records
            .len(),
        2
    );
    let wrong = client::Reader::new(
        identity(5),
        client::Access {
            binding: binding(&f),
            endpoint: server.endpoint.clone(),
            private_key: PRIVATE,
        },
    )
    .unwrap();
    assert!(matches!(
        wrong.page(&pin, None, 1).await,
        Err(service::Failure::AccessLimited)
    ));
    server.stop().await;
}

#[tokio::test]
async fn proof_reader_pins_and_tokens_never_replace_current_permission_or_decryption() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_requests(dir.path(), Profile::Admitted, encrypted);
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 1).await.unwrap();
    let wrong = client::Reader::new(
        identity(6),
        client::Access {
            binding: binding(&f),
            endpoint: server.endpoint.clone(),
            private_key: [72; 32],
        },
    )
    .unwrap();
    assert!(matches!(
        wrong.source(&pin, &page.records[0].selection).await,
        Ok(client::Source::KeyUnavailable { .. })
    ));
    server
        .service
        .lock()
        .unwrap()
        .replace_grants(vec![])
        .unwrap();
    assert!(matches!(
        reader.page(&pin, None, 1).await,
        Err(service::Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.source(&pin, &page.records[0].selection).await,
        Err(service::Failure::AccessLimited)
    ));
    assert!(matches!(
        reader.snapshot().await,
        Err(service::Failure::AccessLimited)
    ));
    server.stop().await;
}

#[tokio::test]
async fn proof_reader_can_browse_empty_copy_before_original_membership_is_complete() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("legacy");
    let mut ledger = Ledger::create(&legacy).unwrap();
    ledger.stage(b"retained staged orphan").unwrap();
    drop(ledger);
    let source = PlannedCopy::open(
        &legacy.join("archive.sqlite"),
        Target {
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
        identity(7).did().to_string(),
        [9; 32],
    )
    .unwrap();
    assert_eq!(source.plan().source().through, 0);
    let root = dir.path().join("copy");
    let binding = attested::Binding {
        archive: source.plan().archive_id(),
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    let mut copy = copied::Archive::create(&root, &source, binding.clone()).unwrap();
    let f = Fixture {
        root,
        binding,
        requests: vec![],
        profile: Profile::Copied,
    };
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    assert!(matches!(
        pin.reply.reply.result,
        Ok(wire::Output::Snapshot {
            recipe_metadata_match: Some(false),
            ..
        })
    ));
    let page = reader.page(&pin, None, 1).await.unwrap();
    assert!(page.records.is_empty() && page.next.is_none());
    copy.copy_batch(
        &source,
        &identity(8),
        1000,
        copied::Budget {
            objects: 10,
            records: 10,
            bytes: 16 * 1024 * 1024,
        },
    )
    .unwrap();
    let fresh = reader.snapshot().await.unwrap();
    assert!(matches!(
        fresh.reply.reply.result,
        Ok(wire::Output::Snapshot {
            recipe_metadata_match: Some(true),
            ..
        })
    ));
    server.stop().await;
}

#[path = "proof_library_tests.rs"]
mod library_tests;

#[tokio::test]
async fn proof_batch_preserves_order_fresh_loss_and_current_grants() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, encrypted);
        let server = Server::start(&f).await;
        let reader = server.client(&f);
        let pin = reader.snapshot().await.unwrap();
        let page = reader.page(&pin, None, 3).await.unwrap();
        // Deliberately non-descending selection: output must follow caller order.
        let selections = vec![
            page.records[2].selection.clone(),
            page.records[0].selection.clone(),
            page.records[1].selection.clone(),
        ];
        let sources = reader.sources_prefix(&pin, &selections).await.unwrap();
        assert_eq!(sources.len(), 3);
        for (source, sequence) in sources.iter().zip(["1", "3", "2"]) {
            let client::Source::Available {
                record,
                writer,
                plaintext,
                ..
            } = source
            else {
                panic!("available");
            };
            assert_eq!(record.sequence, sequence);
            assert_eq!(writer, identity(6).did().as_str());
            assert_eq!(plaintext, RAW);
        }
        for mode in [11, 12, 13, 14] {
            server.mode.store(mode, Ordering::Relaxed);
            assert!(
                matches!(
                    reader.sources_prefix(&pin, &selections).await,
                    Err(Failure::Corrupt)
                ),
                "mode {mode}"
            );
        }
        for mode in [15, 16] {
            server.mode.store(mode, Ordering::Relaxed);
            let sources = reader.sources_prefix(&pin, &selections).await.unwrap();
            assert_eq!(sources.len(), 1);
            assert!(
                matches!(&sources[0],client::Source::Available{record,..} if record.sequence == "1")
            );
        }
        server.mode.store(0, Ordering::Relaxed);
        f.remove(2);
        f.edit(&format!(
            "UPDATE objects SET bytes=x'00' WHERE cid='{}'",
            f.id(1)
        ));
        let sources = reader.sources_prefix(&pin, &selections).await.unwrap();
        assert!(matches!(&sources[0], client::Source::Available { .. }));
        assert!(matches!(&sources[1], client::Source::Missing { .. }));
        assert!(matches!(&sources[2], client::Source::Corrupt { .. }));
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(Vec::new())
            .unwrap();
        assert!(matches!(
            reader.sources_prefix(&pin, &selections).await,
            Err(Failure::AccessLimited)
        ));
        server.stop().await;
    }
}

#[tokio::test]
async fn proof_batch_byte_limit_returns_a_resumable_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let raw = vec![b'x'; 900 * 1024];
    let f = fixture_requests(dir.path(), Profile::Admitted, |n, audience, previous| {
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
                &raw,
            )
            .unwrap(),
        );
        service::SignedRequest::sign(req, &identity(6))
            .unwrap()
            .bytes()
            .unwrap()
    });
    let server = Server::start(&f).await;
    let reader = server.client(&f);
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 3).await.unwrap();
    let selections: Vec<_> = page.records.into_iter().map(|r| r.selection).collect();
    let first = reader.sources_prefix(&pin, &selections).await.unwrap();
    assert_eq!(first.len(), 2);
    let rest = reader
        .sources_prefix(&pin, &selections[first.len()..])
        .await
        .unwrap();
    assert_eq!(rest.len(), 1);
    for (source, sequence) in first.into_iter().chain(rest).zip(["3", "2", "1"]) {
        let client::Source::Available {
            record, plaintext, ..
        } = source
        else {
            panic!("available");
        };
        assert_eq!(record.sequence, sequence);
        assert_eq!(plaintext, raw);
    }
    assert!(matches!(
        reader.sources_prefix(&pin, &[]).await,
        Err(Failure::Invalid)
    ));
    assert!(matches!(
        reader
            .sources_prefix(&pin, &vec![selections[0].clone(); 9])
            .await,
        Err(Failure::Invalid)
    ));
    server.stop().await;
}

#[tokio::test]
async fn historical_recipient_keys_read_multiple_epochs_and_missing_keys_keep_provenance() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_requests(dir.path(), profile, |n, audience, previous| {
            let mut req = service::SignedRequest::decode(&request(n, audience, previous))
                .unwrap()
                .request;
            let service::Command::Append { ciphertext, .. } = &mut req.command else {
                unreachable!()
            };
            let private = if n == 1 { [72; 32] } else { PRIVATE };
            *ciphertext = service::hex(
                &kan::evidence_crypto::seal(
                    &kan::evidence_crypto::public_key(&private).unwrap(),
                    &[1; 32],
                    RAW,
                )
                .unwrap(),
            );
            service::SignedRequest::sign(req, &identity(6))
                .unwrap()
                .bytes()
                .unwrap()
        });
        let server = Server::start(&f).await;
        let reader = server.client(&f);
        let pin = reader.snapshot().await.unwrap();
        let page = reader.page(&pin, None, 3).await.unwrap();
        let selections = page
            .records
            .iter()
            .map(|r| r.selection.clone())
            .collect::<Vec<_>>();
        let values = reader.sources_prefix(&pin, &selections).await.unwrap();
        assert!(
            matches!(&values[1],client::Source::KeyUnavailable{record,writer,recipient} if record.sequence=="2" && writer==identity(6).did().as_str() && recipient.len()==64)
        );
        let complete = server
            .client(&f)
            .with_historical_keys(vec![[72; 32]])
            .unwrap();
        for value in complete.sources_prefix(&pin, &selections).await.unwrap() {
            assert!(matches!(value,client::Source::Available{plaintext,..} if plaintext==RAW));
        }
        server
            .service
            .lock()
            .unwrap()
            .replace_grants(vec![])
            .unwrap();
        assert!(matches!(
            complete.sources_prefix(&pin, &selections).await,
            Err(Failure::AccessLimited)
        ));
        server.stop().await;
    }
}
