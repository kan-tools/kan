use crate as kan;
include!("reader_fixture.rs");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_real_content_keeps_worker_admission_until_exit_and_stops_after_first_item() {
    use crate::evidence_content::{ContentError, Format};
    use std::sync::atomic::AtomicUsize;
    let identity = Identity::generate();
    let mut fixture = Fixture::new(91, &identity).await;
    let header=serde_json::to_vec(&serde_json::json!({"version":2,"attempt":"9".repeat(64),"observer":"collector","ordinal":0,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"request-chunk","offset":0}})).unwrap();
    let mut frame = b"KANC2".to_vec();
    frame.extend((header.len() as u32).to_be_bytes());
    frame.extend(header);
    frame.extend(br#"{"messages":[{"role":"user","content":"cancel-worker-canary"}]}"#);
    fixture.append(&frame);
    let reader = Arc::new(Reader::new(identity, vec![fixture.access()]).unwrap());
    let pin = reader.snapshot(&svc::hex(&fixture.scope)).await.unwrap();
    let spare = reader.content_workers.clone().try_acquire_owned().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let seen = Arc::new(AtomicUsize::new(0));
    let r = reader.clone();
    let p = pin.clone();
    let calls = seen.clone();
    let job = tokio::spawn(async move {
        let mut started = Some(started_tx);
        r.content_observed(
            &p,
            &["1".into()],
            Format::AnthropicMessagesJson,
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(tx) = started.take() {
                    let _ = tx.send(());
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap();
                }
            },
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reader.content_workers.available_permits(),
        0,
        "worker must own its permit while paused"
    );
    assert_eq!(
        reader
            .content_detailed(&pin, &["1".into()], Format::AnthropicMessagesJson)
            .await,
        Err(ContentError::Busy)
    );
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert_eq!(
        reader.content_workers.available_permits(),
        0,
        "disconnect must not release the still-running worker's permit"
    );
    release_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while reader.content_workers.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "cancelled render must not process the next item"
    );
    drop(spare);
    assert!(reader
        .content(&pin, &["1".into()], Format::AnthropicMessagesJson)
        .await
        .is_ok());
    fixture.revoke();
    assert_eq!(
        reader
            .content(&pin, &["1".into()], Format::AnthropicMessagesJson)
            .await,
        Err(Failure::AccessLimited)
    );
}
