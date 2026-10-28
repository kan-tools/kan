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
            || std::future::ready(()),
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

#[tokio::test]
async fn busy_content_http_response_is_distinct_and_retry_succeeds_after_capacity_returns() {
    let identity = Identity::generate();
    let mut fixture = Fixture::new(93, &identity).await;
    fixture.append(b"synthetic-opaque-capacity-fixture");
    let reader = Reader::new(identity, vec![fixture.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&fixture.scope)).await.unwrap();
    let wire = crate::evidence_content::pin_wire(&pin).unwrap();
    let first = reader.content_workers.clone().try_acquire_owned().unwrap();
    let second = reader.content_workers.clone().try_acquire_owned().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api/library", listener.local_addr().unwrap());
    let token = "synthetic-capacity-reader-token-32-chars";
    struct Stop(JoinHandle<std::io::Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = Stop(tokio::spawn(crate::evidence_library::serve(
        listener,
        token.into(),
        reader,
    )));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let request = || {
        client.post(&endpoint).bearer_auth(token).header("content-type","application/json").body(serde_json::json!({"action":"content","pin_wire":wire,"sequences":["1"],"format":"anthropic-messages-sse"}).to_string())
    };
    let busy = request().send().await.unwrap();
    assert_eq!(busy.status(), 429);
    assert_eq!(busy.headers()["cache-control"], "no-store");
    assert_eq!(busy.text().await.unwrap(), r#"{"error":"content-busy"}"#);
    drop(first);
    drop(second);
    assert_eq!(request().send().await.unwrap().status(), 200);
    fixture.revoke();
    assert_eq!(request().send().await.unwrap().status(), 403);
}

#[tokio::test]
async fn overall_content_deadline_covers_acquisition_work_after_a_verified_read() {
    use crate::evidence_content::{ContentError, Format};
    let identity = Identity::generate();
    let mut fixture = Fixture::new(94, &identity).await;
    fixture.append(b"synthetic deadline acquisition");
    let reader = Arc::new(Reader::new(identity, vec![fixture.access()]).unwrap());
    let pin = reader.snapshot(&svc::hex(&fixture.scope)).await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let r = reader.clone();
    let mut job = tokio::spawn(async move {
        let mut ready = Some(ready_tx);
        r.content_observed(
            &pin,
            &["1".into()],
            Format::AnthropicMessagesJson,
            || {},
            move || {
                ready.take().unwrap().send(()).unwrap();
                std::future::pending::<()>()
            },
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx)
        .await
        .unwrap()
        .unwrap();
    // Networking and all per-RPC timeouts have finished before virtual time
    // advances. Only the real outer Content deadline can end this operation.
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(20)).await;
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), &mut job).await;
    job.abort();
    assert_eq!(result.unwrap().unwrap(), Err(ContentError::Limited));
    assert_eq!(reader.content_workers.available_permits(), 2);
}

#[tokio::test]
async fn acquisition_cap_stops_before_fetching_the_next_selected_record() {
    use crate::evidence_content::{ContentError, Format};
    use std::sync::atomic::AtomicUsize;
    let identity = Identity::generate();
    let mut fixture = Fixture::new(95, &identity).await;
    for _ in 0..10 {
        fixture.append(&vec![b'x'; 1_000_000]);
    }
    let reader = Reader::new(identity, vec![fixture.access()]).unwrap();
    let pin = reader.snapshot(&svc::hex(&fixture.scope)).await.unwrap();
    // Exercise the real 8MiB boundary independently of the 20s deadline. On slow
    // CI hosts repeated encrypted reads can exhaust time before the byte cap.
    // Keep a runnable cooperative task while time is paused: otherwise Tokio
    // auto-advances to a timeout whenever socket I/O is the only pending work.
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let keep_clock_paused = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let sequences = (1..=10).map(|n| n.to_string()).collect::<Vec<_>>();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let result = reader
        .content_observed(
            &pin,
            &sequences,
            Format::AnthropicMessagesJson,
            || {},
            move || {
                seen.fetch_add(1, Ordering::Relaxed);
                std::future::ready(())
            },
        )
        .await;
    assert_eq!(result, Err(ContentError::Limited));
    assert_eq!(
        count.load(Ordering::Relaxed),
        9,
        "never fetch the tenth selected record after exceeding8MiB"
    );
    // Do not start a second eight-record interpretation here: the synchronous
    // render budget uses std::time::Instant, which Tokio's pause cannot freeze.
    // Successful bounded Content rendering has separate integration coverage.
    // This probe isolates the real acquisition cutoff and its exact fetch count.
    assert_eq!(
        tokio::time::Instant::now(),
        started,
        "byte-cap probe must not spend virtual deadline time"
    );
    keep_clock_paused.abort();
    tokio::time::resume();
}
