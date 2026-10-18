#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::{self as ops, Journal},
    evidence_service::{hex, Grant, Service},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use std::{path::PathBuf, time::Duration};
struct Fixture {
    dir: tempfile::TempDir,
    spool: PathBuf,
    journal: PathBuf,
    writer: Identity,
    server: Identity,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let journal = dir.path().join("health");
        let writer = Identity::generate();
        let server = Identity::generate();
        Spool::create(
            &spool,
            &hex(&[3; 32]),
            writer.did().as_str(),
            server.did().as_str(),
            1 << 24,
        )
        .unwrap();
        Journal::create(&journal, &spool).unwrap();
        Self {
            dir,
            spool,
            journal,
            writer,
            server,
        }
    }
    fn health(&self) -> Health {
        Health {
            attempt: hex(&[5; 32]),
            observer: Observer::Collector,
            observed: 3,
            locally_queued: 2,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: Some(200),
            outcome: Some(Outcome::Completed),
        }
    }
}
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn sample_worker(path: &std::path::Path) -> Option<ops::WorkerStatus> {
    match Journal::open(path).and_then(|mut j| j.snapshot()) {
            Ok(snapshot) => snapshot.worker,
            Err(error) if error.downcast_ref::<rusqlite::Error>().is_some_and(|e| {
                matches!(e, rusqlite::Error::SqliteFailure(code, _) if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked))
            }) => None,
            Err(error) => panic!("unexpected journal read failure: {error}"),
        }
}

#[test]
fn journal_reopen_preserves_monotone_gaps_and_binding() {
    let f = Fixture::new();
    let mut j = Journal::open(&f.journal).unwrap();
    j.record(&f.health()).unwrap();
    assert!(j
        .check_binding(&f.spool, Some(f.server.did().as_str()))
        .is_err());
    let mut backwards = f.health();
    backwards.observed = 2;
    backwards.unconfirmed = 0;
    backwards.recording_gap = false;
    assert!(j.record(&backwards).is_err());
    drop(j);
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    assert_eq!((s.attempts, s.observed, s.unconfirmed), (1, 3, 1));
    assert!(s.worker.is_none());
    assert_eq!(s.recent[0]["capture"]["outcome"], "completed");
    assert!(!serde_json::to_string(&s).unwrap().contains("ciphertext"));
}
#[test]
fn locked_journal_never_blocks_callback_and_retains_loss_count() {
    let f = Fixture::new();
    let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap()).unwrap();
    assert_eq!(
        Journal::open(&f.journal)
            .unwrap()
            .snapshot()
            .unwrap()
            .unclosed_sessions,
        1
    );
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (done, completion) = std::sync::mpsc::channel();
    let health = f.health();
    let caller = std::thread::spawn(move || {
        for i in 0..600u64 {
            let mut distinct = health.clone();
            distinct.attempt = format!("{i:064x}");
            report(&distinct);
        }
        drop(report);
        done.send(()).unwrap();
    });
    let prompt = completion.recv_timeout(Duration::from_secs(1)).is_ok();
    lock.execute_batch("ROLLBACK").unwrap();
    caller.join().unwrap();
    guard.join();
    assert!(prompt, "capture callback blocked on the health journal");
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    assert!(
        s.telemetry_dropped > 250,
        "distinct-attempt overflow must be counted independently of failed journal writes"
    );
    assert_eq!(s.unclosed_sessions, 0);
    // Every write may have failed before the lock was released. This pressure
    // test requires a visible loss count, not a scheduling-dependent survivor.
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuous_delivery_retries_exact_head_and_resumes_after_restart() {
    let f = Fixture::new();
    let mut queue = Spool::open(&f.spool).unwrap();
    kan::evidence_delivery::queue(
        &mut queue,
        &f.writer,
        &kan::evidence_crypto::public_key(&[9; 32]).unwrap(),
        &[1; 16],
        b"synthetic raw body",
    )
    .unwrap();
    let retained = queue.head().unwrap().unwrap();
    drop(queue);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let endpoint = format!("http://{addr}/v1/rpc");
    let run = |spool: PathBuf, journal: PathBuf, endpoint: String| {
        Task(tokio::spawn(async move {
            ops::drain(&spool, &journal, &endpoint).await.unwrap();
        }))
    };
    let first = run(f.spool.clone(), f.journal.clone(), endpoint.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if sample_worker(&f.journal).is_some_and(|w| w.state == "retrying") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        Spool::open(&f.spool).unwrap().head().unwrap().unwrap(),
        retained
    );
    let ledger = Ledger::create(&f.dir.path().join("archive")).unwrap();
    let service = Service::new(
        ledger,
        [3; 32],
        f.server,
        vec![Grant {
            principal: f.writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let _server = Task(tokio::spawn(async move {
        kan::evidence_http::serve(listener, service).await.unwrap();
    }));
    let _worker = run(f.spool.clone(), f.journal.clone(), endpoint);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if sample_worker(&f.journal).is_some_and(|w| {
                w.queue.is_some_and(|q| q.pending == 0) && w.last_ack_position == Some(0)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let conn = rusqlite::Connection::open(f.dir.path().join("archive/archive.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM commits", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let blobs: Vec<Vec<u8>> = conn
        .prepare("SELECT bytes FROM objects")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(blobs.iter().any(|b| b == &retained));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_auth_host_origin_routes_and_shared_cli_snapshot() {
    let f = Fixture::new();
    Journal::open(&f.journal)
        .unwrap()
        .record(&f.health())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let journal = f.journal.clone();
    let token = "synthetic-dashboard-token-at-least-32";
    let _server = Task(tokio::spawn(async move {
        kan::evidence_dashboard::serve(listener, token.into(), journal)
            .await
            .unwrap();
    }));
    let c = reqwest::Client::builder().no_proxy().build().unwrap();
    let theme = c.get(format!("{url}/theme.js")).send().await.unwrap();
    assert_eq!(theme.status(), 200);
    assert_eq!(theme.headers()["cache-control"], "no-store");
    assert_eq!(theme.text().await.unwrap(), include_str!("../web/theme.js"));
    assert_eq!(
        c.get(format!("{url}/api/status"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for header in ["host", "origin"] {
        assert_eq!(
            c.get(format!("{url}/api/status"))
                .bearer_auth(token)
                .header(header, "http://foreign.example")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    assert_eq!(
        c.post(format!("{url}/api/status"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    let mut duplicate = reqwest::header::HeaderMap::new();
    duplicate.append(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    duplicate.append(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    assert_eq!(
        c.get(format!("{url}/api/status"))
            .headers(duplicate)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let r = c
        .get(format!("{url}/api/status"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    let mut http: serde_json::Value = r.json().await.unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(["ops-status", f.journal.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    http.as_object_mut().unwrap().remove("read_at");
    cli.as_object_mut().unwrap().remove("read_at");
    assert_eq!(http, cli);
    for (path, mime) in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/style.css", "text/css"),
    ] {
        let r = c.get(format!("{url}{path}")).send().await.unwrap();
        assert!(r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with(mime));
        assert!(!r.text().await.unwrap().contains(token));
    }
    assert_eq!(
        c.get(format!("{url}/api/status?token=x"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

// Retained from the independent Opus review, adapted to the shared fixture.
fn fill_journal(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    // Synthetic setup only: disable sync to fill 32 MiB without thousands of fsyncs.
    conn.execute_batch("PRAGMA max_page_count=8192; PRAGMA synchronous=OFF; PRAGMA fullfsync=OFF")
        .unwrap();
    let mut count = 0;
    loop {
        let h = Health {
            attempt: format!("{:064x}", 1_000_000 + count),
            observer: Observer::Collector,
            observed: 40,
            locally_queued: 40,
            unconfirmed: 0,
            recording_gap: false,
            remote_acknowledged: false,
            status: Some(200),
            outcome: None,
        };
        match conn.execute(
            "INSERT INTO attempts VALUES(?,?,?,?,?,?)",
            rusqlite::params![
                h.attempt,
                1_700_000_000i64,
                40,
                40,
                0,
                serde_json::to_string(&h).unwrap()
            ],
        ) {
            Ok(_) => count += 1,
            Err(e) => {
                assert!(e.to_string().contains("full"), "{e}");
                break;
            }
        }
    }
    assert!(count > 0);
}
#[test]
fn full_health_journal_does_not_refuse_reporter_restart() {
    let f = Fixture::new();
    fill_journal(&f.journal);
    for _ in 0..500 {
        let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap())
            .expect("health capacity must not stop proxy restart");
        drop(report);
        guard.join();
    }
}
#[test]
fn missing_spool_keeps_bound_reporter_available_for_gap_reporting() {
    let f = Fixture::new();
    std::fs::remove_file(&f.spool).unwrap();
    let journal = Journal::open(&f.journal).unwrap();
    journal
        .check_binding(&f.spool, Some(f.writer.did().as_str()))
        .unwrap();
    let (report, guard) = ops::reporter(journal).unwrap();
    report(&f.health());
    drop(report);
    guard.join();
    assert_eq!(
        Journal::open(&f.journal)
            .unwrap()
            .snapshot()
            .unwrap()
            .unconfirmed,
        1
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_lock_does_not_stop_archive_worker() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    drop(listener);
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = Task(tokio::spawn(async move {
        ops::drain(&spool, &journal, &endpoint).await.unwrap();
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if Journal::open(&f.journal)
                .unwrap()
                .snapshot()
                .unwrap()
                .worker
                .is_some_and(|w| w.state == "idle")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    lock.execute_batch("ROLLBACK").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !worker.0.is_finished(),
        "telemetry lock stopped delivery worker"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let json = serde_json::to_value(Journal::open(&f.journal).unwrap().snapshot().unwrap())
                .unwrap();
            if json["worker"]["telemetry_failures"]
                .as_u64()
                .is_some_and(|n| n > 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_retries_wait_and_preserve_continuous_backlog_age() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::AsyncWriteExt;
    let f = Fixture::new();
    let mut spool = Spool::open(&f.spool).unwrap();
    kan::evidence_delivery::queue(
        &mut spool,
        &f.writer,
        &kan::evidence_crypto::public_key(&[9; 32]).unwrap(),
        &[8; 16],
        b"retain head",
    )
    .unwrap();
    let original = spool.head().unwrap().unwrap();
    drop(spool);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let _server = Task(tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let _ = stream
                .write_all(
                    b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    }));
    let (p, j) = (f.spool.clone(), f.journal.clone());
    let _worker = Task(tokio::spawn(async move {
        ops::drain(&p, &j, &endpoint).await.unwrap();
    }));
    let first = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let w = sample_worker(&f.journal);
            if let Some(w) = w {
                if w.consecutive_failures == 1 {
                    break w;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no tight-loop retry storm");
    let second = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(w) = sample_worker(&f.journal) {
                if w.consecutive_failures >= 2 {
                    break w;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(first.nonempty_since, second.nonempty_since);
    assert_eq!(second.retry_seconds, 4);
    assert_eq!(
        Spool::open(&f.spool).unwrap().head().unwrap().unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn operations_journal_refuses_public_permissions_and_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    std::fs::set_permissions(&f.journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Journal::open(&f.journal).is_err());
    std::fs::set_permissions(&f.journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Journal::open(&f.journal).is_ok());
    let link = f.dir.path().join("linked-health");
    symlink(&f.journal, &link).unwrap();
    assert!(Journal::open(&link).is_err());
}
#[tokio::test]
async fn dashboard_rejects_nonloopback_listener() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        kan::evidence_dashboard::serve(
            listener,
            "synthetic-dashboard-token-at-least-32".into(),
            f.journal.clone(),
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "dashboard must reject remote binding before serving"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_journal_at_start_does_not_gate_archive_delivery() {
    let f = Fixture::new();
    let mut queue = Spool::open(&f.spool).unwrap();
    kan::evidence_delivery::queue(
        &mut queue,
        &f.writer,
        &kan::evidence_crypto::public_key(&[9; 32]).unwrap(),
        &[9; 16],
        b"independent archive delivery",
    )
    .unwrap();
    drop(queue);
    let saved = f.dir.path().join("preserved-health");
    std::fs::rename(&f.journal, &saved).unwrap();
    let service = Service::new(
        Ledger::create(&f.dir.path().join("archive")).unwrap(),
        [3; 32],
        f.server,
        vec![Grant {
            principal: f.writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let _server = Task(tokio::spawn(async move {
        kan::evidence_http::serve(listener, service).await.unwrap();
    }));
    let (p, j) = (f.spool.clone(), f.journal.clone());
    let worker = Task(tokio::spawn(async move {
        ops::drain(&p, &j, &endpoint).await.unwrap();
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if Spool::open(&f.spool).unwrap().status().unwrap().pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(!worker.0.is_finished());
    std::fs::rename(&saved, &f.journal).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = serde_json::to_value(Journal::open(&f.journal).unwrap().snapshot().unwrap())
                .unwrap();
            if s["worker"]["telemetry_failures"]
                .as_u64()
                .is_some_and(|n| n > 0)
                && s["worker"]["queue"]["pending"] == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

// A real signed archive reply establishes the prior acknowledgment used below.
fn seeded_worker_history(f: &Fixture) -> ops::WorkerStatus {
    let mut queue = Spool::open(&f.spool).unwrap();
    let recipient = kan::evidence_crypto::public_key(&[9; 32]).unwrap();
    kan::evidence_delivery::queue(
        &mut queue,
        &f.writer,
        &recipient,
        &[6; 16],
        b"history fixture",
    )
    .unwrap();
    let request = queue.head().unwrap().unwrap();
    let record = kan::evidence_service::append_manifest(&request).unwrap();
    // Service construction consumes its key; duplicate only this generated
    // fixture identity through an owner-only file in the disposable test dir.
    let key = f.dir.path().join("synthetic-server-key");
    f.server.save(&key).unwrap();
    let mut service = Service::new(
        Ledger::create(&f.dir.path().join("history-archive")).unwrap(),
        [3; 32],
        Identity::load_existing(&key).unwrap(),
        vec![Grant {
            principal: f.writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let reply = service.dispatch(&request, ops::now()).unwrap();
    assert_eq!(
        kan::evidence_service::admitted_manifest(&request, &reply, f.server.did().as_str())
            .unwrap()
            .cid(),
        record.cid()
    );
    queue.acknowledge(&reply.bytes().unwrap()).unwrap();
    let prior = ops::WorkerStatus {
        sampled_at: 1,
        state: "idle".into(),
        queue: Some(queue.status().unwrap()),
        nonempty_since: None,
        last_ack_at: Some(1234),
        last_ack_position: Some(0),
        consecutive_failures: 0,
        retry_seconds: 1,
        telemetry_failures: 7,
    };
    Journal::open(&f.journal)
        .unwrap()
        .save_worker(&prior)
        .unwrap();
    prior
}
async fn wait_worker_history(f: &Fixture) -> ops::WorkerStatus {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let w = Journal::open(&f.journal)
                .ok()
                .and_then(|mut j| j.snapshot().ok())
                .and_then(|s| s.worker);
            if let Some(w) = w.filter(|w| w.sampled_at > 1) {
                return w;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_journal_recovery_preserves_ack_and_accumulates_failures_once() {
    let f = Fixture::new();
    seeded_worker_history(&f);
    let saved = f.dir.path().join("saved-history");
    std::fs::rename(&f.journal, &saved).unwrap();
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = Task(tokio::spawn(async move {
        ops::drain(&spool, &journal, "http://127.0.0.1:9/v1/rpc")
            .await
            .unwrap();
    }));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    std::fs::rename(saved, &f.journal).unwrap();
    let w = wait_worker_history(&f).await;
    assert_eq!((w.last_ack_position, w.last_ack_at), (Some(0), Some(1234)));
    assert!(
        w.telemetry_failures >= 9,
        "prior seven plus this run's missing writes: {w:?}"
    );
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let later = Journal::open(&f.journal)
        .unwrap()
        .snapshot()
        .unwrap()
        .worker
        .unwrap();
    assert_eq!(
        later.telemetry_failures, w.telemetry_failures,
        "successful retries must not recount the run's failures"
    );
    drop(worker);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_read_lock_cannot_erase_worker_history() {
    let f = Fixture::new();
    seeded_worker_history(&f);
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = Task(tokio::spawn(async move {
        ops::drain(&spool, &journal, "http://127.0.0.1:9/v1/rpc")
            .await
            .unwrap();
    }));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    lock.execute_batch("ROLLBACK").unwrap();
    let w = wait_worker_history(&f).await;
    assert_eq!((w.last_ack_position, w.last_ack_at), (Some(0), Some(1234)));
    assert!(w.telemetry_failures > 7);
    drop(worker);
}

#[test]
fn lazy_reporter_rejects_wrong_spool_and_wrong_writer() {
    let f = Fixture::new();
    let other = Fixture::new();
    for (journal, writer) in [
        (other.journal.clone(), f.writer.did().to_string()),
        (f.journal.clone(), other.writer.did().to_string()),
    ] {
        let (report, guard) = ops::reporter_at(journal.clone(), f.spool.clone(), writer).unwrap();
        report(&f.health());
        drop(report);
        guard.join();
        let snapshot = Journal::open(&journal).unwrap().snapshot().unwrap();
        assert_eq!(snapshot.attempts, 0);
        assert!(snapshot.reporters.is_empty());
    }
}
#[test]
fn lazy_reporter_counts_absent_journal_losses_after_recovery() {
    let f = Fixture::new();
    let saved = f.dir.path().join("temporarily-unavailable");
    std::fs::rename(&f.journal, &saved).unwrap();
    let (report, guard) = ops::reporter_at(
        f.journal.clone(),
        f.spool.clone(),
        f.writer.did().to_string(),
    )
    .unwrap();
    for i in 0..10u8 {
        let mut h = f.health();
        h.attempt = hex(&[i; 32]);
        report(&h);
    }
    std::thread::sleep(Duration::from_millis(700));
    std::fs::rename(saved, &f.journal).unwrap();
    report(&f.health());
    drop(report);
    guard.join();
    let snapshot = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    assert!(
        snapshot.telemetry_dropped >= 10,
        "missing-journal updates must not disappear from the loss count"
    );
    assert_eq!(snapshot.attempts, 1);
    assert_eq!(snapshot.unclosed_sessions, 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_rejects_a_journal_bound_to_another_spool() {
    let f = Fixture::new();
    let other = Fixture::new();
    let (spool, journal) = (f.spool.clone(), other.journal.clone());
    let worker = Task(tokio::spawn(async move {
        ops::drain(&spool, &journal, "http://127.0.0.1:9/v1/rpc")
            .await
            .unwrap();
    }));
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(
        !worker.0.is_finished(),
        "journal binding failure must not stop delivery"
    );
    assert!(Journal::open(&other.journal)
        .unwrap()
        .snapshot()
        .unwrap()
        .worker
        .is_none());
    drop(worker);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_refuses_history_outside_current_queue_lineage() {
    for case in [
        "regressed-frontier",
        "different-head",
        "unacknowledged-position",
    ] {
        let f = Fixture::new();
        let mut prior = seeded_worker_history(&f);
        match case {
            "regressed-frontier" => prior.queue.as_mut().unwrap().next += 1,
            "different-head" => {
                prior.queue.as_mut().unwrap().previous = Some("different-retained-head".into())
            }
            _ => prior.last_ack_position = Some(1),
        }
        Journal::open(&f.journal)
            .unwrap()
            .save_worker(&prior)
            .unwrap();
        let (spool, journal) = (f.spool.clone(), f.journal.clone());
        let worker = Task(tokio::spawn(async move {
            ops::drain(&spool, &journal, "http://127.0.0.1:9/v1/rpc")
                .await
                .unwrap();
        }));
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !worker.0.is_finished(),
            "delivery must remain independent of rejected history"
        );
        let retained = Journal::open(&f.journal)
            .unwrap()
            .snapshot()
            .unwrap()
            .worker
            .unwrap();
        assert_eq!(
            retained.sampled_at, 1,
            "{case}: incompatible history must not be merged into a fresh status"
        );
        drop(worker);
    }
}

#[test]
fn persisted_terminal_observation_rejects_regression_and_contradiction() {
    let f = Fixture::new();
    let mut journal = Journal::open(&f.journal).unwrap();
    let health = f.health();
    journal.record(&health).unwrap();
    let mut next = health.clone();
    next.outcome = None;
    assert!(journal.record(&next).is_err());
    next = health.clone();
    next.status = Some(503);
    assert!(journal.record(&next).is_err());
    next = health.clone();
    next.observer = Observer::Gateway;
    assert!(journal.record(&next).is_err());
    assert_eq!(
        journal.snapshot().unwrap().recent[0]["capture"]["outcome"],
        "completed"
    );
}

/// Qualification workload from the independent coalescing review: 80 distinct
/// attempts (below the 256 bound), eight concurrent streams at 1 ms intervals.
/// Allows four terminal losses to avoid claiming a scheduling-independent SLA;
/// the mandatory held-lock unit separately proves exact loss accounting.
#[test]
fn synchronized_streams_retain_terminal_summaries() {
    let f = Fixture::new();
    let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap()).unwrap();
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut threads = Vec::new();
    for t in 0..8 {
        let report = report.clone();
        let start = start.clone();
        threads.push(std::thread::spawn(move || {
            start.wait();
            for i in 0..10 {
                let mut h = Health {
                    attempt: format!("{:064x}", t * 1_000_000 + i + 10),
                    observer: Observer::Collector,
                    observed: 0,
                    locally_queued: 0,
                    unconfirmed: 0,
                    recording_gap: false,
                    remote_acknowledged: false,
                    status: Some(200),
                    outcome: None,
                };
                report(&h);
                for n in 1..=30 {
                    std::thread::sleep(Duration::from_millis(1));
                    h.observed = n;
                    h.locally_queued = n;
                    if n == 30 {
                        h.outcome = Some(Outcome::Completed);
                    }
                    report(&h);
                }
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    drop(report);
    guard.join();
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    let terminal = s
        .recent
        .iter()
        .filter(|r| r["capture"]["outcome"] == "completed")
        .count();
    eprintln!(
        "synchronized terminals={terminal}/80; lost-summary observations={}",
        s.telemetry_dropped
    );
    assert!(
        terminal >= 76,
        "healthy-journal contention lost more than 5% of terminal summaries"
    );
    assert!(
        s.observed == 2400 || s.telemetry_dropped > 0,
        "shortfall must be disclosed"
    );
    assert_eq!(s.unclosed_sessions, 0);
}

#[test]
fn journal_session_exhaustion_is_visible_without_refusing_reporter_start() {
    let f = Fixture::new();
    let conn = rusqlite::Connection::open(&f.journal).unwrap();
    conn.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1023) INSERT INTO sessions SELECT printf('%032x',i),0,0,1 FROM n").unwrap();
    drop(conn);
    let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap())
        .expect("health session capacity cannot refuse capture startup");
    report(&f.health());
    drop(report);
    guard.join();
    let mut journal = Journal::open(&f.journal).unwrap();
    let value = serde_json::to_value(journal.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["journal"]["exhausted_observed"], true,
        "session exhaustion must be retained and visible after restart"
    );
    assert_eq!(value["journal"]["exhaustion_reason"], "session_limit");
    assert_eq!(value["journal"]["sessions_used"], 1024);
    assert_eq!(value["journal"]["loss_count_certainty"], "lower_bound");
    assert!(
        journal.record(&f.health()).is_err(),
        "a heartbeat cannot unseal exhausted history"
    );
}
