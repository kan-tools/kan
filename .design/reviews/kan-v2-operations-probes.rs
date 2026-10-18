#![cfg(feature = "v2-crypto")]
//! Independent reviewer probes (claude-opus-5-5) for d55f821. Synthetic data only.
//! Each probe prints a PROBE line; assertions encode the behaviour the design
//! *requires*, so a failing probe is a finding, not a broken test.
use kan::{
    evidence_capture::{Health, Observer},
    evidence_operations::{self as ops, Journal},
    evidence_service::{hex, Grant, Service},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Fixture {
    dir: tempfile::TempDir,
    spool: PathBuf,
    journal: PathBuf,
    writer: Identity,
    server: Identity,
}
fn fixture() -> Fixture {
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
    Fixture {
        dir,
        spool,
        journal,
        writer,
        server,
    }
}
fn health(attempt: u64, observed: u64) -> Health {
    Health {
        attempt: format!("{attempt:064x}"),
        observer: Observer::Collector,
        observed,
        locally_queued: observed,
        unconfirmed: 0,
        recording_gap: false,
        remote_acknowledged: false,
        status: Some(200),
        outcome: None,
    }
}
/// Fill the attempts table with realistic serialized Health rows until SQLite
/// refuses growth at the production 8192-page cap. Returns rows inserted.
fn fill_to_page_cap(path: &Path) -> u64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA max_page_count=8192; PRAGMA synchronous=OFF; PRAGMA fullfsync=OFF")
        .unwrap();
    let mut n = 0u64;
    loop {
        let h = health(1_000_000 + n, 40);
        let r = conn.execute(
            "INSERT INTO attempts VALUES(?,?,?,?,?,?)",
            rusqlite::params![h.attempt, 1_700_000_000i64, 40, 40, 0, serde_json::to_string(&h).unwrap()],
        );
        match r {
            Ok(_) => n += 1,
            Err(e) => {
                println!("PROBE fill stopped: {e}");
                break;
            }
        }
    }
    n
}
fn queue_one(f: &Fixture) -> Vec<u8> {
    let mut queue = Spool::open(&f.spool).unwrap();
    kan::evidence_delivery::queue(
        &mut queue,
        &f.writer,
        &kan::evidence_crypto::public_key(&[9; 32]).unwrap(),
        &[1; 16],
        b"synthetic raw body",
    )
    .unwrap();
    queue.head().unwrap().unwrap()
}

/// REQ-2 / north star: telemetry capacity must fail closed for telemetry, not
/// inference. With --health-journal, run_proxy calls ops::reporter at startup and
/// refuses to start the capture proxy if it errors.
#[test]
fn probe_full_journal_blocks_reporter_startup() {
    let f = fixture();
    let rows = fill_to_page_cap(&f.journal);
    println!("PROBE fill: {rows} realistic attempts fit before 8192-page cap (attempt cap is 100000)");
    let mut started = 0;
    for _ in 0..500 {
        match ops::reporter(Journal::open(&f.journal).unwrap()) {
            Ok((report, guard)) => {
                drop(report);
                guard.join();
                started += 1;
            }
            Err(e) => {
                println!("PROBE reporter startup refused after {started} restarts on full journal: {e}");
                break;
            }
        }
    }
    assert_eq!(
        started, 500,
        "full operations journal stops capture proxy restart (inference outage), not just telemetry"
    );
}

/// REQ-1 vs journal: does archive delivery keep running while the private
/// operations journal is briefly locked (e.g. operator sqlite3 inspection/backup)?
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_journal_lock_stops_archive_worker() {
    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    drop(listener);
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = tokio::spawn(async move { ops::drain(&spool, &journal, &endpoint).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    lock.execute_batch("ROLLBACK").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let exited = worker.is_finished();
    if exited {
        println!("PROBE drain exited on 1.5s journal lock: {:?}", worker.await.unwrap().err());
    } else {
        worker.abort();
    }
    assert!(!exited, "archive drain terminated because the telemetry journal was locked");
}

/// REQ-2: drop accounting under a healthy, unlocked journal at streaming rates.
#[test]
fn probe_streaming_rate_drops_with_healthy_journal() {
    let f = fixture();
    let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap()).unwrap();
    let chunks = 1500u64;
    let start = Instant::now();
    for i in 1..=chunks {
        report(&health(7, i));
        std::thread::sleep(Duration::from_micros(500));
    }
    let callback = start.elapsed();
    drop(report);
    guard.join();
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    println!(
        "PROBE streaming: {chunks} cumulative updates for ONE attempt over {callback:?}; persisted observed={} telemetry_dropped={} ",
        s.observed, s.telemetry_dropped
    );
    assert_eq!(s.observed, chunks, "final cumulative snapshot was not retained");
}

/// Crash state: a live reporter's session is indistinguishable from a crashed one.
#[test]
fn probe_active_session_reads_as_unclosed() {
    let f = fixture();
    let (report, guard) = ops::reporter(Journal::open(&f.journal).unwrap()).unwrap();
    report(&health(9, 1));
    std::thread::sleep(Duration::from_millis(700));
    let live = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    // Simulate a SIGKILL: the session row is never closed (leak the writer).
    std::mem::forget(report);
    std::mem::forget(guard);
    let reopened = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    println!(
        "PROBE crash: live unclosed={} after-kill unclosed={} reporters={:?}",
        live.unclosed_sessions, reopened.unclosed_sessions, reopened.reporters
    );
    assert_eq!(reopened.unclosed_sessions, 1);
    assert_eq!(reopened.observed, 1);
}

/// AC-1: a permanently rejected head is retained and never skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_rejected_head_retained_and_backoff_visible() {
    let f = fixture();
    let retained = queue_one(&f);
    let ledger = Ledger::create(&f.dir.path().join("archive")).unwrap();
    // No grant for the writer: every append is refused.
    let other = Identity::generate();
    let service = Service::new(
        ledger,
        [3; 32],
        f.server,
        vec![Grant {
            principal: other.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { kan::evidence_http::serve(listener, service).await });
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = tokio::spawn(async move { ops::drain(&spool, &journal, &endpoint).await });
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    let w = s.worker.unwrap();
    println!(
        "PROBE rejection: state={} failures={} retry={}s pending={:?}",
        w.state,
        w.consecutive_failures,
        w.retry_seconds,
        w.queue.as_ref().map(|q| q.pending)
    );
    assert_eq!(Spool::open(&f.spool).unwrap().head().unwrap().unwrap(), retained);
    assert_eq!(w.state, "retrying");
    assert!(!worker.is_finished());
    worker.abort();
    server.abort();
}

/// REQ-3: unavailable health must not look like zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_dashboard_boundary_and_unavailable() {
    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let journal = f.journal.clone();
    let token = "synthetic-dashboard-token-at-least-32x";
    let server = tokio::spawn(async move {
        kan::evidence_dashboard::serve(listener, token.into(), journal).await
    });
    let raw = |req: String| -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out.lines().next().unwrap_or("<closed>").to_string()
    };
    let auth = format!("Authorization: Bearer {token}\r\n");
    let cases = [
        ("missing host", format!("GET /api/status HTTP/1.1\r\n{auth}\r\n")),
        ("localhost host", format!("GET /api/status HTTP/1.1\r\nHost: localhost:{}\r\n{auth}\r\n", addr.port())),
        ("dup auth", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}{auth}\r\n")),
        ("lowercase scheme", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nAuthorization: bearer {token}\r\n\r\n")),
        ("null origin", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nOrigin: null\r\n{auth}\r\n")),
        ("https origin", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://{addr}\r\n{auth}\r\n")),
        ("OPTIONS", format!("OPTIONS /api/status HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\r\n")),
        ("HEAD", format!("HEAD / HTTP/1.1\r\nHost: {addr}\r\n\r\n")),
        ("absolute-form", format!("GET http://{addr}/api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}\r\n")),
        ("path traversal", format!("GET /../api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}\r\n")),
        ("prefix token", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\n\r\n", &token[..33])),
        ("valid", format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n{auth}\r\n")),
    ];
    let mut results = Vec::new();
    for (name, req) in cases {
        let line = raw(req);
        println!("PROBE dashboard {name}: {line}");
        results.push((name, line));
    }
    for (name, line) in &results {
        let ok = line.contains(" 200 ");
        assert_eq!(ok, *name == "valid" || *name == "absolute-form", "{name}: {line}");
    }
    std::fs::remove_file(&f.journal).unwrap();
    let line = raw(format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\n{auth}\r\n"));
    println!("PROBE dashboard missing journal: {line}");
    assert!(line.contains(" 503 "));
    // Slot exhaustion: 8 idle sockets hold every slot until the header deadline.
    let idle: Vec<_> = (0..8).map(|_| std::net::TcpStream::connect(addr).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    let line = raw(format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n"));
    println!("PROBE dashboard 9th client while 8 idle sockets open: {line:?} after {:?}", start.elapsed());
    drop(idle);
    server.abort();
}

/// Replay/ack binding: the archive committed, but the local acknowledgment was
/// lost (crash between reply and acknowledge). The worker must resend identical
/// bytes, accept the idempotent reply, ack once and never duplicate the archive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_ambiguous_commit_replays_identical_bytes_once() {
    let f = fixture();
    let retained = queue_one(&f);
    let issuer = f.server.did().to_string();
    let writer = f.writer.did().to_string();
    let archive = f.dir.path().join("archive");
    let service = Service::new(
        Ledger::create(&archive).unwrap(),
        [3; 32],
        f.server,
        vec![Grant { principal: writer, append: true, inventory: false }],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { kan::evidence_http::serve(listener, service).await });
    // Remote commit with no local acknowledgment.
    kan::evidence_http::send(&endpoint, &issuer, &retained).await.unwrap();
    assert_eq!(Spool::open(&f.spool).unwrap().head().unwrap().unwrap(), retained);
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = tokio::spawn(async move { ops::drain(&spool, &journal, &endpoint).await });
    let deadline = Instant::now() + Duration::from_secs(5);
    let w = loop {
        let w = Journal::open(&f.journal).unwrap().snapshot().unwrap().worker;
        if w.as_ref().is_some_and(|w| w.last_ack_position.is_some()) || Instant::now() > deadline {
            break w;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    println!("PROBE ambiguous commit: worker={w:?}");
    worker.abort();
    server.abort();
    let w = w.expect("worker sample");
    assert_eq!(w.last_ack_position, Some(0));
    let conn = rusqlite::Connection::open(archive.join("archive.sqlite")).unwrap();
    let commits: i64 = conn.query_row("SELECT count(*) FROM commits", [], |r| r.get(0)).unwrap();
    assert_eq!(commits, 1);
    assert!(Spool::open(&f.spool).unwrap().head().unwrap().is_none());
}

/// Does the drain worker survive a full operations journal (no automatic expiry)?
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_full_journal_and_archive_worker() {
    let f = fixture();
    queue_one(&f);
    fill_to_page_cap(&f.journal);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    drop(listener);
    let (spool, journal) = (f.spool.clone(), f.journal.clone());
    let worker = tokio::spawn(async move { ops::drain(&spool, &journal, &endpoint).await });
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let exited = worker.is_finished();
    if exited {
        println!("PROBE full journal drain exit: {:?}", worker.await.unwrap().err());
    } else {
        println!("PROBE full journal drain still running");
        worker.abort();
    }
    assert!(!exited);
}
