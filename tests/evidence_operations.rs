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
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = std::time::Instant::now();
    for _ in 0..3000 {
        report(&f.health());
    }
    assert!(start.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(250));
    lock.execute_batch("ROLLBACK").unwrap();
    drop(report);
    guard.join();
    let s = Journal::open(&f.journal).unwrap().snapshot().unwrap();
    assert!(s.telemetry_dropped > 0);
    assert_eq!(s.unclosed_sessions, 0);
    assert_eq!(s.unconfirmed, 1);
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
            if Journal::open(&f.journal)
                .unwrap()
                .snapshot()
                .unwrap()
                .worker
                .is_some_and(|w| w.state == "retrying")
            {
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
            let st = Journal::open(&f.journal).unwrap().snapshot().unwrap();
            if st.worker.is_some_and(|w| {
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
