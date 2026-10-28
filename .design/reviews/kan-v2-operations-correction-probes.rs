// Reviewer probes (claude-opus-5-5) for d55f821..e95a3ec. Copied into the export's
// tests/ directory to run; synthetic tempdir data only.
#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::{self as ops, Journal},
    evidence_service::hex,
    evidence_spool::Spool,
    sign::Identity,
};
use std::{path::PathBuf, time::Duration};

struct Fx {
    dir: tempfile::TempDir,
    spool: PathBuf,
    journal: PathBuf,
    writer: Identity,
}
fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("queue");
    let journal = dir.path().join("health");
    let writer = Identity::generate();
    let server = Identity::generate();
    Spool::create(&spool, &hex(&[3; 32]), writer.did().as_str(), server.did().as_str(), 1 << 24).unwrap();
    Journal::create(&journal, &spool).unwrap();
    Fx { dir, spool, journal, writer }
}
fn health(n: u8) -> Health {
    Health {
        attempt: hex(&[n; 32]),
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
fn snap(p: &std::path::Path) -> serde_json::Value {
    serde_json::to_value(Journal::open(p).unwrap().snapshot().unwrap()).unwrap()
}
fn fill(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA max_page_count=8192; PRAGMA synchronous=OFF; PRAGMA fullfsync=OFF").unwrap();
    let mut i = 0u64;
    loop {
        let body = format!("{{\"attempt\":\"{:064x}\",\"observer\":\"collector\",\"observed\":40,\"locally_queued\":40,\"unconfirmed\":0,\"recording_gap\":false,\"remote_acknowledged\":false,\"status\":200,\"outcome\":null}}", 1_000_000 + i);
        if conn.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?)", rusqlite::params![format!("{:064x}", 1_000_000 + i), 1_700_000_000i64, 40, 40, 0, body]).is_err() { break; }
        i += 1;
    }
}

// P1: production path (reporter_at) against a full journal: start must not fail;
// report what persists so loss visibility can be judged.
#[test]
fn p1_reporter_at_full_journal_starts_and_reports_visibility() {
    let f = fx();
    fill(&f.journal);
    let before = snap(&f.journal);
    for _ in 0..300 {
        let (report, guard) = ops::reporter_at(f.journal.clone(), f.spool.clone(), f.writer.did().to_string()).expect("start");
        for n in 0..20 { report(&health(n)); }
        drop(report);
        guard.join();
    }
    let after = snap(&f.journal);
    eprintln!("P1 before dropped={} sessions={} after dropped={} sessions={} unclosed={}",
        before["telemetry_dropped"], before["reporters"].as_array().unwrap().len(),
        after["telemetry_dropped"], after["reporters"].as_array().unwrap().len(), after["unclosed_sessions"]);
}

// P2: mismatched journal (bound to a different spool) is never written via reporter_at.
#[test]
fn p2_reporter_at_never_writes_mismatched_journal() {
    let f = fx();
    let other = fx();
    let (report, guard) = ops::reporter_at(other.journal.clone(), f.spool.clone(), f.writer.did().to_string()).unwrap();
    report(&health(1));
    std::thread::sleep(Duration::from_millis(700));
    drop(report);
    guard.join();
    let s = snap(&other.journal);
    assert_eq!(s["attempts"], 0, "{s}");
    assert_eq!(s["reporters"].as_array().unwrap().len(), 0, "{s}");
    // Wrong writer DID also must not bind.
    let (report, guard) = ops::reporter_at(f.journal.clone(), f.spool.clone(), Identity::generate().did().to_string()).unwrap();
    report(&health(2));
    drop(report);
    guard.join();
    assert_eq!(snap(&f.journal)["attempts"], 0);
}

// P3: missing journal that later appears: losses during absence counted on return.
#[test]
fn p3_reporter_at_missing_then_restored_counts_losses() {
    let f = fx();
    let saved = f.dir.path().join("saved");
    std::fs::rename(&f.journal, &saved).unwrap();
    let (report, guard) = ops::reporter_at(f.journal.clone(), f.spool.clone(), f.writer.did().to_string()).unwrap();
    for n in 0..10 { report(&health(n)); }
    std::thread::sleep(Duration::from_millis(700));
    std::fs::rename(&saved, &f.journal).unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    report(&health(99));
    std::thread::sleep(Duration::from_millis(700));
    let live = snap(&f.journal);
    drop(report);
    guard.join();
    let s = snap(&f.journal);
    eprintln!("P3 live={live}\nP3 final dropped={} attempts={} unclosed={}", s["telemetry_dropped"], s["attempts"], s["unclosed_sessions"]);
    assert!(s["telemetry_dropped"].as_u64().unwrap() >= 10, "{s}");
    assert_eq!(s["attempts"], 1, "{s}");
    assert_eq!(s["unclosed_sessions"], 0, "{s}");
}

// P4: journal exclusively locked at startup; callbacks remain prompt; recovery records.
#[test]
fn p4_reporter_at_locked_at_start() {
    let f = fx();
    let lock = rusqlite::Connection::open(&f.journal).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let t = std::time::Instant::now();
    let (report, guard) = ops::reporter_at(f.journal.clone(), f.spool.clone(), f.writer.did().to_string()).unwrap();
    for _ in 0..1000 { report(&health(1)); }
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    std::thread::sleep(Duration::from_millis(1500));
    lock.execute_batch("ROLLBACK").unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    report(&health(2));
    drop(report);
    guard.join();
    let s = snap(&f.journal);
    eprintln!("P4 dropped={} attempts={} unclosed={}", s["telemetry_dropped"], s["attempts"], s["unclosed_sessions"]);
    assert!(s["telemetry_dropped"].as_u64().unwrap() >= 744, "{s}");
    assert!(s["attempts"].as_u64().unwrap() >= 1, "recorded after recovery: {s}");
}

// P5: drain with a journal bound to a different spool never writes it, keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p5_drain_never_writes_mismatched_journal() {
    let f = fx();
    let other = fx();
    let (sp, j) = (f.spool.clone(), other.journal.clone());
    let h = tokio::spawn(async move { ops::drain(&sp, &j, "http://127.0.0.1:9/v1/rpc").await });
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(!h.is_finished());
    h.abort();
    assert!(snap(&other.journal)["worker"].is_null());
}

// P6: prior worker history (last ack, failure count) when the journal is
// unavailable at worker start and returns later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p6_drain_prior_history_after_late_journal() {
    let f = fx();
    let st = Spool::open(&f.spool).unwrap().status().unwrap();
    let prior = ops::WorkerStatus { sampled_at: 1, state: "idle".into(), queue: Some(st), nonempty_since: None,
        last_ack_at: Some(1_700_000_000), last_ack_position: Some(41), consecutive_failures: 0, retry_seconds: 1, telemetry_failures: 7 };
    Journal::open(&f.journal).unwrap().save_worker(&prior).unwrap();
    let saved = f.dir.path().join("saved");
    std::fs::rename(&f.journal, &saved).unwrap();
    let (sp, j) = (f.spool.clone(), f.journal.clone());
    let h = tokio::spawn(async move { ops::drain(&sp, &j, "http://127.0.0.1:9/v1/rpc").await });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    std::fs::rename(&saved, &f.journal).unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    h.abort();
    let w = snap(&f.journal)["worker"].clone();
    eprintln!("P6 worker after late journal: last_ack_at={} last_ack_position={} telemetry_failures={}", w["last_ack_at"], w["last_ack_position"], w["telemetry_failures"]);
}
