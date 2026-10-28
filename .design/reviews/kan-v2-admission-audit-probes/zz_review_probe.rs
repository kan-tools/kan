#![cfg(feature = "v2-crypto")]
// Reviewer probe; temporary copy into tests/, removed after the run.
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::{self as ops, Journal},
    evidence_service::hex,
    evidence_spool::Spool,
    sign::Identity,
};
use std::path::{Path, PathBuf};

fn setup() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("queue");
    let journal = dir.path().join("health");
    let w = Identity::generate();
    Spool::create(&spool, &hex(&[3; 32]), w.did().as_str(), w.did().as_str(), 1 << 24).unwrap();
    Journal::create(&journal, &spool).unwrap();
    (dir, journal)
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
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    v.sort();
    v
}

/// An older binary sealed a session-exhausted journal and released its reserve.
/// What does the new binary do with attempt writes there?
#[test]
fn probe_old_v2_session_marker_with_released_reserve() {
    let (_d, path) = setup();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1023) INSERT INTO sessions SELECT printf('%032x',i),0,0,1 FROM n; DELETE FROM reserve; UPDATE control SET exhausted=1, reason='session_limit' WHERE singleton=1;").unwrap();
    drop(c);
    let mut j = Journal::open(&path).unwrap();
    let r = j.record(&health(5));
    let s = serde_json::to_value(j.snapshot().unwrap()).unwrap();
    eprintln!("PROBE old-v2 released-reserve session marker: record={:?} reason={} reserve={}", r.as_ref().map_err(|e| e.to_string()), s["journal"]["exhaustion_reason"], s["journal"]["reserve_bytes"]);
}

/// Repeated session-limit refusals (new reporters) must not rewrite control.
#[test]
fn probe_repeated_session_refusals_are_byte_stable() {
    let (_d, path) = setup();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1023) INSERT INTO sessions SELECT printf('%032x',i),0,0,1 FROM n").unwrap();
    drop(c);
    let (report, guard) = ops::reporter(Journal::open(&path).unwrap()).unwrap();
    drop(report);
    guard.join();
    let before = std::fs::read(&path).unwrap();
    for _ in 0..5 {
        let (report, guard) = ops::reporter(Journal::open(&path).unwrap()).unwrap();
        drop(report);
        guard.join();
    }
    let same = std::fs::read(&path).unwrap() == before;
    eprintln!("PROBE repeated session refusals byte-stable={same}");
    assert!(same, "unchanged session refusals rewrote the journal");
}

/// Session-limited journal, then real SQLite page exhaustion on a new attempt.
#[test]
fn probe_session_limited_then_page_full_escalates() {
    let (_d, path) = setup();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("UPDATE control SET exhausted=1, reason='session_limit' WHERE singleton=1; PRAGMA max_page_count=8192;").unwrap();
    let mut i = 0u64;
    for size in [3000usize, 400, 40] {
        loop {
            i += 1;
            let id = format!("{i:032x}{}", "x".repeat(size));
            if c.execute("INSERT INTO sessions VALUES(?,0,0,1)", [id]).is_err() {
                break;
            }
        }
    }
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    drop(c);
    let mut j = Journal::open(&path).unwrap();
    let mut first = None;
    for n in 0..200u8 {
        if let Err(e) = j.record(&health(n)) {
            first = Some((n, e.to_string()));
            break;
        }
    }
    let s = serde_json::to_value(j.snapshot().unwrap()).unwrap();
    eprintln!("PROBE page-full after session-limit: pages={pages} first_err={first:?} reason={} reserve={}", s["journal"]["exhaustion_reason"], s["journal"]["reserve_bytes"]);
    assert!(first.is_some());
    assert_eq!(s["journal"]["exhaustion_reason"], "sqlite_full");
    assert_eq!(s["journal"]["reserve_bytes"], 0);
    let before = std::fs::read(&path).unwrap();
    for n in 0..10u8 {
        assert!(j.record(&health(n.wrapping_add(100))).is_err());
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "sealed refusals rewrote");
}

/// Unknown/mixed format bytes and short files are refused before lock sidecar creation.
#[test]
fn probe_header_variants_refused_without_side_effects() {
    for (b18, b19) in [(1u8, 2u8), (2, 1), (2, 2), (0, 1)] {
        let (d, path) = setup();
        std::fs::remove_file(d.path().join("health.lock")).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[18] = b18;
        bytes[19] = b19;
        std::fs::write(&path, &bytes).unwrap();
        let before = listing(d.path());
        let r = Journal::open(&path);
        eprintln!("PROBE header {b18},{b19}: refused={}", r.is_err());
        assert!(r.is_err());
        assert_eq!(listing(d.path()), before);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    let (d, path) = setup();
    std::fs::remove_file(d.path().join("health.lock")).unwrap();
    std::fs::write(&path, b"SQLite format 3\0").unwrap();
    let before = listing(d.path());
    let r = Journal::open(&path);
    eprintln!("PROBE short file: refused={} err={:?}", r.is_err(), r.as_ref().err().map(|e| e.to_string()));
    assert!(r.is_err());
    assert_eq!(listing(d.path()), before);
}

/// First non-session exhaustion reason must not be overwritten by a later failure.
#[test]
fn probe_attempt_limit_reason_survives_later_page_full() {
    let (_d, path) = setup();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99999) INSERT INTO attempts SELECT printf('%064x',i),0,0,0,0,'{}' FROM n").unwrap();
    drop(c);
    let mut j = Journal::open(&path).unwrap();
    assert!(j.record(&health(7)).is_err());
    drop(j);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA max_page_count=8192").unwrap();
    let mut i = 0u64;
    for size in [3000usize, 400, 40] {
        loop {
            i += 1;
            if c.execute("INSERT INTO sessions VALUES(?,0,0,1)", [format!("{i:032x}{}", "x".repeat(size))]).is_err() {
                break;
            }
        }
    }
    drop(c);
    let mut j = Journal::open(&path).unwrap();
    let w = ops::WorkerStatus { sampled_at: ops::now(), state: "x".repeat(20000), queue: None, nonempty_since: None, last_ack_at: None, last_ack_position: None, consecutive_failures: 0, retry_seconds: 0, telemetry_failures: 0 };
    let r = j.save_worker(&w);
    let s = serde_json::to_value(j.snapshot().unwrap()).unwrap();
    eprintln!("PROBE attempt_limit then worker full: save={:?} reason={}", r.as_ref().map_err(|e| e.to_string()), s["journal"]["exhaustion_reason"]);
    assert!(r.is_err());
    assert_eq!(s["journal"]["exhaustion_reason"], "attempt_limit", "first sealing reason was overwritten");
}
