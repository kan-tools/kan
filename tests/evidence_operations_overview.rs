#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::Journal,
    evidence_operations_collection::{
        self as collection,
        overview::{self, Boundary, Failure, Limits, Manager},
    },
    evidence_spool::Spool,
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
}
fn health(n: u64) -> Health {
    Health {
        attempt: format!("{:064x}", 1),
        observer: Observer::Collector,
        observed: n,
        locally_queued: n - 1,
        unconfirmed: 1,
        recording_gap: true,
        remote_acknowledged: false,
        status: Some(200),
        outcome: Some(Outcome::Completed),
    }
}
fn sql(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
fn session(path: &Path, dropped: i64, clean: bool) {
    sql(path)
        .execute(
            "INSERT INTO sessions VALUES('same-session',1,?,?)",
            rusqlite::params![dropped, clean],
        )
        .unwrap();
}
fn digest(path: &Path) -> String {
    kan::evidence_service::hex(&Sha256::digest(std::fs::read(path).unwrap()))
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("health");
        let root = dir.path().join("collection");
        let spool = dir.path().join("queue");
        let id = Identity::generate();
        Spool::create(
            &spool,
            &format!("{:064x}", 3),
            id.did().as_str(),
            id.did().as_str(),
            1 << 20,
        )
        .unwrap();
        Journal::create(&source, &spool)
            .unwrap()
            .record(&health(1))
            .unwrap();
        session(&source, 2, false);
        collection::adopt(&source, &root).unwrap();
        let f = Self {
            _dir: dir,
            root,
            source,
        };
        Journal::open(&f.root).unwrap().record(&health(2)).unwrap();
        session(&f.active(), 5, false);
        collection::rotate(&f.root).unwrap();
        Journal::open(&f.root).unwrap().record(&health(3)).unwrap();
        session(&f.active(), 8, true);
        f
    }
    fn generations(&self) -> collection::Generations {
        collection::generations(&self.root, 0, 100).unwrap()
    }
    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("generation-{id}.sqlite"))
    }
    fn active(&self) -> PathBuf {
        self.path(&self.generations().active)
    }
    fn build(&self) -> overview::Overview {
        overview::build(&self.root, &AtomicBool::new(false), Limits::default()).unwrap()
    }
    fn hashes(&self) -> Vec<(String, String)> {
        let mut paths = vec![self.source.clone(), self.root.join("manifest.json")];
        paths.extend(
            self.generations()
                .generations
                .iter()
                .map(|g| self.path(&g.id)),
        );
        paths
            .into_iter()
            .map(|p| (p.to_string_lossy().into_owned(), digest(&p)))
            .collect()
    }
    fn reseal(&self, index: usize) {
        let path = self.root.join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let id = m["generations"][index]["id"].as_str().unwrap();
        m["generations"][index]["sealed_sha256"] = digest(&self.path(id)).into();
        std::fs::write(path, serde_json::to_vec(&m).unwrap()).unwrap();
    }
}
#[test]
fn cumulative_rows_are_deduplicated_without_rewriting_sources() {
    let f = Fixture::new();
    let before = f.hashes();
    let a = f.build();
    assert_eq!(a.sources.len(), 3);
    assert_eq!(a.totals.attempts, 1);
    assert_eq!(a.totals.observed, 3);
    assert_eq!(a.totals.locally_queued, 2);
    assert_eq!(a.totals.unconfirmed, 1);
    assert_eq!(a.totals.attempts_with_gaps, 1);
    assert_eq!(a.totals.sessions, 1);
    assert_eq!(a.totals.telemetry_dropped_lower_bound, 8);
    assert_eq!(a.totals.unclosed_sessions, 0);
    assert_eq!(a.coverage, "observations-only");
    assert_eq!(a.capture_completeness, "unknown");
    assert_eq!(before, f.hashes());
    assert_eq!(
        a.sources
            .iter()
            .map(|s| &s.snapshot.digest)
            .collect::<Vec<_>>(),
        f.build()
            .sources
            .iter()
            .map(|s| &s.snapshot.digest)
            .collect::<Vec<_>>()
    );
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(json["totals"]["observed"], "3");
}

/// Regression derived from the cold review's PO1: parsing a large active
/// rollback journal must not hold its SQLite reader lock across every row.
#[test]
fn active_snapshot_parsing_does_not_exclude_health_writes() {
    let f = Fixture::new();
    let mut conn = sql(&f.active());
    let tx = conn.transaction().unwrap();
    {
        let mut insert = tx
            .prepare("INSERT INTO attempts VALUES(?,?,?,?,?,?)")
            .unwrap();
        for n in 1000..41000u64 {
            let mut h = health(3);
            h.attempt = format!("{n:064x}");
            insert
                .execute(rusqlite::params![
                    h.attempt,
                    1,
                    3,
                    2,
                    1,
                    serde_json::to_string(&h).unwrap()
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    drop(conn);
    let mut writer = Journal::open(&f.root).unwrap();
    let root = f.root.clone();
    let (started, ready) = mpsc::sync_channel(1);
    let builder = std::thread::spawn(move || {
        overview::build_observed(
            &root,
            &AtomicBool::new(false),
            Limits::default(),
            &mut |b| {
                if b == Boundary::MembershipPinned {
                    started.send(()).unwrap();
                }
                Ok(())
            },
        )
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut failures = Vec::new();
    for n in 500000..500100u64 {
        let mut h = health(1);
        h.attempt = format!("{n:064x}");
        if let Err(e) = writer.record(&h) {
            failures.push(e.to_string());
        }
    }
    let sampled = builder.join().unwrap().unwrap();
    assert!(sampled.totals.attempts >= 40001);
    assert!(
        failures.is_empty(),
        "overview row scan excluded the health writer: {failures:?}"
    );
}

#[test]
fn sealed_change_after_row_scan_is_not_published() {
    let f = Fixture::new();
    let sealed = f.path(&f.generations().generations[0].id);
    let mut scans = 0;
    let result = overview::build_observed(
        &f.root,
        &AtomicBool::new(false),
        Limits::default(),
        &mut |b| {
            if b == Boundary::SourceRowsRead {
                scans += 1;
                if scans == 2 {
                    sql(&sealed)
                        .execute("UPDATE sessions SET updated=updated+1", [])
                        .unwrap();
                }
            }
            Ok(())
        },
    );
    assert_eq!(scans, 2, "must reach the post-read sealed hash fence");
    assert!(
        result.is_err(),
        "a changed sealed source cannot be published from its earlier hash"
    );
}

#[test]
fn ignored_sqlite_sidecars_and_invalid_unique_health_rows_refuse() {
    let f = Fixture::new();
    let sealed = f.path(&f.generations().generations[0].id);
    std::fs::write(format!("{}-wal", sealed.display()), []).unwrap();
    assert!(
        overview::build(&f.root, &AtomicBool::new(false), Limits::default()).is_err(),
        "even an empty sealed WAL is outside the declared source"
    );
    for mutation in ["ack", "gap", "arithmetic"] {
        let f = Fixture::new();
        let mut h = health(3);
        h.attempt = format!("{:064x}", 99);
        match mutation {
            "ack" => h.remote_acknowledged = true,
            "gap" => h.recording_gap = false,
            _ => h.observed = 4,
        }
        sql(&f.active())
            .execute(
                "INSERT INTO attempts VALUES(?,?,?,?,?,?)",
                rusqlite::params![
                    h.attempt,
                    1,
                    h.observed,
                    h.locally_queued,
                    h.unconfirmed,
                    serde_json::to_string(&h).unwrap()
                ],
            )
            .unwrap();
        assert!(
            overview::build(&f.root, &AtomicBool::new(false), Limits::default()).is_err(),
            "unique malformed health row: {mutation}"
        );
    }
}

#[test]
fn historical_worker_is_hashed_but_not_promoted_to_current_health() {
    let f = Fixture::new();
    let sealed = f.path(&f.generations().generations[0].id);
    let mut worker = kan::evidence_operations::WorkerStatus {
        sampled_at: 1,
        state: "idle".into(),
        queue: None,
        nonempty_since: None,
        last_ack_at: None,
        last_ack_position: None,
        consecutive_failures: 99,
        retry_seconds: 0,
        telemetry_failures: 99,
    };
    sql(&sealed)
        .execute(
            "INSERT INTO worker VALUES(1,?)",
            [serde_json::to_string(&worker).unwrap()],
        )
        .unwrap();
    f.reseal(0);
    worker.consecutive_failures = 2;
    worker.telemetry_failures = 2;
    Journal::open(&f.root)
        .unwrap()
        .save_worker(&worker)
        .unwrap();
    let first = f.build();
    assert!(first.sources[0].snapshot.worker.is_none());
    assert_eq!(
        first
            .sources
            .last()
            .unwrap()
            .snapshot
            .worker
            .as_ref()
            .unwrap()
            .consecutive_failures,
        2
    );
    worker.consecutive_failures = 100;
    sql(&sealed)
        .execute(
            "UPDATE worker SET body=?",
            [serde_json::to_string(&worker).unwrap()],
        )
        .unwrap();
    f.reseal(0);
    assert_ne!(
        first.sources[0].snapshot.digest,
        f.build().sources[0].snapshot.digest,
        "omitted historical worker still belongs to its snapshot digest"
    );
}
#[test]
fn intermediate_regressions_conflicting_observers_and_terminals_refuse_publication() {
    for defect in [
        "regression",
        "observer",
        "status",
        "outcome",
        "session-drop",
        "session-reopen",
        "derived",
    ] {
        let f = Fixture::new();
        let middle = f.path(&f.generations().generations[1].id);
        let conn = sql(&middle);
        match defect {
            "session-drop" => {
                conn.execute("UPDATE sessions SET dropped=1", []).unwrap();
            }
            "session-reopen" => {
                sql(&f.path(&f.generations().generations[0].id))
                    .execute("UPDATE sessions SET clean=1", [])
                    .unwrap();
                f.reseal(0);
            }
            "derived" => {
                conn.execute("UPDATE attempts SET observed=99", []).unwrap();
            }
            _ => {
                let mut h = health(2);
                match defect {
                    "regression" => {
                        h.locally_queued = 0;
                        h.unconfirmed = 0;
                        h.observed = 0;
                        h.recording_gap = false;
                    }
                    "observer" => h.observer = Observer::Gateway,
                    "status" => h.status = Some(500),
                    "outcome" => h.outcome = Some(Outcome::OutcomeUnknown),
                    _ => unreachable!(),
                };
                conn.execute(
                    "UPDATE attempts SET observed=?,queued=?,unconfirmed=?,body=?",
                    rusqlite::params![
                        h.observed as i64,
                        h.locally_queued as i64,
                        h.unconfirmed as i64,
                        serde_json::to_string(&h).unwrap()
                    ],
                )
                .unwrap();
            }
        }
        drop(conn);
        f.reseal(1);
        assert!(
            overview::build(&f.root, &AtomicBool::new(false), Limits::default()).is_err(),
            "accepted {defect}"
        );
    }
}
#[test]
fn changed_missing_sources_binding_and_membership_fail_visibly() {
    for defect in ["hash", "missing", "binding", "membership"] {
        let f = Fixture::new();
        let first = f.path(&f.generations().generations[0].id);
        match defect {
            "hash" => {
                sql(&first)
                    .execute("UPDATE sessions SET dropped=3", [])
                    .unwrap();
            }
            "missing" => std::fs::remove_file(&first).unwrap(),
            "binding" => {
                sql(&first)
                    .execute("UPDATE binding SET scope='foreign'", [])
                    .unwrap();
                f.reseal(0);
            }
            "membership" => {}
            _ => unreachable!(),
        }
        let result = overview::build_observed(
            &f.root,
            &AtomicBool::new(false),
            Limits::default(),
            &mut |phase| {
                if defect == "membership" && phase == Boundary::ActiveRead {
                    let p = f.root.join("manifest.json");
                    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&p)?)?;
                    m["generations"].as_array_mut().unwrap().swap(0, 1);
                    std::fs::write(p, serde_json::to_vec(&m)?)?;
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "accepted {defect}");
    }
}
#[test]
fn pinned_active_snapshot_releases_sqlite_before_history_and_blocks_rotation() {
    let f = Fixture::new();
    let root = f.root.clone();
    let (entered, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        overview::build_observed(
            &root,
            &AtomicBool::new(false),
            Limits::default(),
            &mut |phase| {
                if phase == Boundary::ActiveRead {
                    entered.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                Ok(())
            },
        )
        .unwrap()
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    Journal::open(&f.root).unwrap().record(&health(4)).unwrap();
    assert!(
        collection::rotate(&f.root).is_err(),
        "refresh must hold collection membership lock"
    );
    release.send(()).unwrap();
    let a = worker.join().unwrap();
    assert_eq!(a.totals.observed, 3);
    assert_eq!(f.build().totals.observed, 4);
    collection::rotate(&f.root).unwrap();
    assert_ne!(a.active, f.generations().active);
}
#[test]
fn bounds_cancellation_and_checked_sum_never_publish_partial_totals() {
    let f = Fixture::new();
    for limits in [
        Limits {
            attempts: 0,
            ..Limits::default()
        },
        Limits {
            sessions: 0,
            ..Limits::default()
        },
        Limits {
            bytes: 16 * 1024 * 1024,
            ..Limits::default()
        },
    ] {
        let error = overview::build(&f.root, &AtomicBool::new(false), limits).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Failure>(),
            Some(Failure::Capacity(_))
        ));
    }
    let flag = AtomicBool::new(false);
    let error = overview::build_observed(&f.root, &flag, Limits::default(), &mut |phase| {
        if phase == Boundary::GenerationRead {
            flag.store(true, Ordering::Relaxed);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<Failure>(),
        Some(Failure::Cancelled)
    ));
    let mut journal = Journal::open(&f.root).unwrap();
    for n in 2..=4 {
        let mut h = health(1);
        h.attempt = format!("{n:064x}");
        h.observed = i64::MAX as u64;
        h.locally_queued = h.observed;
        h.unconfirmed = 0;
        h.recording_gap = false;
        journal.record(&h).unwrap();
    }
    drop(journal);
    let error = overview::build(&f.root, &AtomicBool::new(false), Limits::default()).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<Failure>(),
        Some(Failure::Overflow)
    ));
}
fn finish(manager: &Manager) -> overview::Published {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let s = manager.status();
        if !["building", "cancelling"].contains(&s.state) {
            return s;
        }
        assert!(Instant::now() < deadline, "overview did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn published_polling_is_memory_only_and_cancel_preserves_prior_sample() {
    let f = Fixture::new();
    let manager = Manager::new();
    assert_eq!(manager.status().state, "unavailable");
    manager.refresh(f.root.clone()).unwrap();
    let first = finish(&manager);
    assert_eq!(first.state, "completed");
    let (entered, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let started = manager
        .refresh_observed(f.root.clone(), Limits::default(), move |phase| {
            if phase == Boundary::ActiveRead {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            Ok(())
        })
        .unwrap();
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        manager.refresh(f.root.clone()).unwrap().job,
        started.job,
        "only one admitted build"
    );
    // Polling still works with its source unavailable: it reads only publication memory.
    let manifest = f.root.join("manifest.json");
    let saved = std::fs::read(&manifest).unwrap();
    std::fs::write(&manifest, b"broken").unwrap();
    for _ in 0..100 {
        let status = manager.status();
        assert_eq!(status.state, "building");
        assert_eq!(status.last_job, first.last_job);
    }
    std::fs::write(&manifest, saved).unwrap();
    assert_eq!(manager.cancel().state, "cancelling");
    release.send(()).unwrap();
    let cancelled = finish(&manager);
    assert_eq!(cancelled.state, "cancelled");
    assert_eq!(cancelled.last_job, first.last_job);
    manager
        .refresh_observed(
            f.root.clone(),
            Limits {
                attempts: 0,
                ..Limits::default()
            },
            |_| Ok(()),
        )
        .unwrap();
    let limited = finish(&manager);
    assert_eq!(limited.state, "capacity-limited");
    assert_eq!(limited.last_job, first.last_job);
    std::fs::write(&manifest, b"broken").unwrap();
    manager.refresh(f.root.clone()).unwrap();
    let failed = finish(&manager);
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.last_job, first.last_job);
    drop(manager);
    assert!(
        Manager::new().status().last.is_none(),
        "restart must not invent a persisted projection"
    );
}
#[test]
fn real_cli_returns_same_typed_totals() {
    let f = Fixture::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("ops-overview")
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["totals"]["observed"], "3");
    assert_eq!(result["sources"].as_array().unwrap().len(), 3);
}
#[tokio::test]
async fn dashboard_overview_requires_auth_and_cannot_mutate_owner_history() {
    let f = Fixture::new();
    let before = f.hashes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let root = f.root.clone();
    let token = "synthetic-overview-token-more-than-32";
    let server =
        tokio::spawn(
            async move { kan::evidence_dashboard::serve(listener, token.into(), root).await },
        );
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}");
    assert_eq!(
        client
            .get(format!("{url}/api/overview"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{url}/api/overview/refresh"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        client
            .post(format!("{url}/api/overview/refresh"))
            .bearer_auth(token)
            .header("origin", "http://foreign.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{url}/api/overview/refresh"))
            .bearer_auth(token)
            .body("rotate")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let initial: serde_json::Value = client
        .get(format!("{url}/api/overview"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial["state"], "unavailable");
    assert!(client
        .post(format!("{url}/api/overview/refresh"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let s: serde_json::Value = client
            .get(format!("{url}/api/overview"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if s["state"] == "completed" {
            assert_eq!(s["last"]["totals"]["observed"], "3");
            break;
        }
        assert!(Instant::now() < deadline, "{s}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(before, f.hashes());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
#[ignore = "manual synthetic browser fixture; explicit output path required"]
async fn overview_browser_fixture() {
    let output =
        std::env::var_os("KAN_OVERVIEW_FIXTURE_INFO").expect("explicit fixture output path");
    let fixture = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token = "synthetic-browser-overview-token-32-plus";
    std::fs::write(output,serde_json::to_vec(&serde_json::json!({"url":format!("http://{}",listener.local_addr().unwrap()),"token":token})).unwrap()).unwrap();
    tokio::select! {r=kan::evidence_dashboard::serve(listener,token.into(),fixture.root.clone())=>r.unwrap(),_=tokio::signal::ctrl_c()=>{}}
}
