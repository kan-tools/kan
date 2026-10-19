#![cfg(feature = "v2-crypto")]
//! Independent reviewer probes for the bounded collection overview (67c1263).
//! Synthetic fixtures only. Temporarily copied into tests/ to run; removed after.
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
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

fn h(attempt: u64, n: u64) -> Health {
    Health {
        attempt: format!("{attempt:064x}"),
        observer: Observer::Collector,
        observed: n,
        locally_queued: n.saturating_sub(1),
        unconfirmed: u64::from(n > 0),
        recording_gap: n > 0,
        remote_acknowledged: false,
        status: Some(200),
        outcome: Some(Outcome::Completed),
    }
}
fn sql(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
fn sha(path: &Path) -> String {
    kan::evidence_service::hex(&Sha256::digest(std::fs::read(path).unwrap()))
}
struct Fx {
    _dir: tempfile::TempDir,
    root: PathBuf,
}
impl Fx {
    /// Three generations: g0 sealed (attempt 1 obs 1, session s dropped 2),
    /// g1 sealed (attempt 1 obs 2, session s 5), active (attempt 1 obs 3, s 8 clean).
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
            .record(&h(1, 1))
            .unwrap();
        sql(&source)
            .execute("INSERT INTO sessions VALUES('s',1,2,0)", [])
            .unwrap();
        collection::adopt(&source, &root).unwrap();
        let f = Self { _dir: dir, root };
        Journal::open(&f.root).unwrap().record(&h(1, 2)).unwrap();
        sql(&f.active())
            .execute("INSERT INTO sessions VALUES('s',1,5,0)", [])
            .unwrap();
        collection::rotate(&f.root).unwrap();
        Journal::open(&f.root).unwrap().record(&h(1, 3)).unwrap();
        sql(&f.active())
            .execute("INSERT INTO sessions VALUES('s',1,8,1)", [])
            .unwrap();
        f
    }
    fn gens(&self) -> collection::Generations {
        collection::generations(&self.root, 0, 100).unwrap()
    }
    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("generation-{id}.sqlite"))
    }
    fn active(&self) -> PathBuf {
        self.path(&self.gens().active)
    }
    fn sealed(&self, i: usize) -> PathBuf {
        self.path(&self.gens().generations[i].id)
    }
    fn reseal(&self, index: usize) {
        let path = self.root.join("manifest.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let id = m["generations"][index]["id"].as_str().unwrap().to_owned();
        m["generations"][index]["sealed_sha256"] = sha(&self.path(&id)).into();
        std::fs::write(path, serde_json::to_vec(&m).unwrap()).unwrap();
    }
    /// Directory state: name -> (len, mode, mtime, sha256). Detects creation of
    /// sidecars/lock files and any byte or metadata change.
    fn tree(&self) -> BTreeMap<String, (u64, u32, i128, String)> {
        use std::os::unix::fs::PermissionsExt;
        let mut out = BTreeMap::new();
        for e in std::fs::read_dir(&self.root).unwrap() {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            let mt = m
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as i128;
            out.insert(
                e.file_name().to_string_lossy().into_owned(),
                (m.len(), m.permissions().mode(), mt, sha(&e.path())),
            );
        }
        out
    }
    fn build(&self) -> Result<overview::Overview, Box<dyn std::error::Error + Send + Sync>> {
        overview::build(&self.root, &AtomicBool::new(false), Limits::default())
    }
    /// Bulk-insert `n` distinct valid attempts into the active generation.
    fn bulk_active(&self, start: u64, n: u64) {
        let mut c = sql(&self.active());
        let tx = c.transaction().unwrap();
        {
            let mut ins = tx
                .prepare("INSERT INTO attempts VALUES(?,?,?,?,?,?)")
                .unwrap();
            for i in start..start + n {
                let x = h(i, 4);
                ins.execute(rusqlite::params![
                    x.attempt,
                    1i64,
                    4i64,
                    3i64,
                    1i64,
                    serde_json::to_string(&x).unwrap()
                ])
                .unwrap();
            }
        }
        tx.commit().unwrap();
    }
}
fn class(e: &(dyn std::error::Error + Send + Sync + 'static)) -> &'static str {
    match e.downcast_ref::<Failure>() {
        Some(Failure::Conflict) => "conflict",
        Some(Failure::Overflow) => "overflow",
        Some(Failure::Cancelled) => "cancelled",
        Some(Failure::Capacity(_)) => "capacity",
        None => "invalid",
    }
}

/// PO1: live health writes DURING the active-generation scan. The design says
/// "capture callbacks still never wait on this process" and the runbook says
/// "Active health writers continue". The rollback-journal read transaction is
/// held for the whole active scan; the writer's busy timeout is 100 ms.
#[test]
fn po1_health_writer_commits_while_large_active_scan_runs() {
    let f = Fx::new();
    f.bulk_active(1_000, 60_000);
    let size = std::fs::metadata(f.active()).unwrap().len();
    eprintln!("PO1 active journal bytes={size}");
    // Control: the same writer loop without a concurrent build never fails.
    let mut writer = Journal::open(&f.root).unwrap();
    let mut control_errors = 0;
    for i in 0..20 {
        if writer.record(&h(500_000 + i, 1)).is_err() {
            control_errors += 1;
        }
    }
    assert_eq!(control_errors, 0, "control writer failed without a build");

    let phase = Arc::new(AtomicU8::new(0)); // 0 before, 1 scanning active, 2 after
    let p = phase.clone();
    let root = f.root.clone();
    let started = Instant::now();
    let builder = std::thread::spawn(move || {
        p.store(1, Ordering::SeqCst);
        let t = Instant::now();
        let mut active_ms = 0u128;
        let r = overview::build_observed(
            &root,
            &AtomicBool::new(false),
            Limits::default(),
            &mut |b| {
                if b == Boundary::ActiveRead {
                    active_ms = t.elapsed().as_millis();
                    p.store(2, Ordering::SeqCst);
                }
                Ok(())
            },
        );
        p.store(2, Ordering::SeqCst);
        (r.map(|o| o.totals.attempts), active_ms)
    });
    let (mut during_ok, mut during_err, mut max_ms) = (0, 0, 0u128);
    let mut messages = std::collections::BTreeSet::new();
    let mut i = 600_000u64;
    while phase.load(Ordering::SeqCst) < 2 && started.elapsed() < Duration::from_secs(60) {
        let t = Instant::now();
        let r = writer.record(&h(i, 1));
        i += 1;
        let ms = t.elapsed().as_millis();
        if phase.load(Ordering::SeqCst) == 1 {
            max_ms = max_ms.max(ms);
            match r {
                Ok(()) => during_ok += 1,
                Err(e) => {
                    during_err += 1;
                    messages.insert(e.to_string());
                }
            }
        }
    }
    let (built, active_ms) = builder.join().unwrap();
    eprintln!(
        "PO1 build={built:?} active_scan_ms={active_ms} writes_during_scan ok={during_ok} err={during_err} max_write_ms={max_ms} errors={messages:?}"
    );
    assert!(built.is_ok(), "build itself failed: {built:?}");
    assert_eq!(
        during_err, 0,
        "health writer lost {during_err} observations while the overview held the active read transaction ({active_ms} ms)"
    );
}

/// PO2: a build (direct, Manager, and CLI) creates, deletes or changes no file
/// in the collection directory, including -journal/-shm/.lock sidecars and mtimes.
#[test]
fn po2_build_changes_no_collection_file_or_metadata() {
    let f = Fx::new();
    let before = f.tree();
    let a = f.build().unwrap();
    assert_eq!(a.totals.attempts, 1);
    let m = Manager::new();
    m.refresh(f.root.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while ["building", "cancelling"].contains(&m.status().state) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(m.status().state, "completed");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("ops-overview")
        .arg(&f.root)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(before, f.tree(), "collection directory changed by overview");
}

/// PO3: a missing generation lifetime-lock file refuses and is NOT created by
/// the read projection (REQ-5: no new files).
#[test]
fn po3_missing_generation_lock_refuses_without_creating_it() {
    let f = Fx::new();
    let mut lock = f.sealed(0).into_os_string();
    lock.push(".lock");
    let lock = PathBuf::from(lock);
    std::fs::remove_file(&lock).unwrap();
    let r = f.build();
    assert!(!lock.exists(), "overview created a generation lock file");
    assert!(r.is_err(), "overview accepted a generation without its lock");
}

/// PO4: hostile rows in the ACTIVE generation (no sealed hash protects it) are
/// refused, never quietly filtered or summed.
#[test]
fn po4_hostile_active_rows_refuse_publication() {
    let cases: &[(&str, &str)] = &[
        // Consistent summary columns, but the whole observation is invalid.
        ("arith", "UPDATE attempts SET observed=5,queued=1,unconfirmed=1,body=json_set(body,'$.observed',5,'$.locally_queued',1,'$.unconfirmed',1)"),
        ("acked", "UPDATE attempts SET body=json_set(body,'$.remote_acknowledged',json('true'))"),
        ("unknown-field", "UPDATE attempts SET body=json_set(body,'$.extra',1)"),
        ("id-mismatch", "UPDATE attempts SET body=json_set(body,'$.attempt','ff'||substr(attempt,3))"),
        ("blob-body", "UPDATE attempts SET body=CAST(body AS BLOB)"),
        ("negative-updated", "UPDATE attempts SET updated=-1"),
        ("session-empty", "UPDATE sessions SET id=''"),
        ("session-clean-2", "UPDATE sessions SET clean=2"),
        ("session-negative", "UPDATE sessions SET dropped=-1"),
        ("session-long", "UPDATE sessions SET id=hex(zeroblob(2049))"),
        ("worker-malformed", "INSERT INTO worker VALUES(1,'{not json')"),
        ("binding-foreign", "UPDATE binding SET scope='foreign'"),
    ];
    for (name, stmt) in cases {
        let f = Fx::new();
        sql(&f.active()).execute(stmt, []).unwrap();
        let r = f.build();
        assert!(r.is_err(), "accepted hostile active row: {name}");
        eprintln!("PO4 {name}: {}", class(r.unwrap_err().as_ref()));
    }
}

/// PO5: precise failure classes (the author's matrix asserts only is_err).
#[test]
fn po5_conflicts_are_classified_and_manager_labels_them() {
    for (name, expect) in [
        ("regression", "conflict"),
        ("observer", "conflict"),
        ("outcome", "conflict"),
        ("session-reopen", "conflict"),
        ("session-drop", "conflict"),
    ] {
        let f = Fx::new();
        let mid = f.sealed(1);
        match name {
            "regression" => {
                let x = h(1, 0);
                sql(&mid).execute("UPDATE attempts SET observed=0,queued=0,unconfirmed=0,body=?", [serde_json::to_string(&x).unwrap()]).unwrap();
            }
            "observer" => {
                let mut x = h(1, 2);
                x.observer = Observer::Gateway;
                sql(&mid).execute("UPDATE attempts SET body=?", [serde_json::to_string(&x).unwrap()]).unwrap();
            }
            "outcome" => {
                let mut x = h(1, 2);
                x.outcome = Some(Outcome::OutcomeUnknown);
                sql(&mid).execute("UPDATE attempts SET body=?", [serde_json::to_string(&x).unwrap()]).unwrap();
            }
            "session-reopen" => {
                // Close the session in g0 so that g1's unclean row reopens it.
                sql(&f.sealed(0)).execute("UPDATE sessions SET clean=1", []).unwrap();
                f.reseal(0);
            }
            "session-drop" => {
                sql(&mid).execute("UPDATE sessions SET dropped=1", []).unwrap();
            }
            _ => unreachable!(),
        }
        f.reseal(1);
        let e = f.build().expect_err(name);
        assert_eq!(class(e.as_ref()), expect, "{name}");
        let m = Manager::new();
        m.refresh(f.root.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while ["building", "cancelling"].contains(&m.status().state) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let s = m.status();
        assert_eq!(s.state, "failed", "{name}");
        assert_eq!(s.reason.as_deref(), Some("conflicting cumulative observations"), "{name}");
        assert!(s.last.is_none(), "{name}: published a total");
    }
}

/// PO6: whole-row selection, not component maxima: a later row that raises one
/// counter while lowering another refuses rather than synthesizing a maximum.
#[test]
fn po6_incomparable_rows_refuse_instead_of_componentwise_max() {
    let f = Fx::new();
    // g1: observed 2 = queued 1 + unconfirmed 1. Active: observed 3 = queued 3 + unconfirmed 0.
    let mut x = h(1, 3);
    x.locally_queued = 3;
    x.unconfirmed = 0;
    x.recording_gap = false;
    sql(&f.active())
        .execute(
            "UPDATE attempts SET observed=3,queued=3,unconfirmed=0,body=?",
            [serde_json::to_string(&x).unwrap()],
        )
        .unwrap();
    let e = f.build().unwrap_err();
    assert_eq!(class(e.as_ref()), "conflict");
}

/// PO7: exact u64 totals above i64 / 2^53 serialize as decimal strings.
#[test]
fn po7_u64_totals_beyond_i64_are_exact_decimal_strings() {
    let f = Fx::new();
    let mut j = Journal::open(&f.root).unwrap();
    for n in 2..=3u64 {
        let mut x = h(n, 0);
        x.observed = i64::MAX as u64 - if n == 3 { 10 } else { 0 };
        x.locally_queued = x.observed;
        x.unconfirmed = 0;
        x.recording_gap = false;
        j.record(&x).unwrap();
    }
    drop(j);
    let o = f.build().unwrap();
    let v = serde_json::to_value(&o).unwrap();
    // (2^63-1) + (2^63-11) + 3 = 2^64 - 9: above i64::MAX and 2^53, below u64::MAX.
    assert_eq!(v["totals"]["observed"], "18446744073709551607");
}

/// PO8: one-build admission across cancel/refresh: refresh while a cancelled
/// build is still running returns the same job and never starts a second build.
#[test]
fn po8_cancel_then_refresh_does_not_start_concurrent_build() {
    let f = Fx::new();
    let m = Manager::new();
    let (entered, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel::<()>();
    let started = m
        .refresh_observed(f.root.clone(), Limits::default(), move |b| {
            if b == Boundary::ActiveRead {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            Ok(())
        })
        .unwrap();
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(m.cancel().state, "cancelling");
    let again = m.refresh(f.root.clone()).unwrap();
    assert_eq!(again.job, started.job, "second build admitted while first still running");
    assert_eq!(again.state, "cancelling");
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while ["building", "cancelling"].contains(&m.status().state) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(m.status().state, "cancelled");
    assert!(m.status().last.is_none());
    let next = m.refresh(f.root.clone()).unwrap();
    assert_eq!(next.job, started.job + 1);
}

fn raw(addr: std::net::SocketAddr, request: String) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, text)
}

/// PO9: hostile HTTP framing/method/auth against the overview routes.
#[test]
fn po9_dashboard_overview_routes_refuse_hostile_requests() {
    let f = Fx::new();
    let before = f.tree();
    let token = "reviewer-synthetic-token-0123456789abcdef";
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let root = f.root.clone();
    let server = rt.spawn(async move {
        kan::evidence_dashboard::serve(listener, token.into(), root).await
    });
    let host = addr.to_string();
    let auth = format!("Authorization: Bearer {token}\r\n");
    let req = |line: &str, extra: &str| {
        format!("{line} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n")
    };
    let cases: Vec<(&str, String, u16)> = vec![
        ("no-auth-get", req("GET /api/overview", ""), 401),
        ("no-auth-post-body", req("POST /api/overview/refresh", "Content-Length: 6\r\n").replace("\r\n\r\n", "\r\n\r\nrotate"), 401),
        ("lowercase-bearer", req("GET /api/overview", &format!("Authorization: bearer {token}\r\n")), 401),
        ("double-auth", req("GET /api/overview", &format!("{auth}{auth}")), 401),
        ("wrong-host", format!("GET /api/overview HTTP/1.1\r\nHost: localhost:{}\r\n{auth}Connection: close\r\n\r\n", addr.port()), 403),
        ("foreign-origin", req("POST /api/overview/refresh", &format!("{auth}Origin: http://evil.example\r\nContent-Length: 0\r\n")), 403),
        ("post-status-route", req("POST /api/overview", &format!("{auth}Content-Length: 0\r\n")), 405),
        ("put-refresh", req("PUT /api/overview/refresh", &format!("{auth}Content-Length: 0\r\n")), 405),
        ("query-refresh", req("POST /api/overview/refresh?rotate=1", &format!("{auth}Content-Length: 0\r\n")), 405),
        ("slash-refresh", req("POST /api/overview/refresh/", &format!("{auth}Content-Length: 0\r\n")), 405),
        ("get-cancel", req("GET /api/overview/cancel", &auth), 405),
        ("chunked-empty", req("POST /api/overview/refresh", &format!("{auth}Transfer-Encoding: chunked\r\n")).replace("\r\n\r\n", "\r\n\r\n0\r\n\r\n"), 400),
        ("body", req("POST /api/overview/refresh", &format!("{auth}Content-Length: 6\r\n")).replace("\r\n\r\n", "\r\n\r\nrotate"), 400),
        ("cancel-body", req("POST /api/overview/cancel", &format!("{auth}Content-Length: 2\r\n")).replace("\r\n\r\n", "\r\n\r\n{}"), 400),
        ("status-ok", req("GET /api/overview", &auth), 200),
    ];
    let mut failures = Vec::new();
    for (name, request, want) in &cases {
        let (got, text) = raw(addr, request.clone());
        eprintln!("PO9 {name}: {got}");
        if got != *want {
            failures.push(format!("{name}: want {want} got {got}: {}", text.lines().next().unwrap_or("")));
        }
    }
    // A valid refresh, then poll to completion with decimal-string totals.
    let (code, _) = raw(addr, req("POST /api/overview/refresh", &format!("{auth}Content-Length: 0\r\n")));
    assert_eq!(code, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    let body = loop {
        let (_, text) = raw(addr, req("GET /api/overview", &auth));
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        if v["state"] == "completed" {
            break v;
        }
        assert!(Instant::now() < deadline, "{body}");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(body["last"]["totals"]["observed"], "3");
    assert_eq!(body["last"]["totals"]["telemetry_dropped_lower_bound"], "8");
    assert_eq!(body["last"]["capture_completeness"], "unknown");
    // Published status survives removal of the manifest: memory-only polling.
    let manifest = f.root.join("manifest.json");
    let saved = std::fs::read(&manifest).unwrap();
    std::fs::remove_file(&manifest).unwrap();
    let (code, text) = raw(addr, req("GET /api/overview", &auth));
    std::fs::write(&manifest, &saved).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(code, 200, "{text}");
    assert!(text.contains("\"state\":\"completed\""));
    server.abort();
    let _ = rt.block_on(server);
    rt.shutdown_timeout(Duration::from_secs(5));
    let mut after = f.tree();
    let mut b = before.clone();
    // The manifest was rewritten byte-identically by this probe; compare content only.
    for t in [&mut after, &mut b] {
        if let Some(e) = t.get_mut("manifest.json") {
            e.2 = 0;
        }
    }
    assert_eq!(b, after, "dashboard overview changed collection files");
    assert!(failures.is_empty(), "{failures:#?}");
}

/// PO10: telemetry lower-bound and session dedup with overflow on sessions.
#[test]
fn po10_session_counter_overflow_refuses() {
    let f = Fx::new();
    let c = sql(&f.active());
    for id in ["x", "y", "z"] {
        c.execute(
            "INSERT INTO sessions VALUES(?,1,?,0)",
            rusqlite::params![id, i64::MAX],
        )
        .unwrap();
    }
    drop(c);
    let e = f.build().unwrap_err();
    assert_eq!(class(e.as_ref()), "overflow");
}

/// PO1b: robust variant. A writer records continuously across repeated builds;
/// every error counts, compared with an equal-duration control without builds.
#[test]
fn po1b_continuous_health_writer_across_repeated_builds() {
    let f = Fx::new();
    f.bulk_active(1_000, 72_000);
    eprintln!("PO1b active bytes={}", std::fs::metadata(f.active()).unwrap().len());
    let run = |builds: bool| {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let root = f.root.clone();
        let writer = std::thread::spawn(move || {
            let mut j = Journal::open(&root).unwrap();
            let (mut ok, mut err, mut i, mut max) = (0u32, 0u32, 0u64, 0u128);
            let base = if builds { 2_000_000 } else { 3_000_000 };
            while !s.load(Ordering::SeqCst) {
                let t = Instant::now();
                match j.record(&h(base + i, 1)) {
                    Ok(()) => ok += 1,
                    Err(_) => err += 1,
                }
                max = max.max(t.elapsed().as_millis());
                i += 1;
            }
            (ok, err, max)
        });
        let t = Instant::now();
        let mut scans = Vec::new();
        if builds {
            for _ in 0..10 {
                let b = Instant::now();
                let mut active_ms = 0;
                let r = overview::build_observed(&f.root, &AtomicBool::new(false), Limits::default(), &mut |p| {
                    if p == Boundary::ActiveRead {
                        active_ms = b.elapsed().as_millis();
                    }
                    Ok(())
                });
                scans.push(match r {
                    Ok(_) => format!("ok:{active_ms}ms"),
                    Err(e) => format!("err@{}ms:{e}", b.elapsed().as_millis()),
                });
            }
        } else {
            std::thread::sleep(Duration::from_millis(1500));
        }
        let elapsed = t.elapsed();
        if !builds {
            // equal duration is approximate; the control is only a zero-error baseline
        }
        stop.store(true, Ordering::SeqCst);
        let (ok, err, max) = writer.join().unwrap();
        eprintln!("PO1b builds={builds} elapsed_ms={} active_scan_ms={scans:?} writes ok={ok} err={err} max_write_ms={max}", elapsed.as_millis());
        err
    };
    assert_eq!(run(false), 0, "control writer failed without builds");
    let lost = run(true);
    assert_eq!(lost, 0, "health writer lost {lost} observations during repeated overview builds");
}

/// PO4b: an invalid whole observation for an attempt that appears ONLY in the
/// active generation (no duplicate, so dominance() never sees it) must still be
/// refused by row validation, not summed. Isolates the scan's valid_health check.
#[test]
fn po4b_invalid_unique_active_attempt_is_refused_not_summed() {
    for (name, mutate) in [
        ("arith", Box::new(|x: &mut Health| { x.observed = 5; x.locally_queued = 1; x.unconfirmed = 1; }) as Box<dyn Fn(&mut Health)>),
        ("acked", Box::new(|x: &mut Health| x.remote_acknowledged = true)),
        ("gap-flag", Box::new(|x: &mut Health| x.recording_gap = false)),
    ] {
        let f = Fx::new();
        let mut x = h(0xdead, 2);
        mutate(&mut x);
        sql(&f.active())
            .execute(
                "INSERT INTO attempts VALUES(?,1,?,?,?,?)",
                rusqlite::params![x.attempt, x.observed as i64, x.locally_queued as i64, x.unconfirmed as i64, serde_json::to_string(&x).unwrap()],
            )
            .unwrap();
        let r = f.build();
        assert!(r.is_err(), "summed an invalid unique observation: {name} -> {:?}", r.map(|o| o.totals));
    }
}
