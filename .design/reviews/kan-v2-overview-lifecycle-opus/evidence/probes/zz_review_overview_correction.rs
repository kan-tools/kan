#![cfg(feature = "v2-crypto")]
//! Independent reviewer probes for the overview correction (262cad3), Scope A.
//! Temporarily copied into tests/ and removed afterwards. Synthetic fixtures only.
//! Writers run in a SEPARATE PROCESS (this binary re-executed) to mirror the
//! service/dashboard split; nothing here mirrors the implementation's own seams
//! except the public Boundary hook.
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
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
    _dir: Option<tempfile::TempDir>,
    root: PathBuf,
}
impl Fx {
    /// g0 sealed (attempt 1 obs 1, session s 2), g1 sealed (attempt 1 obs 2, s 5),
    /// active (attempt 1 obs 3, s 8 clean). Same shape as the incorporated PO fixture.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("health");
        let root = dir.path().join("collection");
        let spool = dir.path().join("queue");
        let id = Identity::generate();
        Spool::create(&spool, &format!("{:064x}", 3), id.did().as_str(), id.did().as_str(), 1 << 20).unwrap();
        Journal::create(&source, &spool).unwrap().record(&h(1, 1)).unwrap();
        sql(&source).execute("INSERT INTO sessions VALUES('s',1,2,0)", []).unwrap();
        collection::adopt(&source, &root).unwrap();
        let f = Self { _dir: Some(dir), root };
        Journal::open(&f.root).unwrap().record(&h(1, 2)).unwrap();
        sql(&f.active()).execute("INSERT INTO sessions VALUES('s',1,5,0)", []).unwrap();
        collection::rotate(&f.root).unwrap();
        Journal::open(&f.root).unwrap().record(&h(1, 3)).unwrap();
        sql(&f.active()).execute("INSERT INTO sessions VALUES('s',1,8,1)", []).unwrap();
        f
    }
    fn at(root: PathBuf) -> Self {
        Self { _dir: None, root }
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
    /// name -> (len, sha256). Detects sidecar/lock creation or content change.
    fn tree(&self) -> BTreeMap<String, (u64, String)> {
        let mut out = BTreeMap::new();
        for e in std::fs::read_dir(&self.root).unwrap() {
            let e = e.unwrap();
            out.insert(
                e.file_name().to_string_lossy().into_owned(),
                (e.metadata().unwrap().len(), sha(&e.path())),
            );
        }
        out
    }
    /// Valid unique attempts; `wide` varies body JSON length via status codes only
    /// within the Health contract (shape stays valid).
    fn fill(&self, rows: u64, first: u64) {
        let mut conn = sql(&self.active());
        let tx = conn.transaction().unwrap();
        {
            let mut insert = tx.prepare("INSERT INTO attempts VALUES(?,?,?,?,?,?)").unwrap();
            for n in first..first + rows {
                let x = h(n, 1 + n % 7);
                insert
                    .execute(rusqlite::params![
                        x.attempt,
                        1,
                        x.observed as i64,
                        x.locally_queued as i64,
                        x.unconfirmed as i64,
                        serde_json::to_string(&x).unwrap()
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }
}
fn class(e: &(dyn std::error::Error + Send + Sync + 'static)) -> String {
    match e.downcast_ref::<Failure>() {
        Some(f) => format!("failure:{f:?}"),
        None => {
            let s = e.to_string();
            if s.contains("stayed busy") || s.contains("locked") || s.contains("busy") || s.contains("would block") || s.contains("WouldBlock") {
                format!("busy:{s}")
            } else {
                format!("other:{s}")
            }
        }
    }
}

// ---------------------------------------------------------------- child process
fn spawn(mode: &str, envs: &[(&str, String)]) -> Child {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "zz_review_child", "--nocapture", "--test-threads=1"])
        .env("KAN_REVIEW_CHILD", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        c.env(k, v);
    }
    c.spawn().unwrap()
}
fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child never signalled {}", path.display());
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn result_line(child: Child) -> serde_json::Value {
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.split_once("REVIEW-RESULT ").map(|x| x.1))
        .unwrap_or_else(|| panic!("no child result: {text}\n{}", String::from_utf8_lossy(&out.stderr)));
    serde_json::from_str(line).unwrap()
}
fn env(k: &str) -> String {
    std::env::var(k).unwrap()
}

#[test]
fn zz_review_child() {
    let Ok(mode) = std::env::var("KAN_REVIEW_CHILD") else { return };
    let root = PathBuf::from(env("KAN_REVIEW_ROOT"));
    let ready = PathBuf::from(env("KAN_REVIEW_READY"));
    match mode.as_str() {
        // Production health writer API, journal kept open like the service does.
        "record" => {
            let duration = Duration::from_millis(env("KAN_REVIEW_DURATION_MS").parse().unwrap());
            let interval = Duration::from_millis(env("KAN_REVIEW_INTERVAL_MS").parse().unwrap());
            let mut id: u64 = env("KAN_REVIEW_START").parse().unwrap();
            let mut writer = Journal::open(&root).unwrap();
            std::fs::write(&ready, b"").unwrap();
            let start = Instant::now();
            let (mut writes, mut errors, mut max_us, mut over_50ms) = (0u64, Vec::<String>::new(), 0u128, 0u64);
            let mut error_count = 0u64;
            while start.elapsed() < duration {
                let t = Instant::now();
                match writer.record(&h(id, 1)) {
                    Ok(()) => writes += 1,
                    Err(e) => {
                        error_count += 1;
                        if errors.len() < 5 {
                            errors.push(e.to_string());
                        }
                    }
                }
                let us = t.elapsed().as_micros();
                max_us = max_us.max(us);
                if us > 50_000 {
                    over_50ms += 1;
                }
                id += 1;
                if !interval.is_zero() {
                    std::thread::sleep(interval);
                }
            }
            println!(
                "REVIEW-RESULT {}",
                serde_json::json!({"writes":writes,"errors":error_count,"first_errors":errors,"max_ms":max_us as f64/1000.0,"over_50ms":over_50ms,"next_id":id})
            );
        }
        // Raw multi-statement transactions with an exact cross-row invariant and
        // materially different row shapes (near-page-size session ids, freelist churn).
        "txn" => {
            let duration = Duration::from_millis(env("KAN_REVIEW_DURATION_MS").parse().unwrap());
            let active = PathBuf::from(env("KAN_REVIEW_ACTIVE"));
            let k: u64 = env("KAN_REVIEW_K").parse().unwrap();
            let pause = Duration::from_millis(std::env::var("KAN_REVIEW_INTERVAL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0));
            let mut conn = rusqlite::Connection::open(&active).unwrap();
            conn.busy_timeout(Duration::from_millis(100)).unwrap();
            conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;").unwrap();
            std::fs::write(&ready, b"").unwrap();
            let start = Instant::now();
            let (mut txns, mut errors, mut first) = (0u64, 0u64, Vec::<String>::new());
            let mut i = 0u64;
            while start.elapsed() < duration {
                i += 1;
                let r: rusqlite::Result<()> = (|| {
                    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    for j in 0..k {
                        let x = h(10_000_000 + i * k + j, 1 + (i + j) % 5);
                        tx.execute(
                            "INSERT INTO attempts VALUES(?,?,?,?,?,?)",
                            rusqlite::params![x.attempt, i as i64, x.observed as i64, x.locally_queued as i64, x.unconfirmed as i64, serde_json::to_string(&x).unwrap()],
                        )?;
                    }
                    let pad = "x".repeat(((i * 37) % 3900) as usize);
                    tx.execute("INSERT INTO sessions VALUES(?,?,?,0)", rusqlite::params![format!("s{i:08}-{pad}"), i as i64, i as i64])?;
                    tx.execute("UPDATE sessions SET dropped=?, updated=? WHERE id='ctr'", rusqlite::params![i as i64, i as i64])?;
                    // Page churn: a near-page-size row inserted and deleted in the same txn.
                    tx.execute("INSERT INTO sessions VALUES(?,0,0,0)", [format!("zz-churn-{}", "y".repeat(3990))])?;
                    tx.execute("DELETE FROM sessions WHERE id LIKE 'zz-churn-%'", [])?;
                    tx.commit()
                })();
                if !pause.is_zero() {
                    std::thread::sleep(pause);
                }
                match r {
                    Ok(()) => txns += 1,
                    Err(e) => {
                        // A failed txn rolls back; reuse its index so the invariant stays gap-free.
                        i -= 1;
                        errors += 1;
                        if first.len() < 5 {
                            first.push(e.to_string());
                        }
                    }
                }
            }
            println!("REVIEW-RESULT {}", serde_json::json!({"txns":txns,"errors":errors,"first_errors":first}));
        }
        "hold-exclusive" | "hold-reserved" => {
            let active = PathBuf::from(env("KAN_REVIEW_ACTIVE"));
            let hold = Duration::from_millis(env("KAN_REVIEW_DURATION_MS").parse().unwrap());
            let conn = rusqlite::Connection::open(&active).unwrap();
            if mode == "hold-exclusive" {
                conn.execute_batch("BEGIN EXCLUSIVE; SELECT count(*) FROM attempts;").unwrap();
            } else {
                conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
                conn.execute("INSERT INTO sessions VALUES('uncommitted',1,99999,0)", []).unwrap();
            }
            std::fs::write(&ready, b"").unwrap();
            std::thread::sleep(hold);
            conn.execute_batch("ROLLBACK;").unwrap();
            println!("REVIEW-RESULT {}", serde_json::json!({"held_ms":hold.as_millis() as u64}));
        }
        // Leave a hot rollback journal: write inside a txn, then exit abruptly.
        "crash-mid-txn" => {
            let active = PathBuf::from(env("KAN_REVIEW_ACTIVE"));
            let conn = rusqlite::Connection::open(&active).unwrap();
            conn.execute_batch("PRAGMA cache_size=1; BEGIN IMMEDIATE;").unwrap();
            conn.execute("UPDATE attempts SET updated=updated+1", []).unwrap();
            std::fs::write(&ready, b"").unwrap();
            std::process::exit(77);
        }
        "build-loop" => {
            std::fs::write(&ready, b"").unwrap();
            let mut n = 0u64;
            loop {
                let _ = overview::build(&root, &AtomicBool::new(false), Limits::default());
                n += 1;
                let _ = std::io::stdout().write_all(format!("iter {n}\n").as_bytes());
            }
        }
        "measure" => {
            std::fs::write(&ready, b"").unwrap();
            let base = unsafe { rusqlite::ffi::sqlite3_memory_used() };
            let t = Instant::now();
            let r = overview::build(&root, &AtomicBool::new(false), Limits::default());
            let ms = t.elapsed().as_millis() as u64;
            let high = unsafe { rusqlite::ffi::sqlite3_memory_highwater(0) };
            let (ok, accounted, attempts, err) = match &r {
                Ok(o) => (true, o.accounted_bytes as u64, o.totals.attempts, String::new()),
                Err(e) => (false, 0, 0, class(e.as_ref())),
            };
            println!(
                "REVIEW-RESULT {}",
                serde_json::json!({"ok":ok,"error":err,"build_ms":ms,"sqlite_base":base,"sqlite_highwater":high,"accounted_bytes":accounted,"attempts":attempts})
            );
        }
        "noop" => {
            std::fs::write(&ready, b"").unwrap();
            println!("REVIEW-RESULT {}", serde_json::json!({"noop":true}));
        }
        other => panic!("unknown child mode {other}"),
    }
}

fn ready_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    p
}
fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// RA1: a SEPARATE health-writer process uses the production Journal::record API
/// while refreshes repeatedly copy a near-ceiling active generation. Zero writer
/// errors is the design requirement; refresh outcomes are recorded, not assumed.
#[test]
fn ra1_cross_process_writer_never_fails_during_near_ceiling_refreshes() {
    let f = Fx::new();
    f.fill(64_000, 100);
    let size = std::fs::metadata(f.active()).unwrap().len();
    eprintln!("RA1 active bytes={size} pages={}", size / 4096);
    assert!(size < 31 * 1024 * 1024, "fixture must leave writer headroom");
    let s = scratch();
    let mut next = 1_000_000u64;
    let mut writer_errors = 0u64;
    for (label, interval) in [("continuous", 0u64), ("20hz", 50), ("5hz", 200)] {
        let ready = ready_path(s.path(), label);
        let child = spawn(
            "record",
            &[
                ("KAN_REVIEW_ROOT", f.root.display().to_string()),
                ("KAN_REVIEW_READY", ready.display().to_string()),
                ("KAN_REVIEW_DURATION_MS", "9000".into()),
                ("KAN_REVIEW_INTERVAL_MS", interval.to_string()),
                ("KAN_REVIEW_START", next.to_string()),
            ],
        );
        wait_file(&ready);
        let start = Instant::now();
        let mut outcomes: BTreeMap<String, u32> = BTreeMap::new();
        let mut ok_ms = Vec::new();
        let mut windows = Vec::new();
        while start.elapsed() < Duration::from_millis(7500) {
            let t = Instant::now();
            match overview::build(&f.root, &AtomicBool::new(false), Limits::default()) {
                Ok(o) => {
                    *outcomes.entry("ok".into()).or_default() += 1;
                    ok_ms.push(t.elapsed().as_millis());
                    let a = &o.sources.last().unwrap().snapshot;
                    windows.push(a.finished_at.saturating_sub(a.started_at));
                    assert!(a.started_at <= a.finished_at && a.finished_at <= o.built_at);
                }
                Err(e) => *outcomes.entry(format!("{} after {}ms", class(e.as_ref()), t.elapsed().as_millis() / 100 * 100)).or_default() += 1,
            }
        }
        let r = result_line(child);
        next = r["next_id"].as_u64().unwrap();
        writer_errors += r["errors"].as_u64().unwrap();
        eprintln!("RA1 {label}: writer={r} refresh_outcomes={outcomes:?} ok_build_ms={ok_ms:?} active_window_s={windows:?}");
    }
    assert_eq!(writer_errors, 0, "health writer failed while overview refreshed");
}

/// RA2: snapshot consistency. A separate process commits multi-row transactions
/// (K attempts + one session of varying length up to ~3.9 KB + a counter update +
/// near-page-size insert/delete churn). Every published overview must be a whole
/// committed prefix: attempts == base + K*n and dropped == 8 + n(n+1)/2 + n.
#[test]
fn ra2_published_totals_are_a_consistent_committed_prefix_under_churn() {
    for (label, base_rows, pause) in [("small-continuous", 0u64, 0u64), ("small-20ms", 0, 20), ("small-100ms", 0, 100), ("20k-continuous", 20_000, 0), ("20k-100ms", 20_000, 100)] {
        let f = Fx::new();
        if base_rows > 0 {
            f.fill(base_rows, 100);
        }
        sql(&f.active()).execute("INSERT INTO sessions VALUES('ctr',0,0,0)", []).unwrap();
        let k = 5u64;
        let s = scratch();
        let ready = ready_path(s.path(), "txn");
        let child = spawn(
            "txn",
            &[
                ("KAN_REVIEW_ROOT", f.root.display().to_string()),
                ("KAN_REVIEW_READY", ready.display().to_string()),
                ("KAN_REVIEW_ACTIVE", f.active().display().to_string()),
                ("KAN_REVIEW_DURATION_MS", "9000".into()),
                ("KAN_REVIEW_K", k.to_string()),
                ("KAN_REVIEW_INTERVAL_MS", pause.to_string()),
            ],
        );
        wait_file(&ready);
        let start = Instant::now();
        let (mut consistent, mut outcomes, mut ns) = (0u32, BTreeMap::<String, u32>::new(), Vec::new());
        while start.elapsed() < Duration::from_millis(7500) {
            match overview::build(&f.root, &AtomicBool::new(false), Limits::default()) {
                Ok(o) => {
                    let t = &o.totals;
                    // sessions: 's' + 'ctr' + n new.
                    let n = t.sessions - 2;
                    let base_attempts = 1 + base_rows;
                    assert_eq!(t.attempts, base_attempts + k * n, "{label}: torn attempts/sessions snapshot");
                    assert_eq!(t.telemetry_dropped_lower_bound, 8 + n * (n + 1) / 2 + n, "{label}: torn counter snapshot (n={n})");
                    assert_eq!(t.unclosed_sessions, n + 1, "{label}: torn clean flags");
                    consistent += 1;
                    ns.push(n);
                }
                Err(e) => *outcomes.entry(class(e.as_ref())).or_default() += 1,
            }
        }
        let r = result_line(child);
        eprintln!("RA2 {label}: writer={r} consistent_published={consistent} refusals={outcomes:?} n_samples={ns:?}");
        assert_eq!(r["errors"].as_u64().unwrap(), 0, "{label}: raw writer txns failed");
        assert!(
            outcomes.keys().all(|k| k.starts_with("busy:")),
            "{label}: non-busy refusal under valid churn: {outcomes:?}"
        );
    }
}

/// RA3a: cancellation at many points, including inside the 64-page copy loop.
/// Only Ok or Cancelled are acceptable; no file/sidecar changes; the source is
/// immediately writable afterwards.
#[test]
fn ra3a_cancellation_during_copy_is_clean() {
    let f = Fx::new();
    f.fill(60_000, 100);
    let before = f.tree();
    let mut seen = BTreeMap::<String, u32>::new();
    for delay_us in [0u64, 200, 500, 1_000, 2_000, 4_000, 8_000, 15_000, 30_000, 60_000, 120_000, 250_000, 500_000, 1_000_000] {
        let flag = Arc::new(AtomicBool::new(false));
        let pinned = Arc::new(std::sync::Mutex::new(None::<Instant>));
        let rows_read = Arc::new(std::sync::Mutex::new(None::<Instant>));
        let (root, fl, p, rr) = (f.root.clone(), flag.clone(), pinned.clone(), rows_read.clone());
        let t = std::thread::spawn(move || {
            let mut first_rows = true;
            overview::build_observed(&root, &fl, Limits::default(), &mut |b| {
                match b {
                    Boundary::MembershipPinned => *p.lock().unwrap() = Some(Instant::now()),
                    Boundary::SourceRowsRead if first_rows => {
                        first_rows = false;
                        *rr.lock().unwrap() = Some(Instant::now())
                    }
                    _ => {}
                }
                Ok(())
            })
        });
        std::thread::sleep(Duration::from_micros(delay_us));
        let cancel_at = Instant::now();
        flag.store(true, Ordering::Relaxed);
        let r = t.join().unwrap();
        let phase = match (*pinned.lock().unwrap(), *rows_read.lock().unwrap()) {
            (None, _) => "before-pin",
            (Some(p), _) if cancel_at < p => "before-pin",
            (Some(_), None) => "during-active-copy-or-parse",
            (Some(_), Some(rr)) if cancel_at < rr => "during-active-copy-or-parse",
            _ => "after-active",
        };
        let outcome = match &r {
            Ok(_) => "ok".to_string(),
            Err(e) if matches!(e.downcast_ref::<Failure>(), Some(Failure::Cancelled)) => "cancelled".into(),
            Err(e) => panic!("delay {delay_us}us: unexpected {}", class(e.as_ref())),
        };
        *seen.entry(format!("{phase}:{outcome}")).or_default() += 1;
        assert_eq!(before, f.tree(), "cancel at {delay_us}us changed collection files");
    }
    eprintln!("RA3a phases/outcomes: {seen:?}");
    assert!(seen.keys().any(|k| k.starts_with("during-active-copy-or-parse:cancelled")), "no cancellation landed inside the active copy/parse window: {seen:?}");
    let t = Instant::now();
    Journal::open(&f.root).unwrap().record(&h(99_999_999, 1)).unwrap();
    eprintln!("RA3a post-cancel write {}ms", t.elapsed().as_millis());
}

/// RA3b: abrupt death (SIGKILL) of a process that is looping refreshes. The
/// source must be byte-identical, sidecar-free, integrity-clean and writable.
#[test]
fn ra3b_sigkill_during_refresh_leaves_source_untouched() {
    let f = Fx::new();
    f.fill(40_000, 100);
    let before = f.tree();
    let s = scratch();
    let mut iters = Vec::new();
    for (i, delay_ms) in [3u64, 9, 17, 31, 47, 73, 101, 149, 211, 307, 401, 557].iter().enumerate() {
        let ready = ready_path(s.path(), &format!("kill{i}"));
        let mut child = spawn("build-loop", &[("KAN_REVIEW_ROOT", f.root.display().to_string()), ("KAN_REVIEW_READY", ready.display().to_string())]);
        wait_file(&ready);
        std::thread::sleep(Duration::from_millis(*delay_ms));
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        iters.push(String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("iter")).count());
        assert_eq!(before, f.tree(), "SIGKILL after {delay_ms}ms changed/created collection files");
        let c = rusqlite::Connection::open_with_flags(f.active(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0)).unwrap(), "ok");
    }
    eprintln!("RA3b completed refresh iterations before each kill: {iters:?}");
    let t = Instant::now();
    Journal::open(&f.root).unwrap().record(&h(99_999_999, 1)).unwrap();
    eprintln!("RA3b post-kill write {}ms", t.elapsed().as_millis());
    assert!(overview::build(&f.root, &AtomicBool::new(false), Limits::default()).is_ok());
}

fn manager_finish(m: &Manager) -> overview::Published {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = m.status();
        if !["building", "cancelling"].contains(&s.state) {
            return s;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// RA4: classification matrix through the real Manager labels.
#[test]
fn ra4_busy_versus_invalid_classification() {
    let s = scratch();
    // (a) another process holds an EXCLUSIVE lock on the active journal.
    {
        let f = Fx::new();
        let ready = ready_path(s.path(), "excl");
        let child = spawn("hold-exclusive", &[("KAN_REVIEW_ROOT", f.root.display().to_string()), ("KAN_REVIEW_READY", ready.display().to_string()), ("KAN_REVIEW_ACTIVE", f.active().display().to_string()), ("KAN_REVIEW_DURATION_MS", "7000".into())]);
        wait_file(&ready);
        let m = Manager::new();
        let t = Instant::now();
        m.refresh(f.root.clone()).unwrap();
        let p = manager_finish(&m);
        eprintln!("RA4a exclusive holder: state={} reason={:?} after {}ms", p.state, p.reason, t.elapsed().as_millis());
        assert_eq!(p.state, "failed");
        assert_eq!(p.reason.as_deref(), Some("source busy or in use; retry refresh"));
        result_line(child);
    }
    // (b) RESERVED holder with uncommitted rows: readers proceed, uncommitted rows invisible.
    {
        let f = Fx::new();
        let ready = ready_path(s.path(), "res");
        let child = spawn("hold-reserved", &[("KAN_REVIEW_ROOT", f.root.display().to_string()), ("KAN_REVIEW_READY", ready.display().to_string()), ("KAN_REVIEW_ACTIVE", f.active().display().to_string()), ("KAN_REVIEW_DURATION_MS", "3000".into())]);
        wait_file(&ready);
        let o = overview::build(&f.root, &AtomicBool::new(false), Limits::default());
        eprintln!("RA4b reserved holder: {:?}", o.as_ref().map(|o| (o.totals.sessions, o.totals.telemetry_dropped_lower_bound)).map_err(|e| class(e.as_ref())));
        let o = o.unwrap();
        assert_eq!(o.totals.telemetry_dropped_lower_bound, 8, "uncommitted row leaked into snapshot");
        result_line(child);
    }
    // (c) crashed writer left a hot rollback journal on the active generation.
    {
        let f = Fx::new();
        f.fill(2_000, 100);
        let ready = ready_path(s.path(), "crash");
        let child = spawn("crash-mid-txn", &[("KAN_REVIEW_ROOT", f.root.display().to_string()), ("KAN_REVIEW_READY", ready.display().to_string()), ("KAN_REVIEW_ACTIVE", f.active().display().to_string())]);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(77));
        let mut j = f.active().into_os_string();
        j.push("-journal");
        let journal = PathBuf::from(j);
        let hot_before = std::fs::metadata(&journal).map(|m| m.len()).ok();
        let tree = f.tree();
        let m = Manager::new();
        m.refresh(f.root.clone()).unwrap();
        let p = manager_finish(&m);
        eprintln!("RA4c hot journal ({hot_before:?} bytes): state={} reason={:?}", p.state, p.reason);
        assert_ne!(p.state, "completed", "overview published from a source with a hot journal");
        assert_eq!(tree, f.tree(), "overview touched the hot journal or source");
        // The production writer then recovers and capture continues; overview recovers.
        Journal::open(&f.root).unwrap().record(&h(77_777, 1)).unwrap();
        m.refresh(f.root.clone()).unwrap();
        let p = manager_finish(&m);
        eprintln!("RA4c after writer recovery: state={} reason={:?}", p.state, p.reason);
        assert_eq!(p.state, "completed");
    }
    // (d) corrupt b-tree page in the active generation: invalid, never "busy".
    {
        let f = Fx::new();
        f.fill(5_000, 100);
        let active = f.active();
        let root_page: i64 = sql(&active)
            .query_row("SELECT rootpage FROM sqlite_schema WHERE name='attempts'", [], |r| r.get(0))
            .unwrap();
        let mut bytes = std::fs::read(&active).unwrap();
        let page = (root_page - 1) as usize;
        // Invalid b-tree page type byte and header on the attempts root page.
        for b in &mut bytes[page * 4096..page * 4096 + 12] {
            *b = 0xFF;
        }
        std::fs::write(&active, &bytes).unwrap();
        let m = Manager::new();
        m.refresh(f.root.clone()).unwrap();
        let p = manager_finish(&m);
        eprintln!("RA4d corrupt page: state={} reason={:?}", p.state, p.reason);
        assert_eq!(p.state, "failed");
        assert_eq!(p.reason.as_deref(), Some("source invalid or unavailable"));
    }
}

/// RA5: memory. A fresh child process builds a near-ceiling overview; record
/// SQLite's own allocator high-water mark (not covered by Rust heap probes) and
/// max RSS from /usr/bin/time, against the fixed 48-MiB reserve.
#[test]
fn ra5_sqlite_memory_highwater_fits_the_reserve() {
    let f = Fx::new();
    f.fill(64_000, 100);
    eprintln!("RA5 active bytes={}", std::fs::metadata(f.active()).unwrap().len());
    let s = scratch();
    for mode in ["noop", "measure"] {
        let ready = ready_path(s.path(), mode);
        let out = Command::new("/usr/bin/time")
            .arg("-l")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "zz_review_child", "--nocapture", "--test-threads=1"])
            .env("KAN_REVIEW_CHILD", mode)
            .env("KAN_REVIEW_ROOT", &f.root)
            .env("KAN_REVIEW_READY", &ready)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let rss = stderr.lines().find(|l| l.contains("maximum resident set size")).unwrap_or("?").trim().to_owned();
        let line = stdout.lines().find_map(|l| l.split_once("REVIEW-RESULT ").map(|x| x.1)).unwrap_or("?").to_owned();
        eprintln!("RA5 {mode}: {line} | {rss}");
        if mode == "measure" {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(v["ok"].as_bool().unwrap(), "{v}");
            let high = v["sqlite_highwater"].as_i64().unwrap();
            assert!(high > 0, "SQLite memstatus unavailable");
            assert!(high < 48 * 1024 * 1024, "SQLite high-water {high} exceeds the 48-MiB reserve");
        }
    }
}

/// RA6: exact post-read sealed hash. Mutations at the post-read boundary that keep
/// SQLite-visible rows identical (one appended byte; a flipped byte in an unused
/// reserve blob) must still refuse publication.
#[test]
fn ra6_post_read_sealed_rehash_is_byte_exact() {
    for (name, mutate) in [
        ("append-one-byte", Box::new(|p: &Path| {
            let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
            f.write_all(&[0]).unwrap();
        }) as Box<dyn Fn(&Path)>),
        ("flip-reserve-byte", Box::new(|p: &Path| {
            let c = rusqlite::Connection::open(p).unwrap();
            c.execute("UPDATE reserve SET bytes=zeroblob(4095)||X'01' WHERE id=63", []).unwrap();
        })),
        ("truncate-trailing-page", Box::new(|p: &Path| {
            let len = std::fs::metadata(p).unwrap().len();
            std::fs::OpenOptions::new().write(true).open(p).unwrap().set_len(len - 1).unwrap();
        })),
    ] {
        let f = Fx::new();
        let sealed = f.sealed(1);
        let before = f.build_rows();
        let mut scans = 0;
        let r = overview::build_observed(&f.root, &AtomicBool::new(false), Limits::default(), &mut |b| {
            if b == Boundary::SourceRowsRead {
                scans += 1;
                // scan 1 = active, scan 2 = g0, scan 3 = g1
                if scans == 3 {
                    mutate(&sealed);
                }
            }
            Ok(())
        });
        assert_eq!(scans, 3, "{name}: did not reach g1 post-read fence");
        eprintln!("RA6 {name}: {:?}", r.as_ref().map(|_| "PUBLISHED").map_err(|e| class(e.as_ref())));
        assert!(r.is_err(), "{name}: published a sealed source changed after its row read (rows were {before})");
    }
}
impl Fx {
    fn build_rows(&self) -> u64 {
        overview::build(&self.root, &AtomicBool::new(false), Limits::default()).unwrap().totals.attempts
    }
}

/// RA7: Manager-level label under a continuously writing production writer.
#[test]
fn ra7_manager_labels_under_continuous_writer() {
    let f = Fx::new();
    f.fill(64_000, 100);
    let s = scratch();
    let ready = ready_path(s.path(), "ra7");
    let child = spawn("record", &[("KAN_REVIEW_ROOT", f.root.display().to_string()), ("KAN_REVIEW_READY", ready.display().to_string()), ("KAN_REVIEW_DURATION_MS", "12000".into()), ("KAN_REVIEW_INTERVAL_MS", "0".into()), ("KAN_REVIEW_START", "2000000".into())]);
    wait_file(&ready);
    let m = Manager::new();
    let mut states = BTreeMap::<String, u32>::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        m.refresh(f.root.clone()).unwrap();
        let p = manager_finish(&m);
        *states.entry(format!("{}:{:?}", p.state, p.reason)).or_default() += 1;
    }
    let r = result_line(child);
    eprintln!("RA7 writer={r} manager_outcomes={states:?}");
    assert_eq!(r["errors"].as_u64().unwrap(), 0);
    assert!(states.keys().all(|k| k.starts_with("completed") || k.contains("source busy or in use")), "{states:?}");
}

/// RA5b: near-maximal 32-MiB active image. Rows may exceed the row budget, but
/// the image copy itself must stay inside the fixed reserve.
#[test]
fn ra5b_full_size_image_highwater() {
    let f = Fx::new();
    f.fill(78_500, 100);
    let size = std::fs::metadata(f.active()).unwrap().len();
    eprintln!("RA5b active bytes={size} pages={}", size / 4096);
    let s = scratch();
    let ready = ready_path(s.path(), "measure");
    let out = Command::new("/usr/bin/time")
        .arg("-l")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "zz_review_child", "--nocapture", "--test-threads=1"])
        .env("KAN_REVIEW_CHILD", "measure")
        .env("KAN_REVIEW_ROOT", &f.root)
        .env("KAN_REVIEW_READY", &ready)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let rss = stderr.lines().find(|l| l.contains("maximum resident set size")).unwrap_or("?").trim().to_owned();
    let line = stdout.lines().find_map(|l| l.split_once("REVIEW-RESULT ").map(|x| x.1)).unwrap().to_owned();
    eprintln!("RA5b measure: {line} | {rss}");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(v["sqlite_highwater"].as_i64().unwrap() < 48 * 1024 * 1024);
}
