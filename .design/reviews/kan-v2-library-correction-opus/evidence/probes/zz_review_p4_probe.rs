#![cfg(feature = "v2-crypto")]
//! Cold-review hostile probes for b6427c3 (capture SQLite contention). Loopback only.
use kan::{
    evidence_capture::{self as capture, EncryptedSpool, Route},
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_service::hex,
    evidence_spool::Spool,
    sign::Identity,
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SCOPE: [u8; 32] = [17; 32];
const PRIVATE: [u8; 32] = [73; 32];

fn make_spool(root: &Path, writer: &Identity) -> PathBuf {
    let path = root.join("spool");
    drop(
        Spool::create(
            &path,
            &hex(&SCOPE),
            &writer.did().to_string(),
            &Identity::generate().did().to_string(),
            64 << 20,
        )
        .unwrap(),
    );
    path
}

/// Chunked loopback provider: `n` pieces of `piece` bytes, `gap` apart.
async fn drip(n: usize, piece: usize, gap: Duration) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut one = [0; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut one).await.is_err() {
                        return;
                    }
                    head.push(one[0]);
                }
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let len = text
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length: ")
                            .map(|v| v.parse().unwrap())
                    })
                    .unwrap_or(0usize);
                let mut b = vec![0; len];
                let _ = s.read_exact(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    .await;
                for _ in 0..n {
                    tokio::time::sleep(gap).await;
                    let mut w = format!("{piece:x}\r\n").into_bytes();
                    w.extend(vec![b'r'; piece]);
                    w.extend(b"\r\n");
                    if s.write_all(&w).await.is_err() {
                        return;
                    }
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    (url, task)
}

/// P1: REQ-1 capture-specific open. An exclusive-mode holder blocks even WAL
/// readers, so Spool::open would wait its 5 s busy timeout during audit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p1_cli_open_does_not_wait_on_exclusive_lock() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = make_spool(dir.path(), &writer);
    let lock = rusqlite::Connection::open(&path).unwrap();
    lock.execute_batch(
        "PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; SELECT count(*) FROM state;",
    )
    .unwrap();
    // Sanity: confirm the lock really blocks a fresh reader.
    let probe = rusqlite::Connection::open(&path).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    let blocked = probe
        .query_row("SELECT count(*) FROM state", [], |r| r.get::<_, i64>(0))
        .is_err();
    println!("P1 reader blocked by exclusive holder: {blocked}");
    let (url, task) = drip(2, 4, Duration::from_millis(1)).await;
    let started = Instant::now();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("capture-post")
        .args([
            "--endpoint",
            &url,
            "--spool",
            path.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ])
        .args([
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--deadline-seconds",
            "5",
        ])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(20), out)
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    task.abort();
    lock.execute_batch("ROLLBACK").unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!(
        "P1 elapsed={elapsed:?} status={} stdout_len={} last={}",
        out.status,
        out.stdout.len(),
        stderr.lines().last().unwrap_or("")
    );
    assert!(blocked, "fixture must actually block readers");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"rrrrrrrr");
    assert!(stderr
        .lines()
        .last()
        .unwrap()
        .contains("\"recording_gap\":true"));
    assert!(
        elapsed < Duration::from_secs(3),
        "capture open waited on lock: {elapsed:?}"
    );
}

/// P2: with_capture_wait must hand the caller's normal policy back.
#[test]
fn p2_admission_restores_callers_busy_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let path = make_spool(dir.path(), &writer);
    let mut spool = Spool::open(&path).unwrap(); // 5 s policy
    let recipient = crypto::public_key(&PRIVATE).unwrap();
    {
        let mut sink = EncryptedSpool {
            spool: Some(&mut spool),
            signer: &writer,
            recipient,
        };
        capture::Sink::admit(&mut sink, &[1; 16], b"capture").unwrap();
    }
    let p = path.clone();
    let holder = std::thread::spawn(move || {
        let lock = rusqlite::Connection::open(&p).unwrap();
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        std::thread::sleep(Duration::from_millis(400));
        lock.execute_batch("ROLLBACK").unwrap();
    });
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let queued = delivery::queue(&mut spool, &writer, &recipient, &[2; 16], b"ordinary queue");
    println!(
        "P2 ordinary queue after capture: ok={} waited={:?}",
        queued.is_ok(),
        started.elapsed()
    );
    holder.join().unwrap();
    assert!(
        queued.is_ok(),
        "ordinary queue lost its wait policy: {:?}",
        queued.err()
    );
}

/// Full-retention race witness uses the normal spool wait policy, so it tests
/// frontier atomicity independently of host crypto/fsync throughput. Production
/// capture's short wait policy has separate contention/budget/recovery tests.
struct FrontierSink<'a> {
    spool: &'a mut Spool,
    signer: &'a Identity,
}
impl capture::Sink for FrontierSink<'_> {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), capture::Unconfirmed> {
        delivery::queue(
            self.spool,
            self.signer,
            &crypto::public_key(&PRIVATE).unwrap(),
            operation,
            frame,
        )
        .map(|_| ())
        .map_err(|_| capture::Unconfirmed)
    }
}
/// One capture attempt in its own thread/runtime and connection.
fn capture_thread(
    path: PathBuf,
    key: PathBuf,
    url: String,
    frontier_only: bool,
) -> std::thread::JoinHandle<capture::Health> {
    std::thread::spawn(move || {
        let signer = Identity::load_existing(&key).unwrap();
        let mut spool = if frontier_only {
            Some(Spool::open(&path).unwrap())
        } else {
            Spool::open_for_capture(&path).ok()
        };
        let mut sink: Box<dyn capture::Sink + '_> = if frontier_only {
            Box::new(FrontierSink {
                spool: spool.as_mut().unwrap(),
                signer: &signer,
            })
        } else {
            Box::new(EncryptedSpool {
                spool: spool.as_mut(),
                signer: &signer,
                recipient: crypto::public_key(&PRIVATE).unwrap(),
            })
        };
        let mut last = None;
        let mut notify = |h: &capture::Health| last = Some(h.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        let r = rt.block_on(capture::forward(
            &Route::new(&url).unwrap(),
            vec![1; 16],
            sink.as_mut(),
            &mut notify,
            &mut out,
            Duration::from_secs(30),
        ));
        assert!(r.is_ok(), "inference must complete");
        last.unwrap()
    })
}

/// P3: two concurrent capture recorders sharing the durable queue. Both must
/// retain every observation using the normal offline wait policy. Deliberately
/// separate this atomicity assertion from the 100 ms capture wait allowance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_concurrent_captures_share_spool() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = make_spool(dir.path(), &writer);
    let (url, task) = drip(20, 512, Duration::from_millis(10)).await;
    let a = capture_thread(path.clone(), key.clone(), url.clone(), true);
    let b = capture_thread(path.clone(), key.clone(), url.clone(), true);
    let (ha, hb) = (a.join().unwrap(), b.join().unwrap());
    task.abort();
    let pending = Spool::open(&path).unwrap().status().unwrap().pending;
    for (n, h) in [("A", &ha), ("B", &hb)] {
        println!(
            "P3 {n}: observed={} queued={} unconfirmed={} gap={}",
            h.observed, h.locally_queued, h.unconfirmed, h.recording_gap
        );
    }
    println!("P3 spool pending={pending}");
    assert_eq!(
        ha.locally_queued, ha.observed,
        "first concurrent stream lost evidence"
    );
    assert_eq!(
        hb.locally_queued, hb.observed,
        "second concurrent stream lost evidence"
    );
    assert_eq!(
        pending,
        ha.locally_queued + hb.locally_queued,
        "queued count must be truthful"
    );
}

/// P4: one capture while a separate writer performs brief periodic commits
/// (a drain acknowledging replies).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zz_probe_p4_instrumented() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = make_spool(dir.path(), &writer);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (p, s) = (path.clone(), stop.clone());
    let drainer = std::thread::spawn(move || {
        let c = rusqlite::Connection::open(&p).unwrap();
        // This synthetic writer must not assume it wins SQLite's lock race.
        // A missed window creates no contention; retry the next window. Keep
        // unexpected errors fatal and require real held windows below.
        c.busy_timeout(Duration::ZERO).unwrap();
        let mut held = 0; let t0=std::time::Instant::now(); let mut log=Vec::new();
        while !s.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
            if s.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            match c.execute_batch("BEGIN IMMEDIATE") {
                Ok(()) => { log.push(format!("{}ms HELD", t0.elapsed().as_millis())); }
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::DatabaseBusy
                        || error.code == rusqlite::ErrorCode::DatabaseLocked =>
                {
                    log.push(format!("{}ms {:?}", t0.elapsed().as_millis(), error.code));
                    continue;
                }
                Err(error) => panic!("synthetic writer failed: {error}"),
            }
            std::thread::sleep(Duration::from_millis(5));
            c.execute_batch("ROLLBACK").unwrap();
            held += 1;
        }
        (held, log, t0)
    });
    let (url, task) = drip(80, 512, Duration::from_millis(5)).await;
    let cs=std::time::Instant::now();
    let h = capture_thread(path.clone(), key, url, false)
        .join()
        .unwrap();
    let ce=std::time::Instant::now();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (held, log, t0) = drainer.join().unwrap();
    println!("PROBE capture span {}ms..{}ms held={held} attempts={} log={:?}", cs.duration_since(t0).as_millis(), ce.duration_since(t0).as_millis(), log.len(), log);
    task.abort();

    assert_eq!(
        h.locally_queued, h.observed,
        "brief contention must not disable capture"
    );
    println!(
        "P4 writer windows={held} (5 ms each, ~9% duty): observed={} queued={} unconfirmed={}",
        h.observed, h.locally_queued, h.unconfirmed
    );
}

