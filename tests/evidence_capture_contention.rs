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
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan"))
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
/// Coordinate the first writer window after spool open and at admission entry.
/// Preserve both production Sink methods, including the actual spent-wait value.
struct FirstCaptureWindow {
    request: std::sync::mpsc::SyncSender<Instant>,
    locked: std::sync::mpsc::Receiver<()>,
    spent: std::sync::mpsc::SyncSender<Duration>,
}
struct CoordinatedSink<'a> {
    inner: Box<dyn capture::Sink + 'a>,
    first: Option<FirstCaptureWindow>,
}
impl CoordinatedSink<'_> {
    fn first_window(&mut self) -> Option<std::sync::mpsc::SyncSender<Duration>> {
        if let Some(first) = self.first.take() {
            first.request.send(Instant::now()).unwrap();
            first
                .locked
                .recv_timeout(Duration::from_secs(5))
                .expect("synthetic writer must establish first contention window");
            return Some(first.spent);
        }
        None
    }
}
impl capture::Sink for CoordinatedSink<'_> {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), capture::Unconfirmed> {
        self.first_window();
        self.inner.admit(operation, frame)
    }
    fn admit_with_wait(
        &mut self,
        operation: &[u8; 16],
        frame: &[u8],
        wait: Duration,
    ) -> (Result<(), capture::Unconfirmed>, Duration) {
        let first = self.first_window();
        let result = self.inner.admit_with_wait(operation, frame, wait);
        if let Some(spent) = first {
            spent.send(result.1).unwrap();
        }
        result
    }
}

/// The contention wrapper must pass the measured wait back to Recorder, not
/// merely publish it on its diagnostic channel (cold-review W4).
#[test]
fn coordinated_sink_returns_inner_wait_to_its_caller() {
    use capture::Sink;
    struct MeasuredSink(usize);
    impl Sink for MeasuredSink {
        fn admit(&mut self, _: &[u8; 16], _: &[u8]) -> Result<(), capture::Unconfirmed> {
            panic!("wait-aware call must use the wait-aware implementation")
        }
        fn admit_with_wait(
            &mut self,
            operation: &[u8; 16],
            frame: &[u8],
            wait: Duration,
        ) -> (Result<(), capture::Unconfirmed>, Duration) {
            assert_eq!(operation, &[17; 16]);
            assert_eq!(frame, b"synthetic frame");
            assert_eq!(wait, Duration::from_millis(80));
            self.0 += 1;
            if self.0 == 1 {
                (Ok(()), Duration::from_millis(7))
            } else {
                (Err(capture::Unconfirmed), Duration::from_millis(13))
            }
        }
    }
    let (request, requested) = std::sync::mpsc::sync_channel(1);
    let (locked, lock_ready) = std::sync::mpsc::sync_channel(1);
    let (spent, first_spent) = std::sync::mpsc::sync_channel(1);
    locked.send(()).unwrap();
    let mut sink = CoordinatedSink {
        inner: Box::new(MeasuredSink(0)),
        first: Some(FirstCaptureWindow {
            request,
            locked: lock_ready,
            spent,
        }),
    };
    let first = sink.admit_with_wait(&[17; 16], b"synthetic frame", Duration::from_millis(80));
    assert!(first.0.is_ok());
    assert_eq!(
        first.1,
        Duration::from_millis(7),
        "caller must receive measured wait"
    );
    assert_eq!(first_spent.try_recv().unwrap(), first.1);
    assert!(requested.try_recv().is_ok());
    let later = sink.admit_with_wait(&[17; 16], b"synthetic frame", Duration::from_millis(80));
    assert!(later.0.is_err());
    assert_eq!(
        later.1,
        Duration::from_millis(13),
        "failed admission still spends wait"
    );
    assert!(requested.try_recv().is_err());
    assert!(first_spent.try_recv().is_err());
}

/// One capture attempt in its own thread/runtime and connection.
fn capture_thread(
    path: PathBuf,
    key: PathBuf,
    url: String,
    frontier_only: bool,
) -> std::thread::JoinHandle<capture::Health> {
    capture_thread_with_window(path, key, url, frontier_only, None)
}
fn capture_thread_with_window(
    path: PathBuf,
    key: PathBuf,
    url: String,
    frontier_only: bool,
    first: Option<FirstCaptureWindow>,
) -> std::thread::JoinHandle<capture::Health> {
    std::thread::spawn(move || {
        let signer = Identity::load_existing(&key).unwrap();
        let mut spool = if frontier_only {
            Some(Spool::open(&path).unwrap())
        } else {
            Spool::open_for_capture(&path).ok()
        };
        let inner: Box<dyn capture::Sink + '_> = if frontier_only {
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
        let mut sink = CoordinatedSink { inner, first };
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
            &mut sink,
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
async fn p4_capture_beside_brief_periodic_writer() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = make_spool(dir.path(), &writer);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (p, s) = (path.clone(), stop.clone());
    let (request, requested) = std::sync::mpsc::sync_channel(0);
    let (locked, lock_ready) = std::sync::mpsc::sync_channel(0);
    let (spent, first_spent) = std::sync::mpsc::sync_channel(1);
    let drainer = std::thread::spawn(move || {
        let c = rusqlite::Connection::open(&p).unwrap();
        // This synthetic writer must not assume it wins SQLite's lock race.
        // A missed window creates no contention; retry the next window. Keep
        // unexpected errors fatal and require real held windows below.
        c.busy_timeout(Duration::ZERO).unwrap();
        // No capture writes can race this first acquisition: the first Sink
        // call waits for our acknowledgement, after its spool has opened.
        let first_admission = requested
            .recv_timeout(Duration::from_secs(5))
            .expect("capture must reach its first admission");
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        let first_start = Instant::now();
        locked.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        c.execute_batch("ROLLBACK").unwrap();
        let first_end = Instant::now();
        let mut held = 1;
        while !s.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
            if s.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            match c.execute_batch("BEGIN IMMEDIATE") {
                Ok(()) => {}
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::DatabaseBusy
                        || error.code == rusqlite::ErrorCode::DatabaseLocked =>
                {
                    continue;
                }
                Err(error) => panic!("synthetic writer failed: {error}"),
            }
            std::thread::sleep(Duration::from_millis(5));
            c.execute_batch("ROLLBACK").unwrap();
            held += 1;
        }
        (held, first_admission, first_start, first_end)
    });
    let (url, task) = drip(80, 512, Duration::from_millis(5)).await;
    let capture_started = Instant::now();
    let capture_result = capture_thread_with_window(
        path.clone(),
        key,
        url,
        false,
        Some(FirstCaptureWindow {
            request,
            locked: lock_ready,
            spent,
        }),
    )
    .join();
    let capture_finished = Instant::now();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let drain_result = drainer.join();
    task.abort();
    let h = capture_result.unwrap();
    let (held, first_admission, first_start, first_end) = drain_result.unwrap();
    let waited = first_spent
        .try_recv()
        .expect("first admission must report its actual wait");
    assert!(
        waited > Duration::ZERO,
        "first admission must wait on the coordinated writer lock: {waited:?}"
    );
    assert!(held > 0);
    assert!(capture_started <= first_admission && first_admission <= first_start);
    assert!(first_start < first_end && first_end <= capture_finished);
    assert!(first_end.duration_since(first_start) >= Duration::from_millis(5));
    assert_eq!(
        h.locally_queued, h.observed,
        "brief contention must not disable capture"
    );
    println!(
        "P4 writer windows={held} (first coordinated, then periodic; first {:?} inside capture {:?}): observed={} queued={} unconfirmed={}",
        first_end.duration_since(first_start), capture_finished.duration_since(capture_started),
        h.observed, h.locally_queued, h.unconfirmed
    );
}

fn concurrent_opens(
    path: &Path,
    capture: bool,
    trials: usize,
) -> std::collections::BTreeMap<String, usize> {
    let mut failures = std::collections::BTreeMap::<String, usize>::new();
    for _ in 0..trials {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (p, b) = (path.to_path_buf(), barrier.clone());
                std::thread::spawn(move || {
                    b.wait();
                    let r = if capture {
                        Spool::open_for_capture(&p)
                    } else {
                        Spool::open(&p)
                    };
                    r.map(drop).map_err(|e| e.to_string())
                })
            })
            .collect();
        for h in handles {
            if let Err(e) = h.join().unwrap() {
                *failures.entry(e).or_default() += 1;
            }
        }
    }
    failures
}

/// P5: does a zero-timeout capture open fail merely because another
/// connection opens at the same moment (no long-held lock)?
#[test]
fn p5_concurrent_capture_opens() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let path = make_spool(dir.path(), &writer);
    assert!(concurrent_opens(&path, true, 40).is_empty());
    assert!(concurrent_opens(&path, false, 40).is_empty());
}

/// Q2: per-observation cap and allowance accounting under a lock held across repeated admissions.
#[test]
fn q2_per_observation_cap_and_allowance() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let path = make_spool(dir.path(), &writer);
    let mut spool = Spool::open_for_capture(&path).unwrap();
    let lock = rusqlite::Connection::open(&path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut sink = EncryptedSpool {
        spool: Some(&mut spool),
        signer: &writer,
        recipient: crypto::public_key(&PRIVATE).unwrap(),
    };
    let mut notify = |_: &capture::Health| {};
    let mut rec =
        capture::Recorder::new(capture::Observer::Gateway, &mut sink, &mut notify).unwrap();
    let mut per = Vec::new();
    let all = Instant::now();
    for n in 0..15 {
        let s = Instant::now();
        rec.record(capture::Event::RequestChunk { offset: n }, b"x")
            .unwrap();
        per.push(s.elapsed().as_millis());
    }
    println!("Q2 per-observation ms={per:?} total={:?}", all.elapsed());
    let max = *per.iter().max().unwrap();
    lock.execute_batch("ROLLBACK").unwrap();
    rec.record(capture::Event::RequestChunk { offset: 15 }, b"r")
        .unwrap();
    println!(
        "Q2 after unlock queued={} unconfirmed={}",
        rec.health().locally_queued,
        rec.health().unconfirmed
    );
    assert!(max < 200, "per-observation wait exceeded cap: {max} ms");
    assert!(
        per.iter().take(5).all(|&m| m >= 90),
        "admission did not wait: {per:?}"
    );
    assert!(
        per.iter().skip(12).all(|&m| m < 50),
        "allowance not exhausted: {per:?}"
    );
    assert_eq!(rec.health().locally_queued, 1);
}
