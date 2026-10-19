#![cfg(feature = "v2-crypto")]
//! Reviewer probe for 8124878 P4 (temporary copy in tests/, removed after use).
//! Faithful copy of the HEAD P4 fixture plus instrumentation that records what
//! the PRODUCTION sink returned for each admission: the busy-handler `spent`
//! duration, the call's wall time and its result. This separates "a writer
//! window lay inside the capture interval" (what P4 asserts) from "capture's
//! first admission actually waited on SQLite" (what P4 does not assert).
//! Fault modes exercise P4's cleanup when the capture thread panics.
use kan::{
    evidence_capture::{self as capture, EncryptedSpool, Route},
    evidence_crypto as crypto,
    evidence_service::hex,
    evidence_spool::Spool,
    sign::Identity,
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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

#[derive(Clone, Debug)]
struct Admission {
    start: Instant,
    end: Instant,
    caller_wait: Duration,
    spent: Duration,
    ok: bool,
}

struct FirstCaptureWindow {
    request: std::sync::mpsc::SyncSender<Instant>,
    locked: std::sync::mpsc::Receiver<()>,
}
struct CoordinatedSink<'a> {
    inner: Box<dyn capture::Sink + 'a>,
    first: Option<FirstCaptureWindow>,
    log: Arc<Mutex<Vec<Admission>>>,
}
impl CoordinatedSink<'_> {
    fn first_window(&mut self) {
        if let Some(first) = self.first.take() {
            first.request.send(Instant::now()).unwrap();
            first
                .locked
                .recv_timeout(Duration::from_secs(5))
                .expect("synthetic writer must establish first contention window");
        }
    }
}
impl capture::Sink for CoordinatedSink<'_> {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), capture::Unconfirmed> {
        self.first_window();
        let start = Instant::now();
        let r = self.inner.admit(operation, frame);
        self.log.lock().unwrap().push(Admission {
            start,
            end: Instant::now(),
            caller_wait: Duration::MAX,
            spent: Duration::ZERO,
            ok: r.is_ok(),
        });
        r
    }
    fn admit_with_wait(
        &mut self,
        operation: &[u8; 16],
        frame: &[u8],
        wait: Duration,
    ) -> (Result<(), capture::Unconfirmed>, Duration) {
        self.first_window();
        let start = Instant::now();
        let (r, spent) = self.inner.admit_with_wait(operation, frame, wait);
        self.log.lock().unwrap().push(Admission {
            start,
            end: Instant::now(),
            caller_wait: wait,
            spent,
            ok: r.is_ok(),
        });
        (r, spent)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    None,
    PanicBeforeAdmission,
    PanicAfterCapture,
    /// Mirrors mutant T5: rendezvous kept, first window holds no SQLite lock.
    FirstWindowNoLock,
}

fn capture_thread_with_window(
    path: PathBuf,
    key: PathBuf,
    url: String,
    first: Option<FirstCaptureWindow>,
    log: Arc<Mutex<Vec<Admission>>>,
    fault: Fault,
) -> std::thread::JoinHandle<capture::Health> {
    std::thread::spawn(move || {
        if fault == Fault::PanicBeforeAdmission {
            drop(first);
            panic!("probe: injected capture panic before first admission");
        }
        let signer = Identity::load_existing(&key).unwrap();
        let mut spool = Spool::open_for_capture(&path).ok();
        let inner: Box<dyn capture::Sink + '_> = Box::new(EncryptedSpool {
            spool: spool.as_mut(),
            signer: &signer,
            recipient: crypto::public_key(&PRIVATE).unwrap(),
        });
        let mut sink = CoordinatedSink { inner, first, log };
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
        if fault == Fault::PanicAfterCapture {
            panic!("probe: injected capture panic after forward");
        }
        last.unwrap()
    })
}

/// Body is the HEAD P4 body verbatim except for the instrumentation log, the
/// fault parameter, per-window timestamps and the reporting at the end.
async fn p4(fault: Fault) {
    let t0 = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = make_spool(dir.path(), &writer);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (p, s) = (path.clone(), stop.clone());
    let (request, requested) = std::sync::mpsc::sync_channel(0);
    let (locked, lock_ready) = std::sync::mpsc::sync_channel(0);
    let drainer = std::thread::spawn(move || {
        let c = rusqlite::Connection::open(&p).unwrap();
        c.busy_timeout(Duration::ZERO).unwrap();
        let first_admission = requested
            .recv_timeout(Duration::from_secs(5))
            .expect("capture must reach its first admission");
        if fault != Fault::FirstWindowNoLock {
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        let first_start = Instant::now();
        locked.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        if fault != Fault::FirstWindowNoLock {
            c.execute_batch("ROLLBACK").unwrap();
        }
        let first_end = Instant::now();
        let mut held = 1;
        let mut windows = vec![(first_start, first_end)];
        let mut missed = 0;
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
                    missed += 1;
                    continue;
                }
                Err(error) => panic!("synthetic writer failed: {error}"),
            }
            let ws = Instant::now();
            std::thread::sleep(Duration::from_millis(5));
            c.execute_batch("ROLLBACK").unwrap();
            windows.push((ws, Instant::now()));
            held += 1;
        }
        (held, first_admission, first_start, first_end, windows, missed)
    });
    let (url, task) = drip(80, 512, Duration::from_millis(5)).await;
    let log = Arc::new(Mutex::new(Vec::new()));
    let capture_started = Instant::now();
    let capture_result = capture_thread_with_window(
        path.clone(),
        key,
        url,
        Some(FirstCaptureWindow {
            request,
            locked: lock_ready,
        }),
        log.clone(),
        fault,
    )
    .join();
    let capture_finished = Instant::now();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let drain_result = drainer.join();
    task.abort();
    println!(
        "PROBE fault={fault:?} capture_ok={} drain_ok={} elapsed_total={:?}",
        capture_result.is_ok(),
        drain_result.is_ok(),
        t0.elapsed()
    );
    let h = capture_result.unwrap();
    let (held, first_admission, first_start, first_end, windows, missed) = drain_result.unwrap();
    assert!(held > 0);
    assert!(capture_started <= first_admission && first_admission <= first_start);
    assert!(first_start < first_end && first_end <= capture_finished);
    assert!(first_end.duration_since(first_start) >= Duration::from_millis(5));
    assert_eq!(h.locally_queued, h.observed);
    let log = log.lock().unwrap().clone();
    let first = &log[0];
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    let rel = |t: Instant| ms(t.duration_since(capture_started));
    // Which admissions overlapped which writer windows, and which waited.
    let waited: Vec<usize> = (0..log.len())
        .filter(|&i| !log[i].spent.is_zero())
        .collect();
    let overlapping_later = windows[1..]
        .iter()
        .filter(|(ws, we)| log.iter().any(|a| a.start < *we && a.end > *ws))
        .count();
    let waited_later = windows[1..]
        .iter()
        .filter(|(ws, we)| {
            log.iter()
                .any(|a| !a.spent.is_zero() && a.start < *we && a.end > *ws)
        })
        .count();
    println!(
        "PROBE first_admission: caller_wait={:?} spent_ms={:.3} call_ms={:.3} ok={} start_rel_ms={:.3} window_rel_ms=[{:.3},{:.3}] admission_started_inside_window={}",
        first.caller_wait,
        ms(first.spent),
        ms(first.end.duration_since(first.start)),
        first.ok,
        rel(first.start),
        rel(first_start),
        rel(first_end),
        first.start >= first_start && first.start < first_end
    );
    // Proposed strengthening: the coordinated window must make production
    // capture actually wait, witnessed by the spent value it returns.
    assert!(
        !first.spent.is_zero(),
        "first admission must wait on the coordinated writer lock: {first:?}"
    );
    println!(
        "PROBE totals: admissions={} observed={} queued={} unconfirmed={} windows={} missed_attempts={} admissions_with_spent>0={:?} later_windows_overlapping_an_admission={} later_windows_with_a_waiting_admission={} total_spent_ms={:.3}",
        log.len(),
        h.observed,
        h.locally_queued,
        h.unconfirmed,
        held,
        missed,
        waited,
        overlapping_later,
        waited_later,
        ms(log.iter().map(|a| a.spent).sum())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_p4_faithful_first_admission_wait() {
    p4(Fault::None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_p4_capture_panics_before_admission() {
    p4(Fault::PanicBeforeAdmission).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_p4_capture_panics_after_forward() {
    p4(Fault::PanicAfterCapture).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_p4_first_window_without_lock_is_detected() {
    p4(Fault::FirstWindowNoLock).await;
}
