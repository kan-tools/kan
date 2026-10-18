#![cfg(feature = "v2-crypto")]
//! Retained third-review deadline probes; now compiled into CI.
use kan::evidence_capture::{self as capture, Health, Outcome, Route, Sink, Unconfirmed};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

struct Script {
    url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Script {
    fn drop(&mut self) {
        self.task.abort();
    }
}
/// Chunked response: each piece written after `gap`.
async fn drip(pieces: Vec<Vec<u8>>, gap: Duration) -> Script {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let pieces = pieces.clone();
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
                for p in pieces {
                    tokio::time::sleep(gap).await;
                    let mut w = format!("{:x}\r\n", p.len()).into_bytes();
                    w.extend(&p);
                    w.extend(b"\r\n");
                    if s.write_all(&w).await.is_err() {
                        return;
                    }
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    Script { url, calls, task }
}

struct Slow(Duration, usize);
impl Sink for Slow {
    fn admit(&mut self, _: &[u8; 16], _: &[u8]) -> Result<(), Unconfirmed> {
        self.1 += 1;
        std::thread::sleep(self.0);
        Err(Unconfirmed)
    }
}
#[derive(Default)]
struct Ok_(usize);
impl Sink for Ok_ {
    fn admit(&mut self, _: &[u8; 16], _: &[u8]) -> Result<(), Unconfirmed> {
        self.0 += 1;
        Ok(())
    }
}

async fn go(
    url: &str,
    sink: &mut dyn Sink,
    budget: Duration,
) -> (
    Result<Health, capture::Error>,
    Vec<u8>,
    Vec<Health>,
    Duration,
) {
    let mut states = Vec::new();
    let mut out = Vec::new();
    let t = Instant::now();
    let r = capture::forward(
        &Route::new(url).unwrap(),
        vec![7],
        sink,
        &mut |h| states.push(h.clone()),
        &mut out,
        budget,
    )
    .await;
    (r, out, states, t.elapsed())
}

/// Provider slow-drip: each read well under budget, cumulative over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r3_provider_drip_exhausts_cumulative_budget() {
    let p = drip(vec![b"ab".to_vec(); 8], Duration::from_millis(60)).await;
    let mut sink = Ok_::default();
    let (r, out, states, el) = go(&p.url, &mut sink, Duration::from_millis(200)).await;
    println!("R3-DRIP: err={} out={:?} elapsed={el:?}", r.is_err(), out);
    assert!(r.is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
    assert!(out.len() < 16 && !out.is_empty());
    assert!(el < Duration::from_millis(600));
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

/// Control: same drip, ample budget, completes exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r3_provider_drip_completes_with_ample_budget() {
    let p = drip(vec![b"ab".to_vec(); 8], Duration::from_millis(60)).await;
    let mut sink = Ok_::default();
    let (r, out, _, _) = go(&p.url, &mut sink, Duration::from_secs(5)).await;
    assert_eq!(r.unwrap().outcome, Some(Outcome::Completed));
    assert_eq!(out, b"ab".repeat(8));
}

/// Admission (all failing, 150 ms each, many chunks) far exceeds budget,
/// I/O alone is far under: must complete, all visible gaps, one call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r3_many_chunk_slow_admission_completes() {
    let p = drip(vec![b"xy".to_vec(); 10], Duration::from_millis(1)).await;
    let mut sink = Slow(Duration::from_millis(150), 0);
    let (r, out, states, el) = go(&p.url, &mut sink, Duration::from_millis(120)).await;
    println!("R3-SLOWADMIT: elapsed={el:?} admits={}", sink.1);
    let h = r.unwrap();
    assert!(el > Duration::from_millis(1500));
    assert_eq!(out, b"xy".repeat(10));
    assert_eq!(h.outcome, Some(Outcome::Completed));
    assert!(h.recording_gap && h.unconfirmed == h.observed && h.locally_queued == 0);
    assert!(states.iter().all(|s| s.locally_queued == 0));
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

/// Admission latency does not refill the budget: slow admission plus
/// cumulative I/O over budget must still be unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r3_slow_admission_does_not_mask_slow_io() {
    // Overlap: provider wall time hidden behind admission is not awaited I/O.
    let p0 = drip(vec![b"q".to_vec(); 6], Duration::from_millis(70)).await;
    let mut s0 = Slow(Duration::from_millis(100), 0);
    let (r0, o0, _, _) = go(&p0.url, &mut s0, Duration::from_millis(200)).await;
    println!("R3-OVERLAP: err={} out={:?}", r0.is_err(), o0);
    assert!(r0.is_ok());
    let p = drip(vec![b"q".to_vec(); 4], Duration::from_millis(250)).await;
    let mut sink = Slow(Duration::from_millis(100), 0);
    let (r, _, states, _) = go(&p.url, &mut sink, Duration::from_millis(200)).await;
    assert!(r.is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

/// Output whose write blocks synchronously longer than the whole budget but
/// then succeeds (timeout polls inner first). Records how the boundary behaves.
struct BlockingOut(Vec<u8>, Duration);
impl AsyncWrite for BlockingOut {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::thread::sleep(self.1);
        self.0.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r3_boundary_blocking_output_observation() {
    let p = drip(vec![b"z".to_vec()], Duration::from_millis(1)).await;
    let mut sink = Ok_::default();
    let mut out = BlockingOut(Vec::new(), Duration::from_millis(300));
    let mut states = Vec::new();
    let r = capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![],
        &mut sink,
        &mut |h| states.push(h.clone()),
        &mut out,
        Duration::from_millis(200),
    )
    .await;
    println!(
        "R3-BOUNDARY: err={} delivered={:?} outcome={:?}",
        r.is_err(),
        out.0,
        states.last().unwrap().outcome
    );
    // Bytes reached the sink, but the I/O budget was exceeded: unknown, not completed.
    assert_eq!(out.0, b"z");
    assert!(r.is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
}

struct BlockingFlush(Vec<u8>);
impl AsyncWrite for BlockingFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::thread::sleep(Duration::from_millis(300));
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_final_flush_over_budget_is_unknown() {
    let p = drip(vec![b"z".to_vec()], Duration::from_millis(1)).await;
    let mut sink = Ok_::default();
    let mut out = BlockingFlush(Vec::new());
    let mut states = Vec::new();
    let result = capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![],
        &mut sink,
        &mut |h| states.push(h.clone()),
        &mut out,
        Duration::from_millis(200),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(out.0, b"z");
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
}
