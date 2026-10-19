#![cfg(feature = "v2-crypto")]
//! Review-only black-box probes of the Library connection queue (a8cbf21).
//! Copied temporarily into tests/ by the reviewer and removed afterwards.
use kan::evidence_reader::{Reader, ScopeAccess};
use kan::sign::Identity;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn server() -> (std::net::SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
    // GET / needs no remote call, so an unreachable endpoint is fine.
    let reader = Reader::new(
        Identity::generate(),
        vec![ScopeAccess {
            scope: [7; 32],
            endpoint: "http://127.0.0.1:9/v1/rpc".into(),
            issuer: Identity::generate().did().to_string(),
            private_key: [3; 32],
        }],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(kan::evidence_library::serve(
        listener,
        "synthetic-review-queue-token-0032".into(),
        reader,
    ));
    (addr, handle)
}

async fn idle(addr: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    s
}

/// Seconds until the server closes this socket (EOF/reset), or None within `limit`.
async fn closed_after(mut s: TcpStream, start: Instant, limit: Duration) -> Option<f64> {
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(limit.saturating_sub(start.elapsed()), s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(start.elapsed().as_secs_f64()),
            Ok(Ok(_)) => continue,
            Err(_) => return None,
        }
    }
}

async fn get(addr: std::net::SocketAddr) -> (f64, String) {
    let start = Instant::now();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let _ = s
        .write_all(format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(40), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out);
    let status = text.lines().next().unwrap_or("<closed without response>").to_string();
    (start.elapsed().as_secs_f64(), status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_p1_fifth_request_latency_behind_four_idle() {
    let (addr, h) = server().await;
    let mut held = Vec::new();
    for _ in 0..4 { held.push(idle(addr).await); }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (t, status) = get(addr).await;
    println!("P1 fifth GET behind 4 idle: {t:.2}s status={status}");
    drop(held);
    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_p1b_fifth_request_without_settle() {
    // Same as P1 but with no settle interval: does ordering still hold?
    let (addr, h) = server().await;
    let mut held = Vec::new();
    for _ in 0..4 { held.push(idle(addr).await); }
    let (t, status) = get(addr).await;
    println!("P1b fifth GET behind 4 idle, no settle: {t:.2}s status={status}");
    drop(held);
    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_p2_thirteenth_connection_behind_twelve_idle() {
    let (addr, h) = server().await;
    let mut held = Vec::new();
    for _ in 0..12 { held.push(idle(addr).await); }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (t, status) = get(addr).await;
    println!("P2 13th GET behind 12 idle: {t:.2}s status={status}");
    drop(held);
    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_p3_per_socket_close_times_for_twelve_idle() {
    let (addr, h) = server().await;
    let start = Instant::now();
    let mut held = Vec::new();
    for _ in 0..12 { held.push(idle(addr).await); tokio::time::sleep(Duration::from_millis(5)).await; }
    let waits: Vec<_> = held
        .into_iter()
        .map(|s| tokio::spawn(closed_after(s, start, Duration::from_secs(40))))
        .collect();
    let mut times = Vec::new();
    for w in waits { times.push(w.await.unwrap()); }
    let fmt: Vec<String> = times.iter().map(|t| t.map_or("open@40s".into(), |t| format!("{t:.2}"))).collect();
    println!("P3 close times (s) for idle sockets 1..12: {}", fmt.join(" "));
    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_p4_queued_request_served_after_queue_drains() {
    // 12 idle sockets: 4 execute, 8 queue. A legitimate request arriving at
    // ~5.5s (after the first four time out) should be accepted and queued.
    let (addr, h) = server().await;
    let mut held = Vec::new();
    for _ in 0..12 { held.push(idle(addr).await); }
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let (t, status) = get(addr).await;
    println!("P4 GET at 5.5s behind 12 idle: +{t:.2}s status={status}");
    drop(held);
    h.abort();
}
