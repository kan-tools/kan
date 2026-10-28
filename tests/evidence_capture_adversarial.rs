#![cfg(feature = "v2-crypto")]
//! Retained independent Opus review probes, with assertions strengthened after review.
use kan::{
    evidence_capture::{self as capture, Event, Header, Health, Outcome, Route, Sink, Unconfirmed},
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_service::{hex, Command, SignedRequest},
    evidence_spool::Spool,
    sign::Identity,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const SCOPE: [u8; 32] = [17; 32];
const PRIVATE: [u8; 32] = [73; 32];
fn oracle_python() -> String {
    std::env::var("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into())
}

#[derive(Default)]
struct Memory {
    frames: Vec<Vec<u8>>,
}
impl Sink for Memory {
    fn admit(&mut self, _: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        self.frames.push(frame.to_vec());
        Ok(())
    }
}
fn decode(bytes: &[u8]) -> (Header, Vec<u8>) {
    let n = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    (
        serde_json::from_slice(&bytes[9..9 + n]).unwrap(),
        bytes[9 + n..].to_vec(),
    )
}
fn response_body(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        let (h, b) = decode(f);
        if let Event::ResponseChunk { .. } = h.event {
            out.extend(b);
        }
    }
    out
}

/// Accepts any number of connections; for each, reads request head + body and
/// writes `raw` then optionally hangs before closing.
struct Raw {
    url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn raw(raw: Vec<u8>, hang: Duration, read_body: bool) -> Raw {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let raw = raw.clone();
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
                if read_body {
                    let mut b = vec![0; len];
                    let _ = s.read_exact(&mut b).await;
                }
                let _ = s.write_all(&raw).await;
                tokio::time::sleep(hang).await;
            });
        }
    });
    Raw { url, calls, task }
}

fn spool(root: &std::path::Path, writer: &Identity, budget: u64) -> std::path::PathBuf {
    let server = Identity::generate();
    let path = root.join("spool");
    drop(
        Spool::create(
            &path,
            &hex(&SCOPE),
            &writer.did().to_string(),
            &server.did().to_string(),
            budget,
        )
        .unwrap(),
    );
    path
}
fn pending(path: &std::path::Path) -> Vec<Vec<u8>> {
    drop(Spool::open(path).unwrap());
    let conn = rusqlite::Connection::open(path).unwrap();
    let rows = conn
        .prepare("SELECT request FROM pending ORDER BY position")
        .unwrap()
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows
}
fn cli(args: &[&str]) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"));
    c.arg("capture-post").args(args).kill_on_drop(true);
    c
}

/// Independent oracle: real CLI + real encrypted spool, decrypted and parsed in
/// Python/OpenSSL. Also checks no decompression with a Content-Encoding header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_oracle_decrypts_cli_spool_frames() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let spool_path = spool(dir.path(), &writer, 64 * 1024 * 1024);
    let request: Vec<u8> = (0..200_003u32).map(|i| (i * 7 % 256) as u8).collect();
    let response: Vec<u8> = (0..300_007u32).map(|i| (i * 13 % 253) as u8).collect();
    let mut wire = format!(
        "HTTP/1.1 202 X\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )
    .into_bytes();
    wire.extend(&response);
    let p = raw(wire, Duration::ZERO, true).await;
    let mut child = cli(&[
        "--endpoint",
        &p.url,
        "--spool",
        spool_path.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--recipient",
        &hex(&crypto::public_key(&PRIVATE).unwrap()),
        "--deadline-seconds",
        "20",
    ])
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request)
        .await
        .unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, response, "stdout must be raw undecoded body");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    let fx = dir.path().join("fx");
    std::fs::create_dir(&fx).unwrap();
    for (i, bytes) in pending(&spool_path).iter().enumerate() {
        let signed = SignedRequest::decode(bytes).unwrap();
        let Command::Append { id, ciphertext, .. } = signed.request.command else {
            panic!("non-append")
        };
        std::fs::write(fx.join(format!("{i}.ct")), hex_decode(&ciphertext)).unwrap();
        std::fs::write(fx.join(format!("{i}.op")), id).unwrap();
    }
    std::fs::write(fx.join("private"), PRIVATE).unwrap();
    std::fs::write(fx.join("scope"), SCOPE).unwrap();
    std::fs::write(fx.join("route"), &p.url).unwrap();
    std::fs::write(fx.join("status"), "202").unwrap();
    std::fs::write(fx.join("request"), &request).unwrap();
    std::fs::write(fx.join("response"), &response).unwrap();
    let decoder = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/verify_encrypted_capture.py"
    );
    let oracle = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/verify_archive_encryption.py"
    );
    let run = std::process::Command::new(oracle_python())
        .args(["-I", decoder, oracle])
        .arg(&fx)
        .output()
        .unwrap();
    println!(
        "ORACLE: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.status.success());
    // tamper: oracle must reject a modified route expectation
    std::fs::write(fx.join("route"), "http://127.0.0.1:1/fixed").unwrap();
    let bad = std::process::Command::new(oracle_python())
        .args(["-I", decoder, oracle])
        .arg(&fx)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Design: "invalid keys/route/input fail before network". A key that is not the
/// spool's writer is checkable before forwarding; observe what happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_cli_key_not_spool_writer() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let other = Identity::generate();
    let key = dir.path().join("key");
    other.save(&key).unwrap();
    let spool_path = spool(dir.path(), &writer, 1024 * 1024);
    let p = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let out = cli(&[
        "--endpoint",
        &p.url,
        "--spool",
        spool_path.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--recipient",
        &hex(&crypto::public_key(&PRIVATE).unwrap()),
    ])
    .stdin(std::process::Stdio::null())
    .output()
    .await
    .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    assert!(pending(&spool_path).is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not match spool writer"));
}

/// Content-Length promised 100, 10 delivered then close.
#[tokio::test]
async fn probe_short_content_length_is_unknown() {
    let p = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 100\r\nConnection: close\r\n\r\n0123456789".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let mut m = Memory::default();
    let mut states: Vec<Health> = Vec::new();
    let mut out = Vec::new();
    let r = capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![1],
        &mut m,
        &mut |h| states.push(h.clone()),
        &mut out,
        Duration::from_secs(5),
    )
    .await;
    println!(
        "SHORT-CL: err={} outcome={:?} out={:?} captured={:?}",
        r.is_err(),
        states.last().unwrap().outcome,
        out,
        response_body(&m.frames)
    );
    assert!(r.is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
}

/// Drop the future after the head and a prefix were observed.
#[tokio::test]
async fn probe_drop_mid_stream() {
    let p = raw(
        b"HTTP/1.1 200 X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n"
            .to_vec(),
        Duration::from_secs(10),
        true,
    )
    .await;
    let mut m = Memory::default();
    let mut states: Vec<Health> = Vec::new();
    let mut out = Vec::new();
    {
        let route = Route::new(&p.url).unwrap();
        let mut notify = |h: &Health| states.push(h.clone());
        let f = capture::forward(
            &route,
            vec![1],
            &mut m,
            &mut notify,
            &mut out,
            Duration::from_secs(30),
        );
        assert!(tokio::time::timeout(Duration::from_millis(500), f)
            .await
            .is_err());
    }
    let terminals: Vec<_> = m
        .frames
        .iter()
        .filter_map(|f| match decode(f).0.event {
            Event::Terminal { outcome } => Some(outcome),
            _ => None,
        })
        .collect();
    println!(
        "DROP-MID: out={:?} captured={:?} terminals={:?}",
        out,
        response_body(&m.frames),
        terminals
    );
    assert_eq!(response_body(&m.frames), b"hello");
    assert_eq!(terminals, vec![Outcome::OutcomeUnknown]);
}

/// Health/stderr must not echo payload canaries, on success and on failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_cli_stderr_has_no_payload() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    for close_early in [false, true] {
        let body = b"RESPCANARY-4411".to_vec();
        let wire = if close_early {
            b"HTTP/1.1 200 X\r\nContent-Length: 999\r\nConnection: close\r\n\r\nRESPCANARY-4411"
                .to_vec()
        } else {
            let mut w = format!(
                "HTTP/1.1 200 X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            w.extend(&body);
            w
        };
        let p = raw(wire, Duration::ZERO, true).await;
        let mut child = cli(&[
            "--endpoint",
            &p.url,
            "--spool",
            dir.path().join("absent").to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"REQCANARY-9921")
            .await
            .unwrap();
        let out = child.wait_with_output().await.unwrap();
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        println!(
            "STDERR(close_early={close_early}) exit={:?} last={}",
            out.status.code(),
            err.lines().last().unwrap_or("")
        );
        assert!(!err.contains("CANARY") && !err.contains("127.0.0.1"));
        assert_eq!(out.status.success(), !close_early);
    }
}

/// Pre-network failures: oversize stdin, bad recipient, bad route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_cli_prenetwork_failures() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let p = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let good = hex(&crypto::public_key(&PRIVATE).unwrap());
    for (name, endpoint, recipient, size) in [
        (
            "oversize",
            p.url.as_str(),
            good.as_str(),
            capture::MAX_REQUEST + 1,
        ),
        ("bad-recipient", p.url.as_str(), "zz", 1),
        ("bad-route", "http://example.org/", good.as_str(), 1),
    ] {
        let mut child = cli(&[
            "--endpoint",
            endpoint,
            "--spool",
            dir.path().join("absent").to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            recipient,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(&vec![0; size]).await;
        drop(stdin);
        let out = child.wait_with_output().await.unwrap();
        println!(
            "PRENET {name}: exit={:?} health_lines={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .filter(|l| l.starts_with('{'))
                .count(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        assert!(!out.status.success());
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

/// Closed stdout (EPIPE) -> nonzero, and spool's last event is unknown terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_cli_closed_stdout_records_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let spool_path = spool(dir.path(), &writer, 64 * 1024 * 1024);
    let body = vec![5u8; 1024 * 1024];
    let mut wire = format!(
        "HTTP/1.1 200 X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(&body);
    let p = raw(wire, Duration::ZERO, true).await;
    let mut child = cli(&[
        "--endpoint",
        &p.url,
        "--spool",
        spool_path.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--recipient",
        &hex(&crypto::public_key(&PRIVATE).unwrap()),
        "--deadline-seconds",
        "10",
    ])
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::null())
    .spawn()
    .unwrap();
    drop(child.stdout.take());
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    let frames: Vec<Header> = pending(&spool_path)
        .iter()
        .map(|r| {
            decode(
                &delivery::decrypt_request(r, &PRIVATE, &SCOPE, &writer.did().to_string()).unwrap(),
            )
            .0
        })
        .collect();
    let last = &frames.last().unwrap().event;
    println!(
        "EPIPE: exit={:?} frames={} last={:?}",
        status.code(),
        frames.len(),
        last
    );
    assert!(!status.success());
    assert!(matches!(
        last,
        Event::Terminal {
            outcome: Outcome::OutcomeUnknown
        }
    ));
}

/// Ambient proxy env must not divert the configured route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_cli_ignores_ambient_proxy_env() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let p = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let proxy = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let proxy_url = proxy.url.trim_end_matches("/fixed").to_string();
    let out = cli(&[
        "--endpoint",
        &p.url,
        "--spool",
        dir.path().join("absent").to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--recipient",
        &hex(&crypto::public_key(&PRIVATE).unwrap()),
    ])
    .env("HTTP_PROXY", &proxy_url)
    .env("http_proxy", &proxy_url)
    .env("ALL_PROXY", &proxy_url)
    .env_remove("NO_PROXY")
    .env_remove("no_proxy")
    .stdin(std::process::Stdio::null())
    .output()
    .await
    .unwrap();
    println!(
        "PROXY: stdout={:?} provider={} proxy={}",
        String::from_utf8_lossy(&out.stdout),
        p.calls.load(Ordering::SeqCst),
        proxy.calls.load(Ordering::SeqCst)
    );
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 0);
    assert_eq!(out.stdout, b"ok");
}

#[test]
fn probe_route_normalized_length() {
    let grow = format!("https://example.org/{}", "a ".repeat(800));
    println!(
        "ROUTE2 raw={} normalized_ok={}",
        grow.len(),
        Route::new(&grow).is_ok()
    );
    assert!(Route::new(&grow).is_err());
}

/// Observer attribution and both clocks are raw observations, not inferred from
/// later remote arrival. Decode JSON so full production reversion still compiles.
#[test]
fn observer_and_capture_clocks_are_retained() {
    use capture::{Observer, Recorder};
    use std::time::{SystemTime, UNIX_EPOCH};
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    for observer in [Observer::Collector, Observer::Gateway] {
        let mut memory = Memory::default();
        let mut notify = |_: &Health| {};
        {
            let mut recorder = Recorder::new(observer, &mut memory, &mut notify).unwrap();
            recorder
                .record(Event::RequestChunk { offset: 0 }, b"first")
                .unwrap();
            std::thread::sleep(Duration::from_millis(5));
            recorder
                .record(Event::RequestChunk { offset: 5 }, b"second")
                .unwrap();
            recorder
                .record(
                    Event::Terminal {
                        outcome: Outcome::Completed,
                    },
                    &[],
                )
                .unwrap();
        }
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let mut previous = 0;
        let mut previous_wall = 0;
        for (i, frame) in memory.frames.iter().enumerate() {
            let n = u32::from_be_bytes(frame[5..9].try_into().unwrap()) as usize;
            let h: serde_json::Value = serde_json::from_slice(&frame[9..9 + n]).unwrap();
            assert_eq!(h["observer"], serde_json::to_value(observer).unwrap());
            let wall = h["observed_at_unix_micros"]
                .as_u64()
                .expect("wall capture time must exist on this host");
            assert!((before..=after).contains(&wall));
            if i == 1 {
                assert!(
                    wall >= previous_wall + 1000,
                    "sample wall time on each observation"
                );
            }
            previous_wall = wall;
            let elapsed = h["elapsed_micros"]
                .as_u64()
                .expect("monotonic elapsed time");
            assert!(elapsed >= previous);
            if i == 1 {
                assert!(elapsed - previous >= 1000, "elapsed clock must advance");
            }
            previous = elapsed;
        }
    }
}

#[test]
fn route_matrix_has_explicit_expected_decisions() {
    for endpoint in [
        "http://127.1/x",
        "http://127.0.0.1./x",
        "http://2130706433/x",
        "http://[::1]:9/x",
        "HTTP://127.0.0.1/x",
        "https://example.org/a%2F..%2Fb",
    ] {
        assert!(Route::new(endpoint).is_ok(), "{endpoint}");
    }
    for endpoint in [
        "http://[::ffff:127.0.0.1]/x",
        "http://0.0.0.0/x",
        "https://example.org/?",
        "https://example.org/#",
        "https://:p@example.org/",
        "https://u@example.org/",
        "unix:///tmp/sock",
    ] {
        assert!(Route::new(endpoint).is_err(), "{endpoint}");
    }
}

/// A server that will keep connections alive exposes pooling directly. Ordinary
/// servers closing after one response cannot witness this client policy.
#[tokio::test]
async fn reused_route_never_reuses_a_pooled_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            handlers.spawn(async move {
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                        assert!(head.len() < 16384);
                    }
                    // Both calls deliberately use empty bodies.
                    if stream
                        .write_all(b"HTTP/1.1 200 X\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let guard = Raw {
        url: url.clone(),
        calls: count.clone(),
        task,
    };
    let route = Route::new(&url).unwrap();
    for _ in 0..2 {
        let mut output = Vec::new();
        capture::forward(
            &route,
            vec![],
            &mut Memory::default(),
            &mut |_| {},
            &mut output,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(output, b"ok");
        tokio::task::yield_now().await;
    }
    assert_eq!(
        guard.calls.load(Ordering::SeqCst),
        2,
        "each attempt needs a fresh connection"
    );
}

/// Retain the second reviewer's actual SQLite-lock reproduction. A failed
/// admission remains a visible gap, not a failed fully delivered inference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_spool_cli_keeps_completed_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let spool_path = spool(dir.path(), &writer, 1024 * 1024);
    let lock = rusqlite::Connection::open(&spool_path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let p = raw(
        b"HTTP/1.1 200 X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        Duration::ZERO,
        true,
    )
    .await;
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        cli(&[
            "--endpoint",
            &p.url,
            "--spool",
            spool_path.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--deadline-seconds",
            "1",
        ])
        .stdin(std::process::Stdio::null())
        .output(),
    )
    .await
    .unwrap()
    .unwrap();
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ok");
    let text = String::from_utf8(output.stderr).unwrap();
    let health: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(health["outcome"], "completed");
    assert_eq!(health["recording_gap"], true);
    assert_eq!(health["locally_queued"], 0);
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}
