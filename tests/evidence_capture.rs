#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{
        self as capture, EncryptedSpool, Event, Header, Health, Observer, Outcome, Recorder, Route,
        Sink, Unconfirmed, CHUNK,
    },
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_service::{hex, Grant, Service},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    collections::HashSet,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
const SCOPE: [u8; 32] = [17; 32];
const PRIVATE: [u8; 32] = [73; 32];
const WAIT: Duration = Duration::from_secs(15);
#[derive(Default)]
struct Memory {
    frames: Vec<([u8; 16], Vec<u8>)>,
    calls: usize,
    reject: Vec<usize>,
}
impl Sink for Memory {
    fn admit(&mut self, op: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        self.calls += 1;
        if self.reject.contains(&self.calls) {
            return Err(Unconfirmed);
        }
        self.frames.push((*op, frame.to_vec()));
        Ok(())
    }
}
fn decode(bytes: &[u8]) -> (Header, &[u8]) {
    assert_eq!(&bytes[..5], b"KANC2");
    let n = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    (
        serde_json::from_slice(&bytes[9..9 + n]).unwrap(),
        &bytes[9 + n..],
    )
}
fn bodies(frames: &[([u8; 16], Vec<u8>)]) -> (Vec<u8>, Vec<u8>) {
    let (mut request, mut response) = (Vec::new(), Vec::new());
    for (_, bytes) in frames {
        let (h, b) = decode(bytes);
        match h.event {
            Event::RequestChunk { offset } => {
                assert_eq!(offset, request.len() as u64);
                request.extend(b);
            }
            Event::ResponseChunk { offset } => {
                assert_eq!(offset, response.len() as u64);
                response.extend(b);
            }
            _ => assert!(b.is_empty()),
        }
    }
    (request, response)
}
struct Provider {
    url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<Vec<u8>>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn provider(
    status: u16,
    headers: String,
    chunks: Vec<Vec<u8>>,
    finish: bool,
    delay: Duration,
) -> Provider {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        count.fetch_add(1, Ordering::SeqCst);
        let mut incoming = Vec::new();
        let mut one = [0; 1];
        while !incoming.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut one).await.unwrap();
            incoming.push(one[0]);
            assert!(incoming.len() < 16384);
        }
        let text = String::from_utf8(incoming).unwrap();
        assert!(text.starts_with("POST /fixed HTTP/1.1\r\n"));
        let len = text
            .lines()
            .find_map(|s| {
                s.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|s| s.parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut request = vec![0; len];
        stream.read_exact(&mut request).await.unwrap();
        tokio::time::sleep(delay).await;
        if stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n{headers}\r\n").as_bytes()).await.is_err() { return request; }
        for chunk in chunks {
            if stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .is_err()
            {
                return request;
            }
            if stream.write_all(&chunk).await.is_err() {
                return request;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                return request;
            }
        }
        if finish {
            let _ = stream.write_all(b"0\r\n\r\n").await;
        }
        request
    });
    Provider { url, calls, task }
}
fn spool(root: &std::path::Path, writer: &Identity, server: &Identity, budget: u64) -> Spool {
    Spool::create(
        &root.join("spool"),
        &hex(&SCOPE),
        &writer.did().to_string(),
        &server.did().to_string(),
        budget,
    )
    .unwrap()
}

#[tokio::test]
async fn binary_stream_above_ten_mib_has_exact_bodies_and_independent_frames() {
    let body: Vec<u8> = (0..11 * 1024 * 1024 + 7).map(|i| (i % 251) as u8).collect();
    let request = b"opaque\0\xff prompt: redirect to http://evil.invalid".to_vec();
    let mut p = provider(
        201,
        String::new(),
        body.chunks(17003).map(|c| c.to_vec()).collect(),
        true,
        Duration::ZERO,
    )
    .await;
    let mut sink = Memory::default();
    let mut health = Vec::new();
    let mut out = Vec::new();
    let h = capture::forward(
        &Route::new(&p.url).unwrap(),
        request.clone(),
        &mut sink,
        &mut |h| health.push(h.clone()),
        &mut out,
        WAIT,
    )
    .await
    .unwrap();
    assert_eq!(out, body);
    assert_eq!(h.outcome, Some(Outcome::Completed));
    assert_eq!(h.status, Some(201));
    assert_eq!(h.unconfirmed, 0);
    assert!(!h.remote_acknowledged);
    assert_eq!(bodies(&sink.frames), (request.clone(), body.clone()));
    assert_eq!(
        tokio::time::timeout(WAIT, &mut p.task)
            .await
            .unwrap()
            .unwrap(),
        request
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    for (i, (_, f)) in sink.frames.iter().enumerate() {
        let (h, b) = decode(f);
        assert_eq!(h.ordinal, i as u64);
        assert_eq!(h.observer, Observer::Gateway);
        assert!(b.len() <= CHUNK);
    }
    let dir = tempfile::tempdir().unwrap();
    for (i, (op, f)) in sink.frames.iter().enumerate() {
        std::fs::write(dir.path().join(format!("{i}.bin")), f).unwrap();
        std::fs::write(dir.path().join(format!("{i}.op")), hex(op)).unwrap();
    }
    std::fs::write(dir.path().join("request"), &request).unwrap();
    std::fs::write(dir.path().join("response"), &body).unwrap();
    let run = std::process::Command::new("python3")
        .args(["-I", "scripts/verify_capture_frames.py"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let mut damaged = sink.frames[1].1.clone();
    *damaged.last_mut().unwrap() ^= 1;
    std::fs::write(dir.path().join("1.bin"), damaged).unwrap();
    assert!(!std::process::Command::new("python3")
        .args(["-I", "scripts/verify_capture_frames.py"])
        .arg(dir.path())
        .output()
        .unwrap()
        .status
        .success());
}

#[tokio::test]
async fn encrypted_spool_reopens_drains_only_evidence_and_contains_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    let mut queue = spool(dir.path(), &writer, &server, 16 * 1024 * 1024);
    let request = b"private-capture-canary-875\0\xff".to_vec();
    let response = b"response-canary-875\0\xff".to_vec();
    let p = provider(
        200,
        String::new(),
        vec![response.clone()],
        true,
        Duration::ZERO,
    )
    .await;
    let mut out = Vec::new();
    let h = capture::forward(
        &Route::new(&p.url).unwrap(),
        request.clone(),
        &mut EncryptedSpool {
            spool: Some(&mut queue),
            signer: &writer,
            recipient: crypto::public_key(&PRIVATE).unwrap(),
        },
        &mut |_| {},
        &mut out,
        WAIT,
    )
    .await
    .unwrap();
    assert_eq!(h.unconfirmed, 0);
    drop(queue);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(20).any(|w| w == &request[..20]));
    }
    let mut queue = Spool::open(&dir.path().join("spool")).unwrap();
    let ledger = Ledger::create(&dir.path().join("archive")).unwrap();
    let mut service = Service::new(
        ledger,
        SCOPE,
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: true,
        }],
    )
    .unwrap();
    let mut frames = Vec::new();
    while let Some(bytes) = queue.head().unwrap() {
        let plain =
            delivery::decrypt_request(&bytes, &PRIVATE, &SCOPE, &writer.did().to_string()).unwrap();
        frames.push(([0; 16], plain));
        let reply = service.dispatch(&bytes, 0).unwrap().bytes().unwrap();
        queue.acknowledge(&reply).unwrap();
    }
    assert_eq!(frames.len() as u64, h.observed);
    assert_eq!(bodies(&frames), (request, response));
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    assert_eq!(out, bodies(&frames).1);
}

#[tokio::test]
async fn full_and_unavailable_capture_continue_with_visible_gap() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    let mut queue = spool(dir.path(), &writer, &server, 1);
    for present in [true, false] {
        let p = provider(
            503,
            String::new(),
            vec![b"provider unavailable\0\xff".to_vec()],
            true,
            Duration::ZERO,
        )
        .await;
        let mut states = Vec::new();
        let mut out = Vec::new();
        let h = capture::forward(
            &Route::new(&p.url).unwrap(),
            b"request".to_vec(),
            &mut EncryptedSpool {
                spool: if present { Some(&mut queue) } else { None },
                signer: &writer,
                recipient: crypto::public_key(&PRIVATE).unwrap(),
            },
            &mut |h| states.push(h.clone()),
            &mut out,
            WAIT,
        )
        .await
        .unwrap();
        assert_eq!(out, b"provider unavailable\0\xff");
        assert_eq!(h.status, Some(503));
        assert!(h.recording_gap);
        assert_eq!(h.locally_queued, 0);
        assert_eq!(h.unconfirmed, h.observed);
        assert!(states[1].recording_gap);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn resumed_capture_carries_gap_and_observers_attempts_have_distinct_ids() {
    let mut sink = Memory {
        reject: vec![1, 3],
        ..Default::default()
    };
    let mut states = Vec::new();
    {
        let mut notify = |h: &Health| states.push(h.clone());
        let mut r = Recorder::new(Observer::Collector, &mut sink, &mut notify).unwrap();
        r.record(Event::RequestChunk { offset: 0 }, b"a").unwrap();
        r.record(Event::RequestChunk { offset: 1 }, b"b").unwrap();
        r.record(Event::RequestEnd { bytes: 2 }, &[]).unwrap();
        r.record(
            Event::Terminal {
                outcome: Outcome::Completed,
            },
            &[],
        )
        .unwrap();
        assert!(r.record(Event::RequestEnd { bytes: 2 }, &[]).is_err());
    }
    assert_eq!(decode(&sink.frames[0].1).0.unconfirmed_before, 1);
    assert_eq!(decode(&sink.frames[1].1).0.unconfirmed_before, 2);
    for observer in [Observer::Gateway, Observer::Collector] {
        let mut notify = |_: &Health| {};
        let mut r = Recorder::new(observer, &mut sink, &mut notify).unwrap();
        r.record(Event::RequestEnd { bytes: 0 }, &[]).unwrap();
    }
    let ids: HashSet<_> = sink.frames.iter().map(|(op, _)| op).collect();
    assert_eq!(ids.len(), sink.frames.len());
    assert_eq!(states.last().unwrap().unconfirmed, 2);
}

#[tokio::test]
async fn redirect_is_observed_but_never_followed() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = provider(
        307,
        format!(
            "Location: http://{}/stolen\r\n",
            target.local_addr().unwrap()
        ),
        vec![b"redirect body".to_vec()],
        true,
        Duration::ZERO,
    )
    .await;
    let mut out = Vec::new();
    let h = capture::forward(
        &Route::new(&p.url).unwrap(),
        b"secret".to_vec(),
        &mut Memory::default(),
        &mut |_| {},
        &mut out,
        WAIT,
    )
    .await
    .unwrap();
    assert_eq!(h.status, Some(307));
    assert_eq!(out, b"redirect body");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disconnect_is_unknown_and_retains_observed_prefix() {
    let p = provider(
        200,
        String::new(),
        vec![b"observed prefix".to_vec()],
        false,
        Duration::ZERO,
    )
    .await;
    let mut memory = Memory::default();
    let mut states = Vec::new();
    let mut out = Vec::new();
    assert!(capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![1],
        &mut memory,
        &mut |h| states.push(h.clone()),
        &mut out,
        WAIT
    )
    .await
    .is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
    assert_eq!(bodies(&memory.frames).1, out);
    assert_eq!(out, b"observed prefix");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn deadline_and_dropped_future_record_unknown_without_retry() {
    for cancellation in [false, true] {
        let p = provider(
            200,
            String::new(),
            vec![b"late".to_vec()],
            true,
            Duration::from_secs(3),
        )
        .await;
        let mut states = Vec::new();
        let mut memory = Memory::default();
        let mut out = Vec::new();
        let route = Route::new(&p.url).unwrap();
        let mut notify = |h: &Health| states.push(h.clone());
        if cancellation {
            let f = capture::forward(&route, vec![1], &mut memory, &mut notify, &mut out, WAIT);
            assert!(tokio::time::timeout(Duration::from_millis(100), f)
                .await
                .is_err());
        } else {
            assert!(capture::forward(
                &route,
                vec![1],
                &mut memory,
                &mut notify,
                &mut out,
                Duration::from_millis(100)
            )
            .await
            .is_err());
        }
        assert_eq!(
            states.last().unwrap().outcome,
            Some(Outcome::OutcomeUnknown)
        );
        assert!(out.is_empty());
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            memory
                .frames
                .iter()
                .filter(|(_, f)| matches!(decode(f).0.event, Event::Terminal { .. }))
                .count(),
            1
        );
    }
}

struct FailingOutput;
impl AsyncWrite for FailingOutput {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("synthetic")))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn output_failure_and_backpressure_stop_reading() {
    for failure in [true, false] {
        let p = provider(
            200,
            String::new(),
            vec![vec![8; CHUNK * 16]],
            true,
            Duration::ZERO,
        )
        .await;
        let mut memory = Memory::default();
        let mut states = Vec::new();
        let (mut output, _unread) = tokio::io::duplex(1);
        let route = Route::new(&p.url).unwrap();
        let mut notify = |h: &Health| states.push(h.clone());
        let result = if failure {
            capture::forward(
                &route,
                vec![],
                &mut memory,
                &mut notify,
                &mut FailingOutput,
                WAIT,
            )
            .await
        } else {
            capture::forward(
                &route,
                vec![],
                &mut memory,
                &mut notify,
                &mut output,
                Duration::from_millis(100),
            )
            .await
        };
        assert!(result.is_err());
        assert_eq!(
            states.last().unwrap().outcome,
            Some(Outcome::OutcomeUnknown)
        );
        assert!(bodies(&memory.frames).1.len() <= CHUNK);
        assert!(!bodies(&memory.frames).1.is_empty());
    }
}

#[tokio::test]
async fn route_and_request_limits_refuse_before_provider() {
    for url in [
        "http://example.org/",
        "http://localhost/",
        "https://user:pass@example.org/",
        "https://example.org/?key=secret",
        "https://example.org/#f",
        "file:///etc/passwd",
    ] {
        assert!(Route::new(url).is_err(), "{url}");
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = Route::new(&format!("http://{}/fixed", listener.local_addr().unwrap())).unwrap();
    for (bytes, deadline) in [
        (vec![0; capture::MAX_REQUEST + 1], WAIT),
        (vec![], Duration::ZERO),
    ] {
        let mut sink = Memory::default();
        assert!(capture::forward(
            &route,
            bytes,
            &mut sink,
            &mut |_| {},
            &mut Vec::new(),
            deadline
        )
        .await
        .is_err());
        assert_eq!(sink.calls, 0);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_missing_spool_reports_gap_separately_from_binary_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Identity::generate();
    let key = dir.path().join("key");
    signer.save(&key).unwrap();
    let p = provider(
        429,
        String::new(),
        vec![b"raw\0\xff".to_vec()],
        true,
        Duration::ZERO,
    )
    .await;
    let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args([
            "capture-post",
            "--endpoint",
            &p.url,
            "--spool",
            dir.path().join("absent").to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--deadline-seconds",
            "5",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"raw\0\xff");
    let states: Vec<serde_json::Value> = result
        .stderr
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).unwrap())
        .collect();
    assert_eq!(states.last().unwrap()["recording_gap"], true);
    assert_eq!(states.last().unwrap()["status"], 429);
    assert!(!String::from_utf8_lossy(&result.stderr).contains(&p.url));
}

struct FlushFailure;
impl AsyncWrite for FlushFailure {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("synthetic flush")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn empty_body_still_requires_successful_output_flush() {
    let p = provider(204, String::new(), vec![], true, Duration::ZERO).await;
    let mut memory = Memory::default();
    let mut states = Vec::new();
    assert!(capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![],
        &mut memory,
        &mut |h| states.push(h.clone()),
        &mut FlushFailure,
        WAIT
    )
    .await
    .is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
}

#[tokio::test]
async fn maximum_request_is_chunked_and_sent_once() {
    let request = vec![39; capture::MAX_REQUEST];
    let mut p = provider(200, String::new(), vec![], true, Duration::ZERO).await;
    let mut memory = Memory::default();
    capture::forward(
        &Route::new(&p.url).unwrap(),
        request.clone(),
        &mut memory,
        &mut |_| {},
        &mut Vec::new(),
        WAIT,
    )
    .await
    .unwrap();
    assert_eq!(bodies(&memory.frames).0, request);
    assert_eq!(
        tokio::time::timeout(WAIT, &mut p.task)
            .await
            .unwrap()
            .unwrap(),
        request
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killed_cli_retains_intent_without_fabricating_terminal_completion() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    drop(spool(dir.path(), &writer, &server, 1024 * 1024));
    let p = provider(
        200,
        String::new(),
        vec![b"late".to_vec()],
        true,
        Duration::from_secs(10),
    )
    .await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args([
            "capture-post",
            "--endpoint",
            &p.url,
            "--spool",
            dir.path().join("spool").to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--deadline-seconds",
            "15",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while p.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let queue = Spool::open(&dir.path().join("spool")).unwrap();
    drop(queue);
    let conn = rusqlite::Connection::open(dir.path().join("spool")).unwrap();
    let frames: Vec<Vec<u8>> = conn
        .prepare("SELECT request FROM pending ORDER BY position")
        .unwrap()
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| {
            delivery::decrypt_request(&r.unwrap(), &PRIVATE, &SCOPE, &writer.did().to_string())
                .unwrap()
        })
        .collect();
    assert!(matches!(
        decode(frames.last().unwrap()).0.event,
        Event::ForwardingIntent
    ));
    assert!(!frames
        .iter()
        .any(|f| matches!(decode(f).0.event, Event::Terminal { .. })));
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_deadline_exits_even_when_stdout_pipe_is_not_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Identity::generate();
    let key = dir.path().join("key");
    signer.save(&key).unwrap();
    let p = provider(
        200,
        String::new(),
        vec![vec![11; 2 * 1024 * 1024]],
        true,
        Duration::ZERO,
    )
    .await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args([
            "capture-post",
            "--endpoint",
            &p.url,
            "--spool",
            dir.path().join("absent").to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--recipient",
            &hex(&crypto::public_key(&PRIVATE).unwrap()),
            "--deadline-seconds",
            "1",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _unread = child.stdout.take().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("CLI must exit after I/O deadline with unread stdout")
        .unwrap();
    assert!(!status.success());
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

struct SlowUnavailable;
impl Sink for SlowUnavailable {
    fn admit(&mut self, _: &[u8; 16], _: &[u8]) -> Result<(), Unconfirmed> {
        std::thread::sleep(Duration::from_millis(100));
        Err(Unconfirmed)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_latency_does_not_consume_provider_io_budget() {
    let p = provider(
        200,
        String::new(),
        vec![b"complete response".to_vec()],
        true,
        Duration::ZERO,
    )
    .await;
    let (mut output, mut reader) = tokio::io::duplex(1);
    let drain = tokio::spawn(async move {
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        received
    });
    let started = std::time::Instant::now();
    let result = capture::forward(
        &Route::new(&p.url).unwrap(),
        vec![1],
        &mut SlowUnavailable,
        &mut |_| {},
        &mut output,
        Duration::from_millis(80),
    )
    .await;
    drop(output);
    let received = drain.await.unwrap();
    let h = result.unwrap();
    assert!(started.elapsed() > Duration::from_millis(500));
    assert_eq!(received, b"complete response");
    assert_eq!(h.outcome, Some(Outcome::Completed));
    assert!(h.recording_gap);
    assert_eq!(h.unconfirmed, h.observed);
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

/// Aggregate I/O budget, not a fresh timeout for each successful small write.
#[tokio::test]
async fn io_budget_is_cumulative_across_output_writes() {
    let p = provider(
        200,
        String::new(),
        vec![vec![9; 4 * CHUNK]],
        true,
        Duration::ZERO,
    )
    .await;
    let (mut output, mut reader) = tokio::io::duplex(CHUNK);
    let drain = async {
        let mut buffer = vec![0; CHUNK];
        loop {
            tokio::time::sleep(Duration::from_millis(60)).await;
            if reader.read(&mut buffer).await.unwrap() == 0 {
                break;
            }
        }
    };
    let mut memory = Memory::default();
    let mut states = Vec::new();
    let run = async {
        let result = capture::forward(
            &Route::new(&p.url).unwrap(),
            vec![],
            &mut memory,
            &mut |h| states.push(h.clone()),
            &mut output,
            Duration::from_millis(100),
        )
        .await;
        drop(output);
        result
    };
    let (result, _) = tokio::join!(run, drain);
    assert!(result.is_err());
    assert_eq!(
        states.last().unwrap().outcome,
        Some(Outcome::OutcomeUnknown)
    );
}

#[test]
fn encrypted_sink_latches_failure_and_new_attempt_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let path = dir.path().join("spool");
    let mut spool = Spool::create(
        &path,
        &kan::evidence_service::hex(&SCOPE),
        &writer.did().to_string(),
        &Identity::generate().did().to_string(),
        1 << 20,
    )
    .unwrap();
    let recipient = crypto::public_key(&PRIVATE).unwrap();
    let lock = rusqlite::Connection::open(&path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut sink = EncryptedSpool {
        spool: Some(&mut spool),
        signer: &writer,
        recipient,
    };
    let started = std::time::Instant::now();
    assert!(sink.admit(&[1; 16], b"first").is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(sink.admit(&[2; 16], b"still unconfirmed").is_err());
    assert!(sink.spool.is_none());
    assert_eq!(spool.status().unwrap().pending, 0);
    let mut fresh = EncryptedSpool {
        spool: Some(&mut spool),
        signer: &writer,
        recipient,
    };
    fresh.admit(&[3; 16], b"later attempt").unwrap();
    assert_eq!(spool.status().unwrap().pending, 1);
    let head = spool.head().unwrap().unwrap();
    assert_eq!(
        delivery::decrypt_request(&head, &PRIVATE, &SCOPE, &writer.did().to_string()).unwrap(),
        b"later attempt"
    );
}
