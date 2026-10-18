#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{self as capture, Observer, Outcome, Route},
    evidence_crypto as crypto,
    evidence_gateway::{self as gateway, Config, ListenerAuth},
    evidence_service::hex,
    evidence_spool::Spool,
    sign::Identity,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const CA: &[u8] = include_bytes!("fixtures/gateway-tls/ca.pem");
const FOREIGN: &[u8] = include_bytes!("fixtures/gateway-tls/foreign.pem");
const CERT: &[u8] = include_bytes!("fixtures/gateway-tls/server.pem");
const KEY: &[u8] = include_bytes!("fixtures/gateway-tls/server.key");
const ID: &[u8] = include_bytes!("fixtures/gateway-tls/identity.pem");
const TOKEN: &str = "synthetic-local-token-32-bytes-long";
const PRIVATE: [u8; 32] = [73; 32];
const SCOPE: [u8; 32] = [17; 32];
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn provider(response: Vec<u8>) -> (String, Arc<AtomicUsize>, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let mut head = Vec::new();
            let mut one = [0];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut one).await.is_err() {
                    break;
                }
                head.push(one[0]);
            }
            let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();
            let mut body = vec![0; len];
            if s.read_exact(&mut body).await.is_err() {
                continue;
            }
            let _ = s.write_all(&response).await;
        }
    });
    (url, calls, Task(task))
}
fn config(
    route: Route,
    observer: Observer,
    dir: &std::path::Path,
    available: bool,
) -> (Config, Arc<Mutex<Vec<capture::Health>>>, String) {
    let signer = Identity::generate();
    let did = signer.did().to_string();
    let spool = dir.join("spool");
    if available {
        drop(
            Spool::create(
                &spool,
                &hex(&SCOPE),
                &did,
                &Identity::generate().did().to_string(),
                64 << 20,
            )
            .unwrap(),
        );
    }
    let health = Arc::new(Mutex::new(Vec::new()));
    let h = health.clone();
    (
        Config {
            profile: gateway::Profile::Opaque,
            provider_key: None,
            route,
            observer,
            spool,
            signer,
            recipient: crypto::public_key(&PRIVATE).unwrap(),
            io_budget: Duration::from_secs(5),
            report: Arc::new(move |s| h.lock().unwrap().push(s.clone())),
        },
        health,
        did,
    )
}
async fn start(auth: ListenerAuth, config: Config) -> (String, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let scheme = if matches!(&auth, ListenerAuth::MutualTls(_)) {
        "https"
    } else {
        "http"
    };
    let task = tokio::spawn(async move {
        gateway::serve(listener, auth, config).await.unwrap();
    });
    (format!("{scheme}://{addr}/v1/forward"), Task(task))
}
fn tls() -> ListenerAuth {
    ListenerAuth::MutualTls(gateway::server_tls(CERT, KEY, CA).unwrap())
}
fn client(ca: &[u8], identity: bool) -> reqwest::Client {
    let c = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca).unwrap())
        .timeout(Duration::from_secs(5));
    let c = if identity {
        c.identity(reqwest::Identity::from_pem(ID).unwrap())
    } else {
        c
    };
    c.build().unwrap()
}
fn frames(path: &std::path::Path, did: &str) -> Vec<(capture::Header, Vec<u8>)> {
    let c = rusqlite::Connection::open(path).unwrap();
    let mut st = c
        .prepare("SELECT request FROM pending ORDER BY position")
        .unwrap();
    st.query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| {
            let b = kan::evidence_delivery::decrypt_request(&r.unwrap(), &PRIVATE, &SCOPE, did)
                .unwrap();
            assert_eq!(&b[..5], b"KANC2");
            let n = u32::from_be_bytes(b[5..9].try_into().unwrap()) as usize;
            (
                serde_json::from_slice(&b[9..9 + n]).unwrap(),
                b[9 + n..].to_vec(),
            )
        })
        .collect()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_hops_preserve_bytes_status_observers_and_exchange() {
    let payload: Vec<u8> = (0..300007).map(|i| (i % 251) as u8).collect();
    let mut response = format!(
        "HTTP/1.1 429 X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    response.extend(&payload);
    let (p, calls, _p) = provider(response).await;
    let gdir = tempfile::tempdir().unwrap();
    let cdir = tempfile::tempdir().unwrap();
    let (g, gh, gd) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        gdir.path(),
        true,
    );
    let (gurl, _g) = start(tls(), g).await;
    let (c, ch, cd) = config(
        Route::mutual_tls(&gurl, CA, ID).unwrap(),
        Observer::Collector,
        cdir.path(),
        true,
    );
    let (curl, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    let request = vec![7; 200003];
    let r = reqwest::Client::new()
        .post(&curl)
        .bearer_auth(TOKEN)
        .body(request.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.bytes().await.unwrap().as_ref(), payload);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut links = Vec::new();
    for (dir, did, observer, h) in [
        (gdir.path(), gd, Observer::Gateway, gh),
        (cdir.path(), cd, Observer::Collector, ch),
    ] {
        let f = frames(&dir.join("spool"), &did);
        let mut input = Vec::new();
        let mut output = Vec::new();
        for (header, b) in f {
            assert_eq!(header.observer, observer);
            match header.event {
                capture::Event::TransportLink { exchange } => links.push(exchange),
                capture::Event::RequestChunk { offset } => {
                    assert_eq!(offset, input.len() as u64);
                    input.extend(b)
                }
                capture::Event::ResponseChunk { offset } => {
                    assert_eq!(offset, output.len() as u64);
                    output.extend(b)
                }
                _ => {}
            }
        }
        assert_eq!(input, request);
        assert_eq!(output, payload);
        let health = h.lock().unwrap();
        assert_eq!(health.last().unwrap().outcome, Some(Outcome::Completed));
        assert!(!health.last().unwrap().recording_gap);
    }
    assert_eq!(links.len(), 2);
    assert_eq!(links[0], links[1]);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_and_local_auth_fail_before_provider() {
    let (p, calls, _p) = provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    for c in [client(CA, false), client(FOREIGN, true)] {
        assert!(c
            .post(&url)
            .header("x-kan-exchange", hex(&[1; 32]))
            .body("x")
            .send()
            .await
            .is_err());
    }
    let foreign_client = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(CA).unwrap())
        .identity(
            reqwest::Identity::from_pem(include_bytes!(
                "fixtures/gateway-tls/foreign-identity.pem"
            ))
            .unwrap(),
        )
        .build()
        .unwrap();
    assert!(foreign_client
        .post(&url)
        .header("x-kan-exchange", hex(&[9; 32]))
        .send()
        .await
        .is_err());
    assert!(reqwest::Client::new()
        .post(url.replace("https:", "http:"))
        .send()
        .await
        .is_err());
    assert_eq!(
        client(CA, true)
            .post(&url)
            .body("x")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let cdir = tempfile::tempdir().unwrap();
    let (c, _, _) = config(
        Route::mutual_tls(&url, CA, ID).unwrap(),
        Observer::Collector,
        cdir.path(),
        false,
    );
    let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    assert_eq!(
        reqwest::Client::new()
            .post(&local)
            .body("x")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        reqwest::Client::new()
            .post(local.replace("/v1/forward", "/other"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let r = reqwest::Client::new()
        .post(&local)
        .bearer_auth(TOKEN)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(r.bytes().await.unwrap(), "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_upstream_remains_incomplete_with_visible_gaps() {
    let (p, calls, _p) = provider(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (g, h, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    let r = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[2; 32]))
        .body("x")
        .send()
        .await;
    if let Ok(r) = r {
        assert!(r.bytes().await.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let h = h.lock().unwrap();
    assert!(h.last().unwrap().recording_gap);
    assert_eq!(h.last().unwrap().outcome, Some(Outcome::OutcomeUnknown));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_and_foreign_routes_never_forward() {
    let (p, calls, _p) = provider(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    assert_eq!(
        client(CA, true)
            .post(&url)
            .header("x-kan-exchange", hex(&[1; 32]))
            .body(vec![0; capture::MAX_REQUEST + 1])
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        client(CA, true)
            .post(format!("{url}?url=https://evil.test"))
            .header("x-kan-exchange", hex(&[1; 32]))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downstream_disconnect_aborts_owned_forwarder() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = format!("http://{}/fixed", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let _p = Task(tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        c.fetch_add(1, Ordering::SeqCst);
        let mut h = Vec::new();
        let mut b = [0];
        while !h.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            h.push(b[0]);
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        s.write_all(b"1\r\nx\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    }));
    let dir = tempfile::tempdir().unwrap();
    let (g, h, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    let response = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[3; 32]))
        .send()
        .await
        .unwrap();
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if h.lock()
                .unwrap()
                .last()
                .is_some_and(|h| h.outcome == Some(Outcome::OutcomeUnknown))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_gateway_spool_does_not_block_inference() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let dir = tempfile::tempdir().unwrap();
    let (g, h, _) = config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), true);
    let lock = rusqlite::Connection::open(dir.path().join("spool")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (url, _g) = start(tls(), g).await;
    let body = tokio::time::timeout(Duration::from_secs(3), async {
        client(CA, true)
            .post(&url)
            .header("x-kan-exchange", hex(&[4; 32]))
            .body("x")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(body, "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let h = h.lock().unwrap();
    assert!(h.last().unwrap().recording_gap);
    assert_eq!(h.last().unwrap().outcome, Some(Outcome::Completed));
    lock.execute_batch("ROLLBACK").unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_python_tls_client_sees_exact_http() {
    let (p, calls, _p) = provider(
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 5\r\nConnection: close\r\n\r\na\x00b\xffc"
            .to_vec(),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    let out = tokio::process::Command::new(
        std::env::var("KAN_TLS_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into()),
    )
    .args(["scripts/verify_gateway_tls.py", &url])
    .kill_on_drop(true)
    .output()
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn sse() -> Vec<u8> {
    let mut out = String::new();
    let events = [
        (
            "message_start",
            serde_json::json!({"type":"message_start","message":{"id":"msg_kan_fixture","type":"message","role":"assistant","content":[],"model":"claude-opus-5-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":0}}}),
        ),
        ("ping", serde_json::json!({"type":"ping"})),
        (
            "content_block_start",
            serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        ),
        (
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"KAN_HARNESS_OK"}}),
        ),
        (
            "content_block_stop",
            serde_json::json!({"type":"content_block_stop","index":0}),
        ),
        (
            "message_delta",
            serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":8}}),
        ),
        ("message_stop", serde_json::json!({"type":"message_stop"})),
    ];
    for (event, data) in events {
        out.push_str(&format!("event: {event}\ndata: {data}\n\n"));
    }
    out.into_bytes()
}
type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
async fn anthropic_provider() -> (String, Requests, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let requests: Requests = Arc::new(Mutex::new(Vec::new()));
    let r = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut byte).await.is_err() {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let len = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap();
            let mut body = vec![0; len];
            if s.read_exact(&mut body).await.is_err() {
                continue;
            }
            let count = head.starts_with("POST /v1/messages/count_tokens");
            r.lock().unwrap().push((head, body));
            let (body, kind) = if count {
                (b"{\"input_tokens\":42}".to_vec(), "application/json")
            } else {
                (sse(), "text/event-stream")
            };
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close, x-private-hop\r\nx-private-hop: drop-me\r\nrequest-id: fixture-request\r\nanthropic-ratelimit-unified-status: allowed\r\nx-should-retry: false\r\n\r\n",body.len());
            let _ = s.write_all(header.as_bytes()).await;
            for chunk in body.chunks(31) {
                if s.write_all(chunk).await.is_err() {
                    break;
                }
            }
        }
    });
    (origin, requests, Task(task))
}
async fn anthropic_pair(
    gdir: &std::path::Path,
    cdir: &std::path::Path,
) -> (String, Requests, Vec<Task>, String, String) {
    let (origin, requests, p) = anthropic_provider().await;
    let (mut g, _, gd) = config(Route::new(&origin).unwrap(), Observer::Gateway, gdir, true);
    g.profile = gateway::Profile::Anthropic;
    g.provider_key = Some(reqwest::header::HeaderValue::from_static(
        "synthetic-provider-secret",
    ));
    let (url, g) = start(tls(), g).await;
    let origin = url.trim_end_matches("v1/forward");
    let (mut c, _, cd) = config(
        Route::mutual_tls(origin, CA, ID).unwrap(),
        Observer::Collector,
        cdir,
        true,
    );
    c.profile = gateway::Profile::Anthropic;
    let (url, c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    (
        url.trim_end_matches("v1/forward").into(),
        requests,
        vec![p, g, c],
        gd,
        cd,
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_profile_preserves_sse_open_headers_and_separates_credentials() {
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (origin, requests, _tasks, gdid, cdid) = anthropic_pair(gd.path(), cd.path()).await;
    let body=b"{ \"model\":\"fixture\", \"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"canary\"}],\"future_field\":7 }";
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let r = client
        .post(format!("{origin}v1/messages?beta=true"))
        .header("x-api-key", TOKEN)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "future-one,future-two")
        .header("anthropic-future-feature", "keep-me")
        .header("x-claude-code-session-id", "fixture-session")
        .header("connection", "close, anthropic-hop")
        .header("anthropic-hop", "remove-me")
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    assert_eq!(r.headers()["request-id"], "fixture-request");
    assert_eq!(r.headers()["x-should-retry"], "false");
    assert!(r.headers().get("x-private-hop").is_none());
    assert_eq!(r.bytes().await.unwrap().as_ref(), sse());
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1, body);
        let h = requests[0].0.to_ascii_lowercase();
        assert!(h.starts_with("post /v1/messages?beta=true "));
        assert!(h.contains("x-api-key: synthetic-provider-secret"));
        assert!(!h.contains(TOKEN));
        assert!(!h.contains("x-kan-exchange"));
        assert!(!h.contains("anthropic-hop"));
        assert!(h.contains("anthropic-future-feature: keep-me"));
        assert!(h.contains("anthropic-beta: future-one,future-two"));
        assert!(h.contains("x-claude-code-session-id: fixture-session"));
    }
    let r = client
        .post(format!("{origin}v1/messages/count_tokens"))
        .bearer_auth(TOKEN)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.bytes().await.unwrap(), "{\"input_tokens\":42}");
    for path in [
        "v1/messages?beta=false",
        "v1/messages?beta=true&url=evil",
        "v1/models",
    ] {
        assert_eq!(
            client
                .post(format!("{origin}{path}"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    assert_eq!(
        client
            .post(format!("{origin}v1/messages"))
            .bearer_auth(TOKEN)
            .header("x-api-key", "wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
    let mut saw_omission = false;
    for (dir, did) in [(gd.path(), gdid), (cd.path(), cdid)] {
        for (h, _) in frames(&dir.join("spool"), &did) {
            if let capture::Event::HttpMetadata {
                headers, omitted, ..
            } = h.event
            {
                let text = serde_json::to_string(&headers).unwrap();
                assert!(!text.contains(&hex(TOKEN.as_bytes())));
                assert!(!text.contains(&hex(b"synthetic-provider-secret")));
                if omitted.iter().any(|s| s == "x-api-key") {
                    saw_omission = true;
                }
            }
        }
    }
    assert!(saw_omission);
}

/// Explicit opt-in: actual installed harness, isolated configuration, synthetic
/// local provider. Never invokes a real model or reads ambient credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit KAN_CLAUDE_BIN; synthetic-provider compatibility witness"]
async fn real_claude_code_uses_both_hops() {
    let binary = std::env::var("KAN_CLAUDE_BIN").expect("explicit harness executable");
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let sandbox = tempfile::tempdir().unwrap();
    let (origin, requests, _tasks, _, _) = anthropic_pair(gd.path(), cd.path()).await;
    let version = tokio::process::Command::new(&binary)
        .arg("--version")
        .output()
        .await
        .unwrap();
    assert!(version.status.success());
    println!(
        "actual harness: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(binary)
            .env_clear()
            .env("PATH", "/opt/homebrew/bin:/usr/bin:/bin")
            .env("CLAUDE_CONFIG_DIR", sandbox.path().join("config"))
            .env("ANTHROPIC_BASE_URL", &origin)
            .env("ANTHROPIC_API_KEY", TOKEN)
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .env("DISABLE_TELEMETRY", "1")
            .env("DISABLE_ERROR_REPORTING", "1")
            .current_dir(sandbox.path())
            .args([
                "-p",
                "Reply KAN_HARNESS_OK. This is an isolated synthetic transport test.",
                "--safe-mode",
                "--no-session-persistence",
                "--strict-mcp-config",
                "--mcp-config",
                "{\"mcpServers\":{}}",
                "--tools",
                "",
                "--setting-sources",
                "",
                "--model",
                "claude-opus-5-5",
                "--max-turns",
                "1",
                "--output-format",
                "json",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        result.status.success(),
        "harness failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["result"], "KAN_HARNESS_OK");
    assert_eq!(json["is_error"], false);
    let requests = requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(requests
        .iter()
        .any(|(h, b)| h.starts_with("POST /v1/messages")
            && String::from_utf8_lossy(b).contains("isolated synthetic transport test")));
    assert!(requests
        .iter()
        .all(|(h, _)| h.contains("synthetic-provider-secret") && !h.contains(TOKEN)));
    println!("real Claude Code → collector → mutual TLS gateway → synthetic provider: {} requests, expected result",requests.len());
}
