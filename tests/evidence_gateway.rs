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
            key_history: None,
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
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close, x-private-hop\r\nx-private-hop: drop-me\r\nrequest-id: fixture-request\r\nanthropic-ratelimit-unified-status: allowed\r\nx-should-retry: false\r\nCache-Control: max-age=17\r\n\r\n",body.len());
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
        .header("content-encoding", "identity")
        .header("accept-encoding", "identity")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    assert_eq!(r.headers()["request-id"], "fixture-request");
    assert_eq!(r.headers()["x-should-retry"], "false");
    assert_eq!(r.headers()["cache-control"], "max-age=17");
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
        assert!(h.contains("content-encoding: identity"));
        assert!(h.contains("accept-encoding: identity"));
        assert!(h.contains("anthropic-beta: future-one,future-two"));
        assert!(h.contains("x-claude-code-session-id: fixture-session"));
    }
    let r = client
        .post(format!("{origin}v1/messages/count_tokens"))
        .header("x-kan-session", "a".repeat(64))
        .header("x-kan-parent-attempt", "b".repeat(64))
        .header("x-kan-transition", "branch")
        .bearer_auth(TOKEN)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.bytes().await.unwrap(), "{\"input_tokens\":42}");
    assert!(!requests.lock().unwrap()[1]
        .0
        .to_ascii_lowercase()
        .contains("content-type:"));
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
    assert!(!requests.lock().unwrap()[1]
        .0
        .to_ascii_lowercase()
        .contains("x-kan-session"));
    let mut session_observers = std::collections::BTreeSet::new();
    let mut saw_omission = false;
    let mut outgoing_provider_omission = false;
    for (dir, did) in [(gd.path(), gdid.clone()), (cd.path(), cdid.clone())] {
        for (h, _) in frames(&dir.join("spool"), &did) {
            if let capture::Event::HttpMetadata {
                direction,
                headers,
                omitted,
            } = h.event
            {
                if h.observer == Observer::Gateway && direction == "request-outgoing" {
                    outgoing_provider_omission |= omitted.iter().any(|s| s == "x-api-key");
                }
                if direction == "request"
                    && headers
                        .iter()
                        .any(|(k, v)| k == "x-kan-session" && v == &hex("a".repeat(64).as_bytes()))
                {
                    session_observers.insert(format!("{:?}", h.observer));
                }
                let text = serde_json::to_string(&headers).unwrap();
                assert!(!text.contains(&hex(TOKEN.as_bytes())));
                assert!(!text.contains(&hex(b"synthetic-provider-secret")));
                if omitted.iter().any(|s| s == "x-api-key") {
                    saw_omission = true;
                }
            }
        }
    }
    assert_eq!(
        session_observers.len(),
        2,
        "session link reaches both collectors but not the provider"
    );
    assert!(saw_omission);
    independent_evidence(
        gd.path(),
        cd.path(),
        &gdid,
        &cdid,
        &requests.lock().unwrap(),
    );
    assert!(
        outgoing_provider_omission,
        "provider credential installation must have an omission marker"
    );
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
    let (origin, requests, _tasks, gdid, cdid) = anthropic_pair(gd.path(), cd.path()).await;
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
    independent_evidence(gd.path(), cd.path(), &gdid, &cdid, &requests);
}

struct CliProcess {
    _child: tokio::process::Child,
    _stderr: Task,
}
async fn proxy_cli(args: &[String]) -> (String, CliProcess) {
    use tokio::io::AsyncBufReadExt;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stderr = tokio::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stderr.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let ready: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("proxy did not start: {line}"));
    let address = ready["listening"]
        .as_str()
        .expect("ready address")
        .to_owned();
    let drain = Task(tokio::spawn(async move {
        loop {
            line.clear();
            match stderr.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                _ => {}
            }
        }
    }));
    (
        address,
        CliProcess {
            _child: child,
            _stderr: drain,
        },
    )
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_profile_uses_explicit_files_and_streams_both_hops() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let file = |name: &str, bytes: &[u8]| {
        let p = root.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p.to_str().unwrap().to_owned()
    };
    let ca = file("ca", CA);
    let cert = file("cert", CERT);
    let tlskey = file("tlskey", KEY);
    let identity = file("identity", ID);
    let token = file("token", TOKEN.as_bytes());
    let providerkey = file("providerkey", b"synthetic-provider-secret");
    let gwriter = Identity::generate();
    let cwriter = Identity::generate();
    let gkey = root.path().join("gkey");
    let ckey = root.path().join("ckey");
    gwriter.save(&gkey).unwrap();
    cwriter.save(&ckey).unwrap();
    let gspool = root.path().join("gspool");
    let cspool = root.path().join("cspool");
    for (path, writer) in [(&gspool, &gwriter), (&cspool, &cwriter)] {
        drop(
            Spool::create(
                path,
                &hex(&SCOPE),
                writer.did().as_str(),
                Identity::generate().did().as_str(),
                64 << 20,
            )
            .unwrap(),
        );
    }
    let (provider, requests, _p) = anthropic_provider().await;
    let recipient = hex(&crypto::public_key(&PRIVATE).unwrap());
    let (gaddr, _g) = proxy_cli(&[
        "gateway".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--certificate".into(),
        cert,
        "--tls-key".into(),
        tlskey,
        "--client-ca".into(),
        ca.clone(),
        "--provider".into(),
        provider,
        "--provider-key-file".into(),
        providerkey,
        "--profile".into(),
        "anthropic".into(),
        "--spool".into(),
        gspool.to_str().unwrap().into(),
        "--key".into(),
        gkey.to_str().unwrap().into(),
        "--recipient".into(),
        recipient.clone(),
    ])
    .await;
    let (caddr, _c) = proxy_cli(&[
        "collector".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--gateway".into(),
        format!("https://{gaddr}/"),
        "--server-ca".into(),
        ca,
        "--identity".into(),
        identity,
        "--token-file".into(),
        token,
        "--profile".into(),
        "anthropic".into(),
        "--spool".into(),
        cspool.to_str().unwrap().into(),
        "--key".into(),
        ckey.to_str().unwrap().into(),
        "--recipient".into(),
        recipient,
        "--health-journal".into(),
        root.path()
            .join("missing-health-journal")
            .to_str()
            .unwrap()
            .into(),
    ])
    .await;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://{caddr}/v1/messages?beta=true"))
        .header("x-api-key", TOKEN)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body("{\"stream\":true}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.bytes().await.unwrap().as_ref(), sse());
    assert_eq!(requests.lock().unwrap().len(), 1);
    for (path, writer, observer) in [
        (&gspool, &gwriter, Observer::Gateway),
        (&cspool, &cwriter, Observer::Collector),
    ] {
        let f = frames(path, writer.did().as_str());
        assert!(!f.is_empty());
        assert!(f.iter().all(|(h, _)| h.observer == observer));
        assert!(matches!(
            f.last().unwrap().0.event,
            capture::Event::Terminal {
                outcome: Outcome::Completed
            }
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_response_metadata_does_not_block_inference() {
    let large = "x".repeat(90000);
    let response=format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Large-Fixture: {large}\r\nConnection: close\r\n\r\nok").into_bytes();
    let (p, calls, _p) = provider(response).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut config, health, did) = config(
        Route::new(p.trim_end_matches("fixed")).unwrap(),
        Observer::Gateway,
        dir.path(),
        true,
    );
    config.profile = gateway::Profile::Anthropic;
    config.provider_key = Some(reqwest::header::HeaderValue::from_static(
        "synthetic-provider-secret",
    ));
    let (url, _g) = start(tls(), config).await;
    let r = client(CA, true)
        .post(url.replace("v1/forward", "v1/messages"))
        .header("x-kan-exchange", hex(&[8; 32]))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["x-large-fixture"].as_bytes(), large.as_bytes());
    assert_eq!(r.bytes().await.unwrap(), "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!health.lock().unwrap().last().unwrap().recording_gap);
    independent_spool(
        dir.path(),
        &did,
        "gateway",
        &serde_json::json!({"private":hex(&PRIVATE),"scope":hex(&SCOPE),"exchanges":[{"request":hex(b"{}"),"response":hex(b"ok"),"status":200}]}),
    );
    let mut metadata = Vec::new();
    let mut total = 0;
    for (h, b) in frames(&dir.path().join("spool"), &did) {
        let event = serde_json::to_value(h.event).unwrap();
        if event["type"] == "http-metadata-chunk" && event["direction"] == "response" {
            assert_eq!(event["offset"].as_u64().unwrap(), metadata.len() as u64);
            total = event["total"].as_u64().unwrap();
            metadata.extend(b);
        }
    }
    assert_eq!(metadata.len() as u64, total);
    assert!(total > capture::CHUNK as u64);
    let event: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    assert!(event["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h[0] == "x-large-fixture" && h[1] == hex(large.as_bytes())));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_tls12_client_rejected() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(
        Route::new(&p).unwrap(),
        Observer::Gateway,
        dir.path(),
        false,
    );
    let (url, _g) = start(tls(), g).await;
    let c = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(CA).unwrap())
        .identity(reqwest::Identity::from_pem(ID).unwrap())
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    let r = c
        .post(&url)
        .header("x-kan-exchange", hex(&[7; 32]))
        .body("x")
        .send()
        .await;
    println!("PROBE tls1.2: {:?}", r.as_ref().map(|r| r.status()));
    assert!(r.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_peer_limit_refuses_new_connections_without_eviction() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (remote, _g) = start(tls(), g).await;
    let (c, _, _) = config(
        Route::mutual_tls(&remote, CA, ID).unwrap(),
        Observer::Collector,
        cd.path(),
        false,
    );
    let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    let mut idle = Vec::new();
    // Excess same-peer arrivals are refused; already admitted sockets survive.
    for url in [&remote, &local] {
        let u = reqwest::Url::parse(url).unwrap();
        for _ in 0..40 {
            idle.push(
                tokio::net::TcpStream::connect((u.host_str().unwrap(), u.port().unwrap()))
                    .await
                    .unwrap(),
            );
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for index in [8, 48] {
        let mut byte = [0];
        let closed =
            tokio::time::timeout(Duration::from_secs(1), idle[index].read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "excess same-peer socket was not refused"
        );
    }
    for index in [0, 40] {
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), idle[index].read(&mut byte))
                .await
                .is_err(),
            "admitted socket was evicted"
        );
    }
    drop(idle);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
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
async fn authenticated_slot_limit_and_body_timeout_are_enforced() {
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (origin, requests, _tasks, _, _) = anthropic_pair(gd.path(), cd.path()).await;
    let url = reqwest::Url::parse(&origin).unwrap();
    let addr = (url.host_str().unwrap(), url.port().unwrap());
    let started = std::time::Instant::now();
    let mut pending = Vec::new();
    for _ in 0..8 {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nx-api-key: {TOKEN}\r\nContent-Length: 10\r\n\r\n{{").as_bytes()).await.unwrap();
        pending.push(s);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let c = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    assert_eq!(
        c.post(format!("{origin}v1/messages"))
            .header("x-api-key", TOKEN)
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    // Every one of the eight requests must still be admitted and awaiting body.
    for stream in &mut pending {
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut byte))
                .await
                .is_err(),
            "fewer than eight authenticated slots"
        );
    }
    // Authentication must precede slot reservation, even when all slots are full.
    assert_eq!(
        c.post(format!("{origin}v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(35),
        pending[0].read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 413"));
    assert!(
        started.elapsed() >= Duration::from_secs(29),
        "body timeout was shortened"
    );
    drop(pending);
    assert_eq!(requests.lock().unwrap().len(), 0);
    // Matching duplicate credentials are still ambiguous, not two votes to allow.
    assert_eq!(
        c.post(format!("{origin}v1/messages"))
            .header("x-api-key", TOKEN)
            .header("x-api-key", TOKEN)
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

fn independent_evidence(
    gd: &std::path::Path,
    cd: &std::path::Path,
    gdid: &str,
    cdid: &str,
    requests: &[(String, Vec<u8>)],
) {
    let expected = serde_json::json!({"private":hex(&PRIVATE),"scope":hex(&SCOPE),"exchanges":requests.iter().map(|(h,b)|{
        let response=if h.starts_with("POST /v1/messages/count_tokens") {b"{\"input_tokens\":42}".to_vec()} else {sse()};
        serde_json::json!({"request":hex(b),"response":hex(&response),"status":200})
    }).collect::<Vec<_>>()});
    let mut summaries = Vec::new();
    for (dir, did, observer) in [(gd, gdid, "gateway"), (cd, cdid, "collector")] {
        summaries.push(independent_spool(dir, did, observer, &expected));
    }
    assert_eq!(
        summaries[0], summaries[1],
        "independently decoded exchange links differ"
    );
}

fn independent_spool(
    dir: &std::path::Path,
    did: &str,
    observer: &str,
    expected: &serde_json::Value,
) -> serde_json::Value {
    let fixture = dir.join("oracle-expectations.json");
    std::fs::write(&fixture, serde_json::to_vec(expected).unwrap()).unwrap();
    let python = std::env::var("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = std::process::Command::new(&python)
        .args([
            "-I",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/verify_gateway_evidence.py"
            ),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/verify_archive_encryption.py"
            ),
        ])
        .arg(dir.join("spool"))
        .arg(&fixture)
        .args([did, observer])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = serde_json::from_slice(&output.stdout).unwrap();
    // A changed external expectation must fail even with Python optimization.
    let mut corrupt = expected.clone();
    corrupt["exchanges"][0]["request"] = serde_json::json!("ff");
    std::fs::write(&fixture, serde_json::to_vec(&corrupt).unwrap()).unwrap();
    let bad = std::process::Command::new(&python)
        .args([
            "-I",
            "-O",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/verify_gateway_evidence.py"
            ),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/verify_archive_encryption.py"
            ),
        ])
        .arg(dir.join("spool"))
        .arg(&fixture)
        .args([did, observer])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("external body expectations"));
    summary
}

#[test]
fn independent_reader_retains_unknown_event_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let frame = dir.path().join("future.bin");
    let json = br#"{"event":{"type":"future-event","new-field":7}}"#;
    let mut raw = b"KANC2".to_vec();
    raw.extend((json.len() as u32).to_be_bytes());
    raw.extend(json);
    raw.extend([0, 255, 7]);
    std::fs::write(&frame, &raw).unwrap();
    let output=std::process::Command::new("python3").args(["-I","-O","-c","import pathlib,runpy,sys; m=runpy.run_path(sys.argv[1]); print(m['parse_frame'](pathlib.Path(sys.argv[2]).read_bytes())[2])",concat!(env!("CARGO_MANIFEST_DIR"),"/scripts/verify_gateway_evidence.py")]).arg(&frame).output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), hex(&raw));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_stream_survives_pending_connection_churn() {
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = format!("http://{}/fixed", provider.local_addr().unwrap());
    let (release, wait) = tokio::sync::oneshot::channel();
    let _p = Task(tokio::spawn(async move {
        let (mut stream, _) = provider.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        stream.read_exact(&mut byte).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
            .await
            .unwrap();
        wait.await.unwrap();
        stream.write_all(b"1\r\nb\r\n0\r\n\r\n").await.unwrap();
    }));
    let gd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (url, _g) = start(tls(), g).await;
    let mut response = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[7; 32]))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "a");
    let u = reqwest::Url::parse(&url).unwrap();
    let mut idle = Vec::new();
    for _ in 0..80 {
        idle.push(
            tokio::net::TcpStream::connect((u.host_str().unwrap(), u.port().unwrap()))
                .await
                .unwrap(),
        );
    }
    release.send(()).unwrap();
    assert_eq!(response.bytes().await.unwrap(), "b");
}

/// R3: the mutual-TLS listener's eight authenticated slots (retained independent probe): eight completed handshakes with no request occupy all slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_mtls_authenticated_slots_are_eight() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let gd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (url, _g) = start(tls(), g).await;
    let u = reqwest::Url::parse(&url).unwrap();
    let addr = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_slice_iter(CA) {
        roots.add(c.unwrap()).unwrap();
    }
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(ID)
        .map(|c| c.unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(ID).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)
    .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let mut held = Vec::new();
    for _ in 0..8 {
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let name =
            rustls::pki_types::ServerName::try_from(u.host_str().unwrap().to_owned()).unwrap();
        held.push(connector.connect(name, tcp).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ninth = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[7; 32]))
        .body("x")
        .send()
        .await;
    println!(
        "PROBE R3 ninth with 8 idle authenticated TLS: {:?}",
        ninth.as_ref().map(|r| r.status())
    );
    assert!(ninth.is_err());
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[7; 32]))
        .body("x")
        .send()
        .await
        .unwrap();
    println!("PROBE R3 after release: {}", after.status());
    assert_eq!(after.status(), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_admitted_tls_handshake_survives_connection_churn() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let gd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (url, _g) = start(tls(), g).await;
    let u = reqwest::Url::parse(&url).unwrap();
    let addr = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap());
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut flood = Vec::new();
    for _ in 0..80 {
        flood.push(tokio::net::TcpStream::connect(&addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_slice_iter(CA) {
        roots.add(c.unwrap()).unwrap();
    }
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(ID)
        .map(|c| c.unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(ID).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)
    .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));

    let name = rustls::pki_types::ServerName::try_from(u.host_str().unwrap().to_owned()).unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(3), connector.connect(name, tcp))
        .await
        .unwrap()
        .expect("admitted handshake survives churn");
    stream.write_all(format!("POST /v1/forward HTTP/1.1\r\nHost: localhost\r\nx-kan-exchange: {}\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",hex(&[7;32])).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "{:?}", response);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// Linux supports distinct 127/8 source bindings without host reconfiguration.
// macOS requires interface aliases, which this test must never install.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_pending_cap_is_32_across_distinct_peers() {
    let (p, calls, _p) = provider(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    let gd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (url, _g) = start(tls(), g).await;
    let u = reqwest::Url::parse(&url).unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", u.port().unwrap()).parse().unwrap();
    let mut held = Vec::new();
    for peer in 2..=5 {
        for _ in 0..8 {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket
                .bind(format!("127.0.0.{peer}:0").parse().unwrap())
                .unwrap();
            held.push(socket.connect(addr).await.unwrap());
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        ),
        "global pending cap did not refuse connection 33"
    );
    held.pop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut available = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), available.read(&mut byte))
            .await
            .is_err(),
        "freed pending capacity was not usable by another peer"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn distinct_peer_can_authenticate_while_other_peer_saturates_pending_slots() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let gd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (url, _g) = start(tls(), g).await;
    let u = reqwest::Url::parse(&url).unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", u.port().unwrap()).parse().unwrap();
    let mut held = Vec::new();
    for _ in 0..80 {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        held.push(socket.connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = client(CA, true)
        .post(&url)
        .header("x-kan-exchange", hex(&[7; 32]))
        .body("x")
        .send()
        .await
        .expect("another peer retains handshake capacity");
    assert_eq!(r.bytes().await.unwrap(), "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_rotation_changes_new_capture_and_history_failure_forwards_with_visible_gap() {
    use kan::{
        evidence_keys::{Access, Record},
        evidence_proof_service::{Binding, Profile},
    };
    let (p, calls, _provider) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec())
            .await;
    let dir = tempfile::tempdir().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner = Identity::generate();
    let history = Access {
        directory: key_dir.path().to_owned(),
        binding: Binding {
            profile: Profile::Admitted,
            archive: hex(&[1; 32]),
            scope: hex(&SCOPE),
            issuer: owner.did().to_string(),
        },
        owner: owner.did().to_string(),
        recovery_recipient: hex(&crypto::public_key(&[92; 32]).unwrap()),
        minimum: None,
    };
    history.initialize().unwrap();
    let first = history.preview(hex(&[1; 32])).unwrap();
    history
        .append(Record::sign(first.clone(), &owner).unwrap())
        .unwrap();
    let (mut cfg, health, writer) =
        config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), true);
    cfg.key_history = Some(history.clone());
    let (url, _gateway) = start(ListenerAuth::LoopbackToken(TOKEN.into()), cfg).await;
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .body("before rotation")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    let second = history.preview(hex(&[2; 32])).unwrap();
    history
        .append(Record::sign(second.clone(), &owner).unwrap())
        .unwrap();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .body("after rotation")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    let count = {
        let c = rusqlite::Connection::open(dir.path().join("spool")).unwrap();
        let mut st = c
            .prepare("SELECT request FROM pending ORDER BY position")
            .unwrap();
        let rows = st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        let first_key = first.unlock(&[92; 32]).unwrap();
        let second_key = second.unlock(&[92; 32]).unwrap();
        let mut before = 0;
        let mut after = 0;
        for raw in &rows {
            let a = kan::evidence_delivery::decrypt_request(raw, &first_key, &SCOPE, &writer);
            let b = kan::evidence_delivery::decrypt_request(raw, &second_key, &SCOPE, &writer);
            assert_ne!(a.is_ok(), b.is_ok());
            before += usize::from(a.is_ok());
            after += usize::from(b.is_ok());
        }
        assert!(before > 0 && after > 0);
        rows.len()
    };
    // A published but invalid generation is never replaced by the old recipient.
    std::fs::write(key_dir.path().join("unexpected"), b"damaged history").unwrap();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .body("capture gap")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if health
                .lock()
                .unwrap()
                .last()
                .is_some_and(|h| h.recording_gap && h.outcome == Some(Outcome::Completed))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let c = rusqlite::Connection::open(dir.path().join("spool")).unwrap();
    assert_eq!(
        c.query_row("SELECT count(*) FROM pending", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        count
    );
}
