
// ---- Independent reviewer probes (claude-opus-5-5). Appended to a copy of the
// committed helpers; only functions named probe_* are new.
type Heads = Arc<Mutex<Vec<String>>>;
async fn raw_provider(resp: Vec<u8>, hang: bool) -> (String, Arc<AtomicUsize>, Heads, Arc<AtomicUsize>, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let heads: Heads = Arc::new(Mutex::new(Vec::new()));
    let (c, cl, hd) = (calls.clone(), closed.clone(), heads.clone());
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            c.fetch_add(1, Ordering::SeqCst);
            let mut head = Vec::new();
            let mut one = [0];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut one).await.is_err() { break; }
                head.push(one[0]);
            }
            let text = String::from_utf8_lossy(&head).to_string();
            let len = text.to_ascii_lowercase().lines()
                .find_map(|l| l.strip_prefix("content-length: ").map(|v| v.trim().to_owned()))
                .unwrap_or("0".into()).parse::<usize>().unwrap();
            hd.lock().unwrap().push(text);
            let mut body = vec![0; len];
            if s.read_exact(&mut body).await.is_err() { continue; }
            let _ = s.write_all(&resp).await;
            if hang {
                let mut b = [0; 1];
                match tokio::time::timeout(Duration::from_secs(10), s.read(&mut b)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => { cl.fetch_add(1, Ordering::SeqCst); }
                    _ => {}
                }
            }
        }
    });
    (origin, calls, heads, closed, Task(task))
}
async fn pair_with(origin: &str, gdir: &std::path::Path, cdir: &std::path::Path)
    -> (String, Vec<Task>, String, String, Arc<Mutex<Vec<capture::Health>>>, Arc<Mutex<Vec<capture::Health>>>) {
    let (mut g, gh, gd) = config(Route::new(origin).unwrap(), Observer::Gateway, gdir, true);
    g.profile = gateway::Profile::Anthropic;
    g.provider_key = Some(reqwest::header::HeaderValue::from_static("synthetic-provider-secret"));
    let (url, g) = start(tls(), g).await;
    let gorigin = url.trim_end_matches("v1/forward");
    let (mut c, ch, cd) = config(Route::mutual_tls(gorigin, CA, ID).unwrap(), Observer::Collector, cdir, true);
    c.profile = gateway::Profile::Anthropic;
    let (url, c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    (url.trim_end_matches("v1/forward").into(), vec![g, c], gd, cd, gh, ch)
}
fn terminal(path: &std::path::Path, did: &str) -> Vec<Outcome> {
    frames(path, did).into_iter().filter_map(|(h, _)| match h.event {
        capture::Event::Terminal { outcome } => Some(outcome), _ => None }).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_preauth_tcp_exhausts_gateway_slots() {
    let (p, calls, _p) = provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), false);
    let (url, _g) = start(tls(), g).await;
    let addr = url.trim_start_matches("https://").trim_end_matches("/v1/forward").to_owned();
    let mut idle = Vec::new();
    for _ in 0..8 { idle.push(tokio::net::TcpStream::connect(&addr).await.unwrap()); }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let blocked = client(CA, true).post(&url).header("x-kan-exchange", hex(&[5; 32])).body("x").send().await;
    println!("PROBE preauth: legit mTLS while 8 unauthenticated idle TCP held -> {:?}", blocked.as_ref().map(|r| r.status()));
    assert!(blocked.is_err(), "slots not exhaustible pre-auth");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(idle);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ok = client(CA, true).post(&url).header("x-kan-exchange", hex(&[6; 32])).body("x").send().await.unwrap();
    assert_eq!(ok.bytes().await.unwrap(), "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_tls12_client_rejected() {
    let (p, calls, _p) = provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), false);
    let (url, _g) = start(tls(), g).await;
    let c = reqwest::Client::builder().no_proxy().tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(CA).unwrap())
        .identity(reqwest::Identity::from_pem(ID).unwrap())
        .max_tls_version(reqwest::tls::Version::TLS_1_2).build().unwrap();
    let r = c.post(&url).header("x-kan-exchange", hex(&[7; 32])).body("x").send().await;
    println!("PROBE tls1.2: {:?}", r.as_ref().map(|r| r.status()));
    assert!(r.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_local_credentials_never_reach_gateway_and_exchange_not_injectable() {
    let (origin, _req, _p) = anthropic_provider().await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, gdid, cdid, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let injected = "cd".repeat(32);
    let r = reqwest::Client::builder().no_proxy().build().unwrap()
        .post(format!("{local}v1/messages"))
        .header("x-api-key", TOKEN).bearer_auth(TOKEN)
        .header("x-kan-exchange", &injected)
        .header("cookie", "local=secret")
        .body("{}").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let _ = r.bytes().await.unwrap();
    let mut links = Vec::new();
    for (dir, did, who) in [(gd.path(), &gdid, "gateway"), (cd.path(), &cdid, "collector")] {
        for (h, body) in frames(&dir.join("spool"), did) {
            match h.event {
                capture::Event::TransportLink { exchange } => links.push(exchange),
                capture::Event::HttpMetadata { direction, headers, omitted } => {
                    let names: Vec<_> = headers.iter().map(|(n, _)| n.clone()).collect();
                    println!("PROBE {who} {direction} metadata names={names:?} omitted={omitted:?}");
                    let all = serde_json::to_string(&headers).unwrap();
                    assert!(!all.contains(&hex(TOKEN.as_bytes())));
                    assert!(!all.contains(&hex(b"synthetic-provider-secret")));
                    if who == "gateway" && direction == "request" {
                        assert!(!omitted.iter().any(|o| o == "authorization" || o == "x-api-key" || o == "cookie"),
                            "local credential headers reached gateway");
                    }
                }
                _ => { let _ = body; }
            }
        }
    }
    println!("PROBE links={links:?}");
    assert_eq!(links.len(), 2);
    assert_eq!(links[0], links[1]);
    assert_ne!(links[0], injected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_two_hop_upstream_truncation_is_not_clean_eof() {
    let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n".to_vec();
    resp.extend_from_slice(&sse()[..200]);
    let (origin, calls, _h, _cl, _p) = raw_provider(resp, false).await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, gdid, cdid, gh, ch) = pair_with(&origin, gd.path(), cd.path()).await;
    let r = reqwest::Client::builder().no_proxy().build().unwrap()
        .post(format!("{local}v1/messages")).header("x-api-key", TOKEN).body("{}").send().await;
    let outcome = match r { Ok(r) => r.bytes().await.map(|b| b.len()), Err(e) => Err(e) };
    println!("PROBE truncation downstream body: {outcome:?}");
    assert!(outcome.is_err(), "truncated stream surfaced as clean EOF");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "retry observed");
    assert_eq!(terminal(&gd.path().join("spool"), &gdid), vec![Outcome::OutcomeUnknown]);
    assert_eq!(terminal(&cd.path().join("spool"), &cdid), vec![Outcome::OutcomeUnknown]);
    assert!(gh.lock().unwrap().iter().all(|h| !h.remote_acknowledged));
    assert!(ch.lock().unwrap().iter().all(|h| !h.remote_acknowledged));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_two_hop_downstream_cancel_reaches_provider() {
    let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    resp.extend_from_slice(b"7\r\nevent:x\r\n");
    let (origin, calls, _h, closed, _p) = raw_provider(resp, true).await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, gdid, cdid, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let mut r = reqwest::Client::builder().no_proxy().build().unwrap()
        .post(format!("{local}v1/messages")).header("x-api-key", TOKEN).body("{}").send().await.unwrap();
    let first = r.chunk().await.unwrap();
    println!("PROBE cancel first chunk {first:?}");
    drop(r);
    let ok = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if closed.load(Ordering::SeqCst) == 1 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await;
    println!("PROBE cancel provider saw close: {}", ok.is_ok());
    assert!(ok.is_ok(), "provider connection not released after downstream cancel");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(terminal(&gd.path().join("spool"), &gdid), vec![Outcome::OutcomeUnknown]);
    assert_eq!(terminal(&cd.path().join("spool"), &cdid), vec![Outcome::OutcomeUnknown]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_absolute_form_and_encoded_paths_stay_pinned() {
    let (origin, _req, _p) = anthropic_provider().await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, _, _, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let addr = local.trim_start_matches("http://").trim_end_matches('/').to_owned();
    let raw = |target: &str| format!("POST {target} HTTP/1.1\r\nHost: evil.invalid\r\nx-api-key: {TOKEN}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
    for (target, expect_ok) in [
        ("http://evil.invalid/v1/messages", true),
        ("/v1/messages/../models", false),
        ("/v1/%6dessages", false),
        ("/v1/messages?beta=true&", false),
        ("/v1/messages/count_tokens?beta=true", true),
        ("*", false),
    ] {
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        s.write_all(raw(target).as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        let line = String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_owned();
        println!("PROBE target {target:?} -> {line:?}");
        assert_eq!(line.starts_with("HTTP/1.1 200"), expect_ok, "{target}");
    }
    let provider_addr = origin.trim_start_matches("http://").trim_end_matches('/');
    let reqs = _req.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    for (h, _) in reqs.iter() {
        let h = h.to_ascii_lowercase();
        assert!(h.contains(&format!("host: {provider_addr}")), "{h}");
        assert!(!h.contains("evil.invalid"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_chunked_oversize_and_ambiguous_credentials_never_forward() {
    let (origin, req, _p) = anthropic_provider().await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, _, _, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let addr = local.trim_start_matches("http://").trim_end_matches('/').to_owned();
    let mut sock = tokio::net::TcpStream::connect(&addr).await.unwrap();
    sock.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: {TOKEN}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
    let chunk = vec![b'a'; 1 << 20];
    for _ in 0..17 {
        if sock.write_all(b"100000\r\n").await.is_err() || sock.write_all(&chunk).await.is_err() || sock.write_all(b"\r\n").await.is_err() { break; }
    }
    let _ = sock.write_all(b"0\r\n\r\n").await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut out)).await;
    let line = String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_owned();
    println!("PROBE chunked oversize -> {line:?}");
    assert!(line.starts_with("HTTP/1.1 413"), "{line}");
    for headers in [
        vec![("x-api-key", TOKEN.to_string()), ("x-api-key", TOKEN.to_string())],
        vec![("x-api-key", TOKEN.to_string()), ("authorization", "Basic abc".into())],
        vec![("authorization", format!("bearer {TOKEN}"))],
        vec![("authorization", format!("Bearer  {TOKEN}"))],
        vec![("x-api-key", format!("{TOKEN}x"))], vec![("x-api-key", TOKEN[..31].to_string())],
        vec![],
    ] {
        let mut b = client.post(format!("{local}v1/messages"));
        for (n, v) in &headers { b = b.header(*n, v); }
        let s = b.body("{}").send().await.unwrap().status();
        println!("PROBE creds {:?} -> {s}", headers.iter().map(|h| h.0).collect::<Vec<_>>());
        assert_eq!(s, 401);
    }
    assert_eq!(req.lock().unwrap().len(), 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_encoded_and_non2xx_bodies_pass_through_two_hops() {
    let body = b"\x1f\x8b\x08\x00not-really-gzip\xff\x00";
    let mut resp = format!("HTTP/1.1 529 Overloaded\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nRetry-After: 7\r\nSet-Cookie: s=1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(body);
    let (origin, calls, heads, _cl, _p) = raw_provider(resp, false).await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, _, _, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let reqbody: Vec<u8> = (0..=255u8).cycle().take(70000).collect();
    let r = reqwest::Client::builder().no_proxy().build().unwrap()
        .post(format!("{local}v1/messages")).header("x-api-key", TOKEN)
        .header("content-encoding", "gzip").header("content-type", "application/json")
        .body(reqbody.clone()).send().await.unwrap();
    assert_eq!(r.status(), 529);
    assert_eq!(r.headers()["content-encoding"], "gzip");
    assert_eq!(r.headers()["retry-after"], "7");
    println!("PROBE set-cookie downstream: {:?}", r.headers().get("set-cookie"));
    assert_eq!(r.bytes().await.unwrap().as_ref(), body);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let h = heads.lock().unwrap()[0].to_ascii_lowercase();
    assert!(h.contains("content-encoding: gzip"));
    assert!(h.contains("content-length: 70000"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_slow_body_bounded_and_idle_local_slots() {
    let (origin, req, _p) = anthropic_provider().await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (local, _t, _, _, _, _) = pair_with(&origin, gd.path(), cd.path()).await;
    let addr = local.trim_start_matches("http://").trim_end_matches('/').to_owned();
    let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
    s.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: {TOKEN}\r\nContent-Length: 10\r\n\r\n{{").as_bytes()).await.unwrap();
    let started = std::time::Instant::now();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(40), s.read_to_end(&mut out)).await;
    let line = String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_owned();
    println!("PROBE slow body after {:?}: {line:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(35));
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert_eq!(req.lock().unwrap().len(), 0);
    // Unauthenticated local idle sockets hold every collector slot.
    let mut idle = Vec::new();
    for _ in 0..8 { idle.push(tokio::net::TcpStream::connect(&addr).await.unwrap()); }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = reqwest::Client::builder().no_proxy().build().unwrap()
        .post(format!("{local}v1/messages")).header("x-api-key", TOKEN).body("{}").send().await;
    println!("PROBE local idle slots -> {:?}", r.as_ref().map(|r| r.status()));
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_config_validation_fails_closed() {
    let lo: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let any: std::net::SocketAddr = "0.0.0.0:1".parse().unwrap();
    assert!(ListenerAuth::LoopbackToken("short".into()).validate(lo).is_err());
    assert!(ListenerAuth::LoopbackToken(format!("{TOKEN}\r")).validate(lo).is_err());
    assert!(ListenerAuth::LoopbackToken(TOKEN.into()).validate(any).is_err());
    assert!(ListenerAuth::LoopbackToken(TOKEN.into()).validate(lo).is_ok());
    let dir = tempfile::tempdir().unwrap();
    // Anthropic collector with a non-origin gateway route.
    let (mut c, _, _) = config(Route::mutual_tls("https://127.0.0.1:9/v1/forward", CA, ID).unwrap(), Observer::Collector, dir.path(), false);
    c.profile = gateway::Profile::Anthropic;
    assert!(c.validate().is_err());
    // Anthropic gateway without provider key; opaque gateway with key; collector with key.
    let (mut g, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Gateway, dir.path(), false);
    g.profile = gateway::Profile::Anthropic;
    assert!(g.validate().is_err());
    let (mut g, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Gateway, dir.path(), false);
    g.provider_key = Some(reqwest::header::HeaderValue::from_static("k"));
    assert!(g.validate().is_err());
    let (mut c, _, _) = config(Route::mutual_tls("https://127.0.0.1:9/", CA, ID).unwrap(), Observer::Collector, dir.path(), false);
    c.profile = gateway::Profile::Anthropic;
    c.provider_key = Some(reqwest::header::HeaderValue::from_static("k"));
    assert!(c.validate().is_err());
    // Collector with a non-mTLS route; public plaintext provider.
    let (c, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Collector, dir.path(), false);
    assert!(c.validate().is_err());
    assert!(Route::new("http://example.com/").is_err());
    assert!(Route::new("https://user:pw@example.com/").is_err());
    // Wrong-writer existing spool is refused at startup.
    let (g, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Gateway, dir.path(), true);
    let other = tempfile::tempdir().unwrap();
    let (mut g2, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Gateway, other.path(), false);
    g2.spool = g.spool.clone();
    assert!(g2.validate().is_err());
    // Gateway server listening with a loopback token, or collector behind mTLS, is refused.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (g3, _, _) = config(Route::new("http://127.0.0.1:9/").unwrap(), Observer::Gateway, other.path(), false);
    assert!(gateway::serve(l, ListenerAuth::LoopbackToken(TOKEN.into()), g3).await.is_err());
    println!("PROBE config validation: all fail-closed cases refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_collector_checks_gateway_hostname_and_server_eku() {
    let (p, calls, _p) = provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    // Correct CA, but address not in SAN (::1).
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), false);
    let l6 = TcpListener::bind("[::1]:0").await.unwrap();
    let a6 = l6.local_addr().unwrap();
    let _g6 = Task(tokio::spawn(async move { let _ = gateway::serve(l6, tls(), g).await; }));
    // Correct CA, but a client-auth-only certificate presented as server.
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, dir.path(), false);
    let bad = gateway::server_tls(include_bytes!("fixtures/gateway-tls/client.pem"), include_bytes!("fixtures/gateway-tls/client.key"), CA).unwrap();
    let (eku_url, _ge) = start(ListenerAuth::MutualTls(bad), g).await;
    for url in [format!("https://[::1]:{}/v1/forward", a6.port()), eku_url] {
        let cdir = tempfile::tempdir().unwrap();
        let (c, ch, _) = config(Route::mutual_tls(&url, CA, ID).unwrap(), Observer::Collector, cdir.path(), false);
        let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
        let r = reqwest::Client::new().post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap();
        println!("PROBE server identity {url} -> {}", r.status());
        assert_eq!(r.status(), 502);
        assert_eq!(ch.lock().unwrap().last().unwrap().outcome, Some(Outcome::OutcomeUnknown));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_serve_shutdown_releases_inflight_provider_stream() {
    let mut resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    resp.extend_from_slice(b"1\r\nx\r\n");
    let (origin, _calls, _h, closed, _p) = raw_provider(resp, true).await;
    let dir = tempfile::tempdir().unwrap();
    let (g, h, _) = config(Route::new(&origin).unwrap(), Observer::Gateway, dir.path(), true);
    let (url, server) = start(tls(), g).await;
    let mut r = client(CA, true).post(&url).header("x-kan-exchange", hex(&[11; 32])).body("x").send().await.unwrap();
    let _ = r.chunk().await.unwrap();
    drop(server); // aborts the serve future, as process shutdown/cancel would
    let ok = tokio::time::timeout(Duration::from_secs(5), async {
        while closed.load(Ordering::SeqCst) == 0 { tokio::time::sleep(Duration::from_millis(20)).await; }
    }).await;
    let rest = tokio::time::timeout(Duration::from_secs(5), r.chunk()).await;
    println!("PROBE shutdown: provider released={} downstream={:?} last={:?}", ok.is_ok(), rest.as_ref().map(|x| x.as_ref().map(|_| ()).map_err(|_| "err")), h.lock().unwrap().last().map(|x| x.outcome));
    assert!(ok.is_ok());
    assert!(matches!(rest, Ok(Err(_))), "shutdown looked like clean EOF");
}
