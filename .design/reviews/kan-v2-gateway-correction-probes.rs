
// ===== Reviewer hostile probes for 4be3f28 (appended to a copy of the
// committed tests/evidence_gateway.rs so its fixtures are reused verbatim). =====

fn rp_metadata(dir: &std::path::Path, did: &str, want: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (h, _) in frames(&dir.join("spool"), did) {
        if let capture::Event::HttpMetadata {
            direction, headers, ..
        } = h.event
        {
            if direction == want {
                out.extend(headers);
            }
        }
    }
    out
}

/// R1: headers the HTTP library adds at execute() time are not in
/// `request-outgoing`, although they are application headers (not framing/host).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_library_added_accept_is_absent_from_outgoing_metadata() {
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (origin, requests, _t, gdid, cdid) = anthropic_pair(gd.path(), cd.path()).await;
    let u = reqwest::Url::parse(&origin).unwrap();
    let mut s = tokio::net::TcpStream::connect((u.host_str().unwrap(), u.port().unwrap()))
        .await
        .unwrap();
    // No Accept header from the harness.
    s.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nx-api-key: {TOKEN}\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut response)).await;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&response));
    let provider_head = requests.lock().unwrap()[0].0.to_ascii_lowercase();
    let gw_out = rp_metadata(gd.path(), &gdid, "request-outgoing");
    let gw_in = rp_metadata(gd.path(), &gdid, "request");
    let col_out = rp_metadata(cd.path(), &cdid, "request-outgoing");
    println!("PROBE R1 provider head: {provider_head:?}");
    println!("PROBE R1 gateway request-outgoing names: {:?}", gw_out.iter().map(|h| &h.0).collect::<Vec<_>>());
    println!("PROBE R1 gateway incoming names: {:?}", gw_in.iter().map(|h| &h.0).collect::<Vec<_>>());
    println!("PROBE R1 collector request-outgoing names: {:?}", col_out.iter().map(|h| &h.0).collect::<Vec<_>>());
    let wire_accept = provider_head.contains("\r\naccept: */*");
    let recorded_accept = gw_out.iter().any(|h| h.0 == "accept");
    println!("PROBE R1 provider received accept */*: {wire_accept}; gateway outgoing metadata records accept: {recorded_accept}");
    let col_recorded = col_out.iter().any(|h| h.0 == "accept");
    let gw_saw = gw_in.iter().any(|h| h.0 == "accept");
    println!("PROBE R1 collector outgoing records accept: {col_recorded}; gateway saw accept from collector: {gw_saw}");
}

async fn rp_slow_provider() -> (String, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut one = [0];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut one).await.is_err() {
                        return;
                    }
                    head.push(one[0]);
                }
                let h = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let len = h
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap_or("0")
                    .parse::<usize>()
                    .unwrap();
                let mut body = vec![0; len];
                if s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n")
                    .await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = s.write_all(b"1\r\nb\r\n0\r\n\r\n").await;
            });
        }
    });
    (url, Task(task))
}

/// Attacker: continuously opens bare TCP connections at `per_sec` (0 = none),
/// holding only the most recent 48 (the server evicts older pending ones anyway).
fn rp_attacker(addr: std::net::SocketAddr, per_sec: u64, stop: Arc<std::sync::atomic::AtomicBool>, opened: Arc<AtomicUsize>) -> Task {
    Task(tokio::spawn(async move {
        if per_sec == 0 {
            return;
        }
        let mut held = std::collections::VecDeque::new();
        let gap = Duration::from_micros(1_000_000 / per_sec);
        let mut tick = tokio::time::interval(gap);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        while !stop.load(Ordering::Relaxed) {
            tick.tick().await;
            if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_millis(200), tokio::net::TcpStream::connect(addr)).await {
                opened.fetch_add(1, Ordering::Relaxed);
                held.push_back(s);
                if held.len() > 48 {
                    held.pop_front();
                }
            }
        }
    }))
}

/// R2: adversarial continuous arrivals against the mutual-TLS gateway and the
/// loopback collector. Reports legitimate success rates; also asserts that a
/// request which already received a 200 head is never truncated by eviction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rp_continuous_arrivals_success_rate() {
    for rate in [0u64, 200, 1000, 4000] {
        for hop in ["gateway-mtls", "collector-loopback"] {
            let (p, _pt) = rp_slow_provider().await;
            let gd = tempfile::tempdir().unwrap();
            let cd = tempfile::tempdir().unwrap();
            let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), true);
            let (remote, _g) = start(tls(), g).await;
            let (c, _, _) = config(Route::mutual_tls(&remote, CA, ID).unwrap(), Observer::Collector, cd.path(), true);
            let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
            let target = if hop == "gateway-mtls" { &remote } else { &local };
            let u = reqwest::Url::parse(target).unwrap();
            let addr: std::net::SocketAddr = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap()).parse().unwrap();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let opened = Arc::new(AtomicUsize::new(0));
            let _a = rp_attacker(addr, rate, stop.clone(), opened.clone());
            tokio::time::sleep(Duration::from_millis(300)).await;
            let (mut ok, mut refused, mut truncated) = (0, 0, 0);
            let started = std::time::Instant::now();
            for _ in 0..20 {
                // Through the collector so the gateway hop sees a real collector
                // client; attacker targets only one hop at a time.
                let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
                match c.post(&local).bearer_auth(TOKEN).body("x").send().await {
                    Ok(r) if r.status() == 200 => match r.bytes().await {
                        Ok(b) if b.as_ref() == b"ab" => ok += 1,
                        _ => truncated += 1,
                    },
                    _ => refused += 1,
                }
            }
            stop.store(true, Ordering::Relaxed);
            println!(
                "PROBE R2 hop={hop} attacker_rate={rate}/s opened={} legit ok={ok} refused={refused} truncated_after_200={truncated} elapsed={:?}",
                opened.load(Ordering::Relaxed),
                started.elapsed()
            );
            assert_eq!(truncated, 0, "an authenticated stream was cut by eviction");
        }
    }
}

/// R3: the mutual-TLS listener's eight authenticated slots (not covered by a
/// committed test): eight completed handshakes with no request occupy all slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_mtls_authenticated_slots_are_eight() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
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
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(ID).map(|c| c.unwrap()).collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(ID).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let mut held = Vec::new();
    for _ in 0..8 {
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from(u.host_str().unwrap().to_owned()).unwrap();
        held.push(connector.connect(name, tcp).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ninth = client(CA, true).post(&url).header("x-kan-exchange", hex(&[7; 32])).body("x").send().await;
    println!("PROBE R3 ninth with 8 idle authenticated TLS: {:?}", ninth.as_ref().map(|r| r.status()));
    assert!(ninth.is_err());
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = client(CA, true).post(&url).header("x-kan-exchange", hex(&[7; 32])).body("x").send().await.unwrap();
    println!("PROBE R3 after release: {}", after.status());
    assert_eq!(after.status(), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// R4: permits are released when downstream clients abandon streams mid-body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_abandoned_streams_release_collector_slots() {
    let (p, _pt) = rp_slow_provider().await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), true);
    let (remote, _g) = start(tls(), g).await;
    let (c, _, _) = config(Route::mutual_tls(&remote, CA, ID).unwrap(), Observer::Collector, cd.path(), true);
    let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    for round in 0..3 {
        let mut live = Vec::new();
        for _ in 0..8 {
            let c = reqwest::Client::builder().no_proxy().build().unwrap();
            let mut r = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap();
            assert_eq!(r.chunk().await.unwrap().unwrap(), "a");
            live.push(r);
        }
        let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap();
        let busy = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap().status();
        drop(live);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap();
        let status = r.status();
        let body = r.bytes().await.unwrap();
        println!("PROBE R4 round {round}: ninth while 8 streaming={busy}; after abandon={status} {body:?}");
        assert_eq!(busy, 503);
        assert_eq!(status, 200);
    }
}

/// R5: reset-before-accept storm (SO_LINGER=0 then close). `serve` propagates
/// any accept() error with `?`; check both listeners survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_reset_storm_does_not_kill_listeners() {
    let (p, calls, _p) =
        provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
    let (remote, gt) = start(tls(), g).await;
    let (c, _, _) = config(Route::mutual_tls(&remote, CA, ID).unwrap(), Observer::Collector, cd.path(), false);
    let (local, ct) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    for url in [&remote, &local] {
        let u = reqwest::Url::parse(url).unwrap();
        let addr: std::net::SocketAddr = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap()).parse().unwrap();
        for _ in 0..3000 {
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            if let Ok(s) = sock.connect(addr).await {
                let _ = s.set_linger(Some(Duration::ZERO));
                drop(s);
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!("PROBE R5 gateway task finished={} collector task finished={}", gt.0.is_finished(), ct.0.is_finished());
    let r = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap()
        .post(&local).bearer_auth(TOKEN).body("x").send().await;
    println!("PROBE R5 legit after storm: {:?}", r.as_ref().map(|r| r.status()));
    assert_eq!(r.unwrap().bytes().await.unwrap(), "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

async fn rp_held_provider(hold: Duration) -> (String, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/fixed", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut one = [0];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read_exact(&mut one).await.is_err() { return; }
                    head.push(one[0]);
                }
                let mut body = [0; 1];
                if s.read_exact(&mut body).await.is_err() { return; }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n").await;
                tokio::time::sleep(hold).await;
                let _ = s.write_all(b"1\r\nb\r\n0\r\n\r\n").await;
            });
        }
    });
    (url, Task(task))
}

/// R4b: held streams really occupy the eight collector slots; abandoning them
/// releases the slots (cancellation lifecycle).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rp_held_streams_occupy_then_release_slots() {
    let (p, _pt) = rp_held_provider(Duration::from_secs(60)).await;
    let gd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), true);
    let (remote, _g) = start(tls(), g).await;
    let (mut c, _, _) = config(Route::mutual_tls(&remote, CA, ID).unwrap(), Observer::Collector, cd.path(), true);
    c.io_budget = Duration::from_secs(120);
    let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
    let mut live = Vec::new();
    for _ in 0..8 {
        let c = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut r = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap();
        assert_eq!(r.chunk().await.unwrap().unwrap(), "a");
        live.push(r);
    }
    let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
    let busy = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap().status();
    drop(live);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut r = c.post(&local).bearer_auth(TOKEN).body("x").send().await.unwrap();
    let status = r.status();
    let first = r.chunk().await.unwrap();
    println!("PROBE R4b ninth while 8 held={busy}; after abandoning all 8={status} first={first:?}");
    assert_eq!(busy, 503);
    assert_eq!(status, 200);
}

/// One-way delay relay (models a remote collector→gateway RTT).
async fn rp_delay_relay(target: std::net::SocketAddr, one_way: Duration) -> (std::net::SocketAddr, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (inbound, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let Ok(outbound) = tokio::net::TcpStream::connect(target).await else { return };
                let (ir, iw) = inbound.into_split();
                let (or, ow) = outbound.into_split();
                async fn pump(mut r: impl tokio::io::AsyncRead + Unpin, mut w: impl tokio::io::AsyncWrite + Unpin + Send + 'static, d: Duration) {
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
                    let writer = tokio::spawn(async move {
                        while let Some((at, b)) = rx.recv().await {
                            tokio::time::sleep_until(at).await;
                            if w.write_all(&b).await.is_err() { return; }
                        }
                        let _ = w.shutdown().await;
                    });
                    let mut buf = vec![0; 16384];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { let _ = tx.send((tokio::time::Instant::now() + d, buf[..n].to_vec())); }
                        }
                    }
                    drop(tx);
                    let _ = writer.await;
                }
                tokio::join!(pump(ir, ow, one_way), pump(or, iw, one_way));
            });
        }
    });
    (addr, Task(task))
}

/// R6: continuous bare-TCP arrivals at the mutual-TLS gateway while the
/// legitimate collector reaches it across a 50 ms RTT. Measures the honest
/// residual: connection-rate, not CPU/bandwidth, denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rp_continuous_arrivals_remote_rtt() {
    for rate in [0u64, 300, 1000, 3000] {
        let (p, calls, _p) =
            provider(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()).await;
        let gd = tempfile::tempdir().unwrap();
        let cd = tempfile::tempdir().unwrap();
        let (g, _, _) = config(Route::new(&p).unwrap(), Observer::Gateway, gd.path(), false);
        let (remote, _g) = start(tls(), g).await;
        let ru = reqwest::Url::parse(&remote).unwrap();
        let gaddr: std::net::SocketAddr = format!("{}:{}", ru.host_str().unwrap(), ru.port().unwrap()).parse().unwrap();
        let (relay, _r) = rp_delay_relay(gaddr, Duration::from_millis(25)).await;
        let via = format!("https://{relay}/v1/forward");
        let (c, _, _) = config(Route::mutual_tls(&via, CA, ID).unwrap(), Observer::Collector, cd.path(), false);
        let (local, _c) = start(ListenerAuth::LoopbackToken(TOKEN.into()), c).await;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let opened = Arc::new(AtomicUsize::new(0));
        let _a = rp_attacker(gaddr, rate, stop.clone(), opened.clone());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (mut ok, mut failed) = (0, 0);
        let mut statuses = std::collections::BTreeMap::new();
        for _ in 0..20 {
            let c = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
            match c.post(&local).bearer_auth(TOKEN).body("x").send().await {
                Ok(r) => {
                    let s = r.status().as_u16();
                    *statuses.entry(s).or_insert(0) += 1;
                    if s == 200 && r.bytes().await.map(|b| b.as_ref() == b"ok").unwrap_or(false) { ok += 1 } else { failed += 1 }
                }
                Err(_) => { failed += 1; *statuses.entry(0).or_insert(0) += 1; }
            }
        }
        stop.store(true, Ordering::Relaxed);
        println!(
            "PROBE R6 rtt=50ms attacker_rate={rate}/s opened={} legit ok={ok} failed={failed} statuses={statuses:?} provider_calls={}",
            opened.load(Ordering::Relaxed), calls.load(Ordering::SeqCst)
        );
    }
}
