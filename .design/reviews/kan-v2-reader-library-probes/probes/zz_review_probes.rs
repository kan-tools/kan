#![cfg(feature = "v2-crypto")]
// Independent review probes (temporary copy in tests/; removed after run).
use kan::{
    evidence_crypto as crypto,
    evidence_reader::{Reader, ScopeAccess},
    evidence_service::{self as svc, Command, Grant, Request, Service, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};
use std::time::Duration;

struct Guard(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Guard { fn drop(&mut self) { self.0.abort(); } }

fn append(service: &mut Service, writer: &Identity, issuer: &str, scope: [u8; 32], private: [u8; 32], n: u64, prev: Option<String>, plain: &[u8]) -> String {
    let req = SignedRequest::sign(Request { version: 1, scope: svc::hex(&scope), principal: writer.did().to_string(), audience: issuer.into(), expires: None,
        command: Command::Append { id: format!("{:032x}", n + 1), position: n, previous: prev,
            ciphertext: svc::hex(&crypto::seal(&crypto::public_key(&private).unwrap(), &scope, plain).unwrap()) } }, writer).unwrap().bytes().unwrap();
    let reply = service.dispatch(&req, kan::evidence_operations::now()).unwrap();
    let Ok(svc::Output::Committed { record, .. }) = reply.reply.result else { panic!("append") };
    let kan::evidence::Decoded::Known(m) = kan::evidence::decode(&svc::unhex(&record.manifest, kan::evidence::MAX_RECORD_BYTES).unwrap()).unwrap() else { panic!() };
    m.cid().to_string()
}

struct Built { _dir: tempfile::TempDir, root: std::path::PathBuf, issuer: String, scope: [u8; 32], private: [u8; 32], owner_key: std::path::PathBuf, reader: Identity, reader_key: std::path::PathBuf, writer: Identity }
fn build(scope_byte: u8, n: usize) -> Built {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let owner = Identity::generate(); let owner_key = dir.path().join("owner.key"); owner.save(&owner_key).unwrap();
    let reader = Identity::generate(); let reader_key = dir.path().join("reader.key"); reader.save(&reader_key).unwrap();
    let writer = Identity::generate();
    let scope = [scope_byte; 32]; let private = [scope_byte.wrapping_add(1); 32];
    let issuer = owner.did().to_string();
    let mut service = Service::new(Ledger::create(&root).unwrap(), scope, owner, grants(&reader, &writer)).unwrap();
    let mut prev = None;
    for i in 0..n { prev = Some(append(&mut service, &writer, &issuer, scope, private, i as u64, prev, format!("record {}", i + 1).as_bytes())); }
    drop(service);
    Built { _dir: dir, root, issuer, scope, private, owner_key, reader, reader_key, writer }
}
fn grants(reader: &Identity, writer: &Identity) -> Vec<Grant> {
    vec![Grant { principal: reader.did().to_string(), append: false, inventory: true }, Grant { principal: writer.did().to_string(), append: true, inventory: false }]
}
async fn serve(b: &Built) -> (String, Guard) {
    let service = Service::new(Ledger::open(&b.root).unwrap(), b.scope, Identity::load_existing(&b.owner_key).unwrap(), grants(&b.reader, &b.writer));
    let service = match service { Ok(s) => s, Err(e) => panic!("service restart refused: {e:?}") };
    let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    (endpoint, Guard(tokio::spawn(kan::evidence_http::serve(listener, service))))
}
fn access(b: &Built, endpoint: &str) -> ScopeAccess { ScopeAccess { scope: b.scope, endpoint: endpoint.into(), issuer: b.issuer.clone(), private_key: b.private } }

fn sql(b: &Built, statement: &str) {
    let conn = rusqlite::Connection::open(b.root.join("archive.sqlite")).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    let cid: String = conn.query_row("SELECT ciphertext FROM bindings b JOIN commits c ON c.cid=b.first_manifest WHERE c.sequence=1", [], |r| r.get(0)).unwrap();
    let n = conn.execute(statement, [cid]).unwrap();
    println!("PROBE sql affected rows={n}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_missing_and_corrupt_object_states() {
    for (label, statement) in [("missing-object", "DELETE FROM objects WHERE cid=?1"), ("corrupt-object", "UPDATE objects SET bytes=x'00' WHERE cid=?1")] {
        let b = build(51, 3);
        let (endpoint, _g) = serve(&b).await;
        sql(&b, statement); // after service startup audit (raw writer change)
        let reader = Reader::new(Identity::load_existing(&b.reader_key).unwrap(), vec![access(&b, &endpoint)]).unwrap();
        let pin = reader.snapshot(&svc::hex(&b.scope)).await;
        println!("PROBE {label} snapshot ok={} err={:?}", pin.is_ok(), pin.as_ref().err());
        let pin = pin.unwrap();
        let p0 = reader.page(&pin, 0, 40).await; println!("PROBE {label} page(after=0) => {:?}", p0.as_ref().map(|p| p.records.len()));
        let p1 = reader.page(&pin, 1, 40).await; println!("PROBE {label} page(after=1) => {:?}", p1.as_ref().map(|p| p.records.len()));
        let s1 = reader.source(&pin, 1, 0, 100).await; println!("PROBE {label} source(1) => {:?}", s1.as_ref().map(|s| s.total_bytes));
        let s2 = reader.source(&pin, 2, 0, 100).await; println!("PROBE {label} source(2) => {:?}", s2.as_ref().map(|s| s.total_bytes));
        let s9 = reader.source(&pin, 9, 0, 100).await; println!("PROBE {label} source(9, beyond pin) => {:?}", s9.as_ref().map(|s| s.total_bytes));
    }
}

async fn library(reader: Reader) -> (String, Guard) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr.to_string(), Guard(tokio::spawn(kan::evidence_library::serve(listener, "probe-token-probe-token-probe-token-0".into(), reader))))
}
fn post(client: &reqwest::Client, host: &str, body: serde_json::Value) -> reqwest::RequestBuilder {
    client.post(format!("http://{host}/api/library")).header("content-type", "application/json").bearer_auth("probe-token-probe-token-probe-token-0").body(body.to_string())
}

/// MITM/forged reply signature: catalog should fail closed visibly, not look like revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_catalog_tampered_signature_and_unreachable_scope() {
    use http_body_util::{BodyExt, Full};
    let b = build(61, 1);
    let service = std::sync::Arc::new(std::sync::Mutex::new(Service::new(Ledger::open(&b.root).unwrap(), b.scope, Identity::load_existing(&b.owner_key).unwrap(), grants(&b.reader, &b.writer)).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let tamper = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (s2, t2) = (service.clone(), tamper.clone());
    let _srv = tokio::spawn(async move { loop { let (stream, _) = listener.accept().await.unwrap(); let (s, t) = (s2.clone(), t2.clone()); tokio::spawn(async move {
        let h = hyper::service::service_fn(move |r: hyper::Request<hyper::body::Incoming>| { let (s, t) = (s.clone(), t.clone()); async move {
            let bytes = r.into_body().collect().await.unwrap().to_bytes();
            let mut reply = s.lock().unwrap().dispatch(&bytes, kan::evidence_operations::now()).unwrap();
            if t.load(std::sync::atomic::Ordering::SeqCst) { reply.signature = "00".repeat(64); }
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(hyper::body::Bytes::from(reply.bytes().unwrap()))))
        }});
        let _ = hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(hyper_util::rt::TokioIo::new(stream), h).await; }); } });
    let reader = Reader::new(Identity::load_existing(&b.reader_key).unwrap(), vec![access(&b, &endpoint)]).unwrap();
    let (host, _lib) = library(reader).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let r = post(&client, &host, serde_json::json!({"action":"catalog"})).send().await.unwrap();
    println!("PROBE catalog honest status={} body={}", r.status(), r.text().await.unwrap().len());
    tamper.store(true, std::sync::atomic::Ordering::SeqCst);
    let r = post(&client, &host, serde_json::json!({"action":"catalog"})).send().await.unwrap();
    println!("PROBE catalog forged-signature status={} body={}", r.status(), r.text().await.unwrap());
    let r = post(&client, &host, serde_json::json!({"action":"snapshot","scope":svc::hex(&b.scope)})).send().await.unwrap();
    println!("PROBE snapshot forged-signature status={} body={}", r.status(), r.text().await.unwrap());

    // Second reader: one good scope + one unreachable configured scope.
    tamper.store(false, std::sync::atomic::Ordering::SeqCst);
    let c = build(62, 1);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let dead = format!("http://{}/v1/rpc", closed.local_addr().unwrap()); drop(closed);
    let reader = Reader::new(Identity::load_existing(&b.reader_key).unwrap(), vec![access(&b, &endpoint), access(&c, &dead)]).unwrap();
    let (host, _lib2) = library(reader).await;
    let r = post(&client, &host, serde_json::json!({"action":"catalog"})).send().await.unwrap();
    println!("PROBE catalog with one unreachable scope status={} body={}", r.status(), r.text().await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_principal_reuse_offline_paths_and_slots() {
    let b = build(71, 2);
    let (endpoint, g) = serve(&b).await;
    // Reader signer equal to the storage service issuer is accepted at construction.
    let same = Reader::new(Identity::load_existing(&b.owner_key).unwrap(), vec![access(&b, &endpoint)]);
    println!("PROBE Reader::new(signer == storage issuer) ok={}", same.is_ok());
    let reader = Reader::new(Identity::load_existing(&b.reader_key).unwrap(), vec![access(&b, &endpoint)]).unwrap();
    let pin = reader.snapshot(&svc::hex(&b.scope)).await.unwrap();
    drop(g); tokio::time::sleep(Duration::from_millis(100)).await; // service gone: no remote authority reachable
    println!("PROBE service down: source(beyond pin) => {:?}", reader.source(&pin, 3, 0, 10).await.err());
    println!("PROBE service down: page(after>through) => {:?}", reader.page(&pin, 3, 1).await.err());
    println!("PROBE service down: source(1) => {:?}", reader.source(&pin, 1, 0, 10).await.err());

    // Connection slot exhaustion by idle local sockets.
    let (endpoint, _g2) = serve(&b).await;
    let reader = Reader::new(Identity::load_existing(&b.reader_key).unwrap(), vec![access(&b, &endpoint)]).unwrap();
    let (host, _lib) = library(reader).await;
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(3)).build().unwrap();
    let ok = client.get(format!("http://{host}/")).send().await.map(|r| r.status());
    println!("PROBE GET / baseline => {:?}", ok);
    let idle: Vec<_> = futures_idle(&host, 4).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t = std::time::Instant::now();
    let blocked = client.get(format!("http://{host}/")).send().await.map(|r| r.status());
    println!("PROBE GET / with 4 idle sockets => ok={} err={:?} after {:?}", blocked.is_ok(), blocked.as_ref().err().map(|e| e.to_string()), t.elapsed());
    tokio::time::sleep(Duration::from_secs(6)).await;
    let after = client.get(format!("http://{host}/")).send().await.map(|r| r.status());
    println!("PROBE GET / after header timeout => {:?}", after);
    drop(idle);
    // Host/Origin variants
    for (h, o) in [("localhost", None), ("127.0.0.1", None), ("", Some("null"))] {
        let host_header = if h.is_empty() { host.clone() } else { format!("{h}:{}", host.rsplit(':').next().unwrap()) };
        let mut rq = post(&client, &host, serde_json::json!({"action":"catalog"})).header("host", host_header.clone());
        if let Some(o) = o { rq = rq.header("origin", o); }
        println!("PROBE host={host_header} origin={o:?} => {}", rq.send().await.unwrap().status());
    }
}
async fn futures_idle(host: &str, n: usize) -> Vec<tokio::net::TcpStream> {
    let mut v = Vec::new();
    for _ in 0..n { v.push(tokio::net::TcpStream::connect(host).await.unwrap()); }
    v
}
