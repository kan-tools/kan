//! Experimental single-tenant collector/gateway. TLS terminates in this process.
use crate::{evidence_capture as capture, evidence_spool::Spool, sign::Identity};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, Limited};
use hyper::{
    body::{Body, Bytes, Frame, Incoming},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::TcpListener,
    sync::{oneshot, Semaphore},
    task::{JoinHandle, JoinSet},
};

pub type HealthReporter = Arc<dyn Fn(&capture::Health) + Send + Sync>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    Opaque,
    Anthropic,
}
pub struct Config {
    pub profile: Profile,
    pub provider_key: Option<reqwest::header::HeaderValue>,
    pub route: capture::Route,
    pub observer: capture::Observer,
    pub spool: PathBuf,
    pub signer: Identity,
    pub recipient: [u8; 32],
    pub io_budget: Duration,
    pub report: HealthReporter,
}
impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.profile == Profile::Anthropic
            && (!self.route.is_origin()
                || self.observer == capture::Observer::Gateway
                    && self
                        .provider_key
                        .as_ref()
                        .is_none_or(|k| k.is_empty() || k.len() > 4096))
        {
            return Err(invalid());
        }
        if self.provider_key.is_some()
            && (self.observer != capture::Observer::Gateway || self.profile != Profile::Anthropic)
        {
            return Err(invalid());
        }
        if self.observer == capture::Observer::Collector && !self.route.is_mutual_tls() {
            return Err(invalid());
        }
        if self.io_budget.is_zero() || self.io_budget > Duration::from_secs(86400) {
            return Err(invalid());
        }
        if let Ok(mut spool) = Spool::open_for_capture(&self.spool) {
            if let Ok(status) = spool.status() {
                if status.writer != self.signer.did().as_str() {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::other("invalid gateway configuration or transport")
}

/// Explicit owner-controlled file. The parent directory remains a trust boundary.
pub fn secret_file(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > 65536 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let file = std::fs::File::open(path)?;
        let after = file.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid());
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        Err(invalid())
    }
}
/// TLS 1.3, required client authentication, no early data. The explicit CA grants
/// access to this single-tenant instance; replace roots/restart to revoke access.
pub struct ServerTls(Arc<rustls::ServerConfig>);
pub fn server_tls(cert: &[u8], key: &[u8], client_ca: &[u8]) -> io::Result<ServerTls> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(client_ca) {
        roots
            .add(cert.map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|_| invalid())?;
    let certs = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| invalid())?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|_| invalid())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(ServerTls(Arc::new(config)))
}
pub enum ListenerAuth {
    MutualTls(ServerTls),
    /// Only permitted on literal loopback. At least 32 printable ASCII bytes.
    LoopbackToken(String),
}
impl ListenerAuth {
    pub fn validate(&self, address: SocketAddr) -> io::Result<()> {
        match self {
            Self::LoopbackToken(t)
                if !address.ip().is_loopback()
                    || t.len() < 32
                    || t.len() > 256
                    || !t.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                Err(invalid())
            }
            _ => Ok(()),
        }
    }
}

type HttpBody = UnsyncBoxBody<Bytes, io::Error>;
fn error(status: StatusCode) -> Response<HttpBody> {
    let mut r = Response::new(
        Full::new(Bytes::from_static(b"{\"error\":\"gateway-unavailable\"}"))
            .map_err(|e: Infallible| match e {})
            .boxed_unsync(),
    );
    *r.status_mut() = status;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}
struct AbortTask(JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct StreamBody {
    reader: DuplexStream,
    complete: Arc<AtomicBool>,
    _task: AbortTask,
    ended: bool,
}
impl Body for StreamBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let mut bytes = [0; 16384];
        let mut buf = ReadBuf::new(&mut bytes);
        match Pin::new(&mut self.reader).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                self.ended = true;
                if self.complete.load(Ordering::Acquire) {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(io::Error::other("upstream outcome unknown"))))
                }
            }
            Poll::Ready(Ok(())) => {
                Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(buf.filled())))))
            }
        }
    }
}
struct HttpOutput {
    writer: DuplexStream,
    head: Option<oneshot::Sender<(u16, reqwest::header::HeaderMap)>>,
}
impl AsyncWrite for HttpOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
impl capture::HttpOutput for HttpOutput {
    fn head(
        &mut self,
        status: u16,
        headers: &reqwest::header::HeaderMap,
    ) -> Result<(), capture::Error> {
        self.head
            .take()
            .ok_or(capture::Error::OutcomeUnknown)?
            .send((status, headers.clone()))
            .map_err(|_| capture::Error::OutcomeUnknown)
    }
}
async fn handle(
    request: Request<Incoming>,
    config: Arc<Config>,
    token: Option<String>,
) -> Result<Response<HttpBody>, Infallible> {
    if let Some(token) = token {
        let mut found = false;
        for name in ["authorization", "x-api-key"] {
            let values = request.headers().get_all(name);
            if values.iter().count() > 1 {
                return Ok(error(StatusCode::UNAUTHORIZED));
            }
            if let Some(value) = values.iter().next() {
                found = true;
                let expected = if name == "authorization" {
                    format!("Bearer {token}")
                } else {
                    token.clone()
                };
                if value.as_bytes() != expected.as_bytes() {
                    return Ok(error(StatusCode::UNAUTHORIZED));
                }
            }
        }
        if !found {
            return Ok(error(StatusCode::UNAUTHORIZED));
        }
    }
    if request.method() != hyper::Method::POST {
        return Ok(error(StatusCode::NOT_FOUND));
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("");
    let selected_route = match config.profile {
        Profile::Opaque if path == "/v1/forward" => None,
        Profile::Anthropic => match config.route.anthropic_path(path) {
            Ok(r) => Some(r),
            Err(_) => return Ok(error(StatusCode::NOT_FOUND)),
        },
        _ => return Ok(error(StatusCode::NOT_FOUND)),
    };
    let metadata = if config.profile == Profile::Anthropic {
        Some(request.headers().clone())
    } else {
        None
    };
    let mut outgoing = reqwest::header::HeaderMap::new();
    if config.profile == Profile::Anthropic {
        let clean = end_to_end(request.headers());
        for (name, value) in &clean {
            if name.as_str().starts_with("anthropic-")
                || name.as_str().starts_with("x-claude-code-")
                || matches!(
                    name.as_str(),
                    "content-type"
                        | "content-encoding"
                        | "accept"
                        | "accept-encoding"
                        | "user-agent"
                        | "x-request-id"
                )
            {
                outgoing.append(name.clone(), value.clone());
            }
        }
        if let Some(key) = &config.provider_key {
            outgoing.insert("x-api-key", key.clone());
        }
    }
    let exchange = if config.observer == capture::Observer::Collector {
        use rand::RngCore;
        let mut nonce = [0; 32];
        if rand::rngs::OsRng.try_fill_bytes(&mut nonce).is_err() {
            return Ok(error(StatusCode::SERVICE_UNAVAILABLE));
        }
        crate::evidence_service::hex(&nonce)
    } else {
        let Some(value) = request
            .headers()
            .get("x-kan-exchange")
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(error(StatusCode::BAD_REQUEST));
        };
        if request.headers().get_all("x-kan-exchange").iter().count() != 1
            || crate::evidence_service::unhex(value, 32).map_or(true, |v| v.len() != 32)
        {
            return Ok(error(StatusCode::BAD_REQUEST));
        }
        value.to_owned()
    };
    let bytes = match tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(request.into_body(), capture::MAX_REQUEST).collect(),
    )
    .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        _ => return Ok(error(StatusCode::PAYLOAD_TOO_LARGE)),
    };
    let (reader, writer) = tokio::io::duplex(capture::CHUNK);
    let (tx, rx) = oneshot::channel();
    let complete = Arc::new(AtomicBool::new(false));
    let completed = complete.clone();
    let profile = config.profile;
    let task = AbortTask(tokio::spawn(async move {
        let mut output = HttpOutput {
            writer,
            head: Some(tx),
        };
        let mut spool = Spool::open_for_capture(&config.spool).ok();
        let mut sink = capture::EncryptedSpool {
            spool: spool.as_mut(),
            signer: &config.signer,
            recipient: config.recipient,
        };
        let mut headers = outgoing;
        if config.observer == capture::Observer::Collector {
            headers.insert(
                "x-kan-exchange",
                reqwest::header::HeaderValue::from_str(&exchange).expect("hex"),
            );
        }
        let result = capture::forward_http(
            selected_route.as_ref().unwrap_or(&config.route),
            capture::ForwardInput {
                body: bytes.to_vec(),
                observer: config.observer,
                headers,
                exchange: Some(exchange),
                metadata,
            },
            &mut sink,
            &mut |h| (config.report)(h),
            &mut output,
            config.io_budget,
        )
        .await;
        completed.store(result.is_ok(), Ordering::Release);
        // Writer drops after the completion flag. Failed streams cannot look like EOF.
    }));
    let (status, headers) = match rx.await {
        Ok(s) => s,
        Err(_) => return Ok(error(StatusCode::BAD_GATEWAY)),
    };
    let mut response = Response::new(
        StreamBody {
            reader,
            complete,
            _task: task,
            ended: false,
        }
        .boxed_unsync(),
    );
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    if profile == Profile::Anthropic {
        *response.headers_mut() = end_to_end(&headers);
    } else {
        response.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static("application/octet-stream"),
        );
    }
    response.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// Stops owned connection tasks when canceled. Bind first to announce the actual
/// address; this validates the actual listener, not an unchecked CLI string.
pub async fn serve(listener: TcpListener, auth: ListenerAuth, config: Config) -> io::Result<()> {
    auth.validate(listener.local_addr()?)?;
    config.validate()?;
    if matches!(&auth, ListenerAuth::MutualTls(_)) && config.observer != capture::Observer::Gateway
        || matches!(&auth, ListenerAuth::LoopbackToken(_))
            && config.observer != capture::Observer::Collector
    {
        return Err(invalid());
    }
    let config = Arc::new(config);
    let permits = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (stream,_)=accepted?;
                let Ok(permit)=permits.clone().try_acquire_owned() else { drop(stream);continue; };
                let config=config.clone();
                match &auth {
                    ListenerAuth::MutualTls(tls)=>{
                        let acceptor=tokio_rustls::TlsAcceptor::from(tls.0.clone());
                        tasks.spawn(async move {
                            let _permit=permit;
                            let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(15),acceptor.accept(stream)).await else{return;};
                            connection(stream,config,None).await;
                        });
                    },
                    ListenerAuth::LoopbackToken(token)=>{
                        let token=token.clone();
                        tasks.spawn(async move {let _permit=permit;connection(stream,config,Some(token)).await;});
                    }
                }
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
}
async fn connection<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    config: Arc<Config>,
    token: Option<String>,
) {
    let service = hyper::service::service_fn(move |r| handle(r, config.clone(), token.clone()));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(32768)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15));
    let _ = tokio::time::timeout(
        Duration::from_secs(86400),
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
}

fn end_to_end(input: &reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
    let nominated: Vec<String> = input
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    let mut output = reqwest::header::HeaderMap::new();
    for (name, value) in input {
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
                | "authorization"
                | "x-api-key"
                | "cookie"
                | "set-cookie"
        ) || name.as_str().starts_with("x-kan-")
            || nominated.iter().any(|n| n == name.as_str())
        {
            continue;
        }
        output.append(name.clone(), value.clone());
    }
    output
}
