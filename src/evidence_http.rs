//! Bounded loopback transport for the experimental opaque service.
use crate::evidence_proof_service as proof;
use crate::evidence_service::{Failure, Service, SignedReply, MAX_REQUEST};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Semaphore};

const MAX_REPLY: usize = 32 * 1024 * 1024;
enum Hosted {
    Legacy(Box<Service>),
    Admitted(Box<crate::evidence_service::AdmittingService>),
    Proof(Box<proof::Service>),
}
impl Hosted {
    fn dispatch(&mut self, bytes: &[u8], now: u64) -> Result<Vec<u8>, Failure> {
        match self {
            Self::Admitted(service) => service.dispatch(bytes, now)?.bytes(),
            Self::Legacy(service) => service.dispatch(bytes, now)?.bytes(),
            Self::Proof(service) => service.dispatch(bytes, now)?.bytes(),
        }
    }
}
#[derive(Clone, Copy)]
struct Route {
    path: &'static str,
    request_limit: usize,
}
const LEGACY: Route = Route {
    path: "/v1/rpc",
    request_limit: MAX_REQUEST,
};
const PROOF: Route = Route {
    path: "/v2/read",
    request_limit: proof::MAX_REQUEST,
};
fn response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}
async fn handle(
    request: Request<Incoming>,
    service: Arc<Mutex<Hosted>>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    route: Route,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != hyper::Method::POST
        || request.uri().path_and_query().map(|p| p.as_str()) != Some(route.path)
    {
        return Ok(response(
            StatusCode::NOT_FOUND,
            b"{\"error\":\"unsupported-route\"}".to_vec(),
        ));
    }
    let body = match tokio::time::timeout(
        Duration::from_secs(15),
        Limited::new(request.into_body(), route.request_limit).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            return Ok(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                b"{\"error\":\"invalid-body\"}".to_vec(),
            ))
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::Unavailable)?
            .as_secs();
        service
            .lock()
            .map_err(|_| Failure::Unavailable)?
            .dispatch(&body, now)
    })
    .await;
    Ok(match result {
        Ok(Ok(bytes)) => response(StatusCode::OK, bytes),
        _ => response(
            StatusCode::SERVICE_UNAVAILABLE,
            b"{\"error\":\"unavailable\"}".to_vec(),
        ),
    })
}

/// Caller may bind port zero and announce the returned address. Non-loopback is refused.
pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::other(
            "experimental listener requires loopback",
        ));
    }
    TcpListener::bind(address).await
}
/// One bounded request per connection. Aborting this accept loop stops new work;
/// already accepted commits may finish, so clients retry original request bytes.
pub async fn serve(listener: TcpListener, service: Service) -> std::io::Result<()> {
    serve_inner(listener, Hosted::Legacy(Box::new(service)), LEGACY).await
}
/// Owner-selected profile-2 ingest using existing signed append requests.
pub async fn serve_admitted(
    listener: TcpListener,
    service: crate::evidence_service::AdmittingService,
) -> std::io::Result<()> {
    serve_inner(listener, Hosted::Admitted(Box::new(service)), LEGACY).await
}
/// Explicit proof-reader endpoint. No legacy fallback or write command.
pub async fn serve_proof(listener: TcpListener, service: proof::Service) -> std::io::Result<()> {
    serve_inner(listener, Hosted::Proof(Box::new(service)), PROOF).await
}
async fn serve_inner(listener: TcpListener, service: Hosted, route: Route) -> std::io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::other(
            "experimental listener requires loopback",
        ));
    }
    let service = Arc::new(Mutex::new(service));
    let slots = Arc::new(Semaphore::new(16));
    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(std::io::Error::other)?;
        let (stream, _) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            let permit = Arc::new(permit);
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.keep_alive(false).max_buf_size(16 * 1024);
            let connection = builder.serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(move |request| {
                    handle(request, service.clone(), permit.clone(), route)
                }),
            );
            // Never log the connection error: request fragments may contain data.
            let _ = tokio::time::timeout(Duration::from_secs(30), connection).await;
        });
    }
}

/// HTTPS or literal loopback HTTP only; no ambient proxy, redirects or credentials.
pub async fn send(endpoint: &str, issuer: &str, request: &[u8]) -> Result<SignedReply, Failure> {
    let bytes = exchange(endpoint, request, LEGACY, MAX_REPLY).await?;
    let reply: SignedReply = serde_json::from_slice(&bytes).map_err(|_| Failure::Invalid)?;
    if reply.bytes()? != bytes {
        return Err(Failure::Invalid);
    }
    reply.verify(request, issuer)?;
    Ok(reply)
}
/// The caller explicitly chooses the proof protocol and its expected issuer.
pub async fn send_proof(
    endpoint: &str,
    issuer: &str,
    request: &[u8],
) -> Result<proof::SignedReply, Failure> {
    let bytes = exchange(endpoint, request, PROOF, proof::MAX_REPLY).await?;
    proof::SignedReply::decode(&bytes, request, issuer)
}
async fn exchange(
    endpoint: &str,
    request: &[u8],
    route: Route,
    max_reply: usize,
) -> Result<Vec<u8>, Failure> {
    if request.len() > route.request_limit {
        return Err(Failure::Invalid);
    }
    let url = reqwest::Url::parse(endpoint).map_err(|_| Failure::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.path() != route.path
    {
        return Err(Failure::Invalid);
    }
    let loopback = url
        .host_str()
        .and_then(|h| {
            h.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|a| a.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(Failure::Invalid);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| Failure::Unavailable)?;
    let mut response = client
        .post(url)
        .header("content-type", "application/json")
        .body(request.to_vec())
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Failure::Unavailable);
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_reply as u64)
    {
        return Err(Failure::Invalid);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Unavailable)? {
        if bytes.len() + chunk.len() > max_reply {
            return Err(Failure::Invalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
