//! Loopback-only presentation of private operations observations; no mutation API.
use crate::evidence_operations::Journal;
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, io, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
const HTML: &str = include_str!("../web/operations/index.html");
const JS: &str = include_str!("../web/operations/app.js");
const THEME: &str = include_str!("../web/theme.js");
const CSS: &str = include_str!("../web/operations/style.css");
fn response(code: StatusCode, mime: &'static str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = code;
    for (key,value) in [("content-type",mime),("cache-control","no-store"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"),("cross-origin-resource-policy","same-origin")] {
        r.headers_mut().insert(key,hyper::header::HeaderValue::from_static(value));
    }
    r
}
fn denied(code: StatusCode) -> Response<Full<Bytes>> {
    response(
        code,
        "application/json",
        r#"{"error":"status unavailable or request refused"}"#,
    )
}
async fn handle(
    r: Request<Incoming>,
    host: String,
    token: Arc<String>,
    journal: PathBuf,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if r.headers().get("host").and_then(|v| v.to_str().ok()) != Some(host.as_str())
        || r.headers()
            .get("origin")
            .is_some_and(|v| v.to_str().ok() != Some(format!("http://{host}").as_str()))
    {
        return Ok(denied(StatusCode::FORBIDDEN));
    }
    if r.method() != hyper::Method::GET {
        return Ok(denied(StatusCode::METHOD_NOT_ALLOWED));
    }
    let path = r.uri().path_and_query().map(|p| p.as_str());
    Ok(match path {
        Some("/") => response(StatusCode::OK, "text/html; charset=utf-8", HTML),
        Some("/theme.js") => response(StatusCode::OK, "text/javascript; charset=utf-8", THEME),
        Some("/app.js") => response(StatusCode::OK, "text/javascript; charset=utf-8", JS),
        Some("/style.css") => response(StatusCode::OK, "text/css; charset=utf-8", CSS),
        Some("/api/status") => {
            let wanted = format!("Bearer {token}");
            if r.headers().get_all("authorization").iter().count() != 1
                || r.headers().get("authorization").map(|v| v.as_bytes()) != Some(wanted.as_bytes())
            {
                return Ok(denied(StatusCode::UNAUTHORIZED));
            }
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                Journal::open(&journal)?.snapshot()
            })
            .await
            {
                Ok(Ok(snapshot)) => match serde_json::to_vec(&snapshot) {
                    Ok(bytes) => response(StatusCode::OK, "application/json", bytes),
                    Err(_) => denied(StatusCode::SERVICE_UNAVAILABLE),
                },
                _ => denied(StatusCode::SERVICE_UNAVAILABLE),
            }
        }
        _ => denied(StatusCode::NOT_FOUND),
    })
}
/// A single request per connection; bounded clients and slow-header deadline.
pub async fn serve(listener: TcpListener, token: String, journal: PathBuf) -> io::Result<()> {
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback()
        || token.len() < 32
        || token.len() > 4096
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(io::Error::other("invalid dashboard configuration"));
    }
    let host = addr.to_string();
    let token = Arc::new(token);
    let slots = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (stream,_)=accepted?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {continue;};
                let host=host.clone();let token=token.clone();let journal=journal.clone();
                tasks.spawn(async move {
                    // Keep the permit alive through the blocking snapshot read too.
                    let permit=Arc::new(permit);
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.keep_alive(false).max_buf_size(16384).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(5));
                    let service=hyper::service::service_fn(move |r|{handle(r,host.clone(),token.clone(),journal.clone(),permit.clone())});
                    let _=tokio::time::timeout(Duration::from_secs(10),builder.serve_connection(TokioIo::new(stream),service)).await;
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
}
