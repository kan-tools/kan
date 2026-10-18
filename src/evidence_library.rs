//! Human evidence Library. Loopback presentation with a separate read capability.
use crate::evidence_reader::{Pin, Reader};
use crate::evidence_service::Failure;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{convert::Infallible, io, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Query {
    Catalog,
    Snapshot {
        scope: String,
    },
    Page {
        pin: Pin,
        after: u64,
        limit: usize,
    },
    Source {
        pin: Pin,
        sequence: u64,
        offset: usize,
        length: usize,
    },
}
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
        r#"{"error":"reader request unavailable or refused"}"#,
    )
}
async fn query(reader: &Reader, query: Query) -> Result<serde_json::Value, Failure> {
    match query {
        Query::Catalog => {
            let mut scopes = Vec::new();
            for scope in reader.configured_scopes() {
                match reader.snapshot(&scope).await {
                    Ok(pin) => scopes.push(serde_json::json!({"scope":scope,"pin":pin})),
                    Err(Failure::AccessLimited) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(
                serde_json::json!({"version":1,"scopes":scopes,"capabilities":["snapshot-inventory","source-ranges","provenance"],"unavailable":["semantic-search","normalized-sessions","annotations","saved-views","analysis","administrative-jobs"]}),
            )
        }
        Query::Snapshot { scope } => Ok(serde_json::json!({"pin":reader.snapshot(&scope).await?})),
        Query::Page { pin, after, limit } => {
            serde_json::to_value(reader.page(&pin, after, limit).await?)
                .map_err(|_| Failure::Invalid)
        }
        Query::Source {
            pin,
            sequence,
            offset,
            length,
        } => serde_json::to_value(reader.source(&pin, sequence, offset, length).await?)
            .map_err(|_| Failure::Invalid),
    }
}
async fn handle(
    r: Request<Incoming>,
    host: String,
    token: Arc<String>,
    reader: Arc<Reader>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if r.headers().get("host").and_then(|v| v.to_str().ok()) != Some(host.as_str())
        || r.headers()
            .get("origin")
            .is_some_and(|v| v.to_str().ok() != Some(format!("http://{host}").as_str()))
    {
        return Ok(denied(StatusCode::FORBIDDEN));
    }
    let path = r.uri().path_and_query().map(|p| p.as_str());
    if r.method() == hyper::Method::GET {
        return Ok(match path {
            Some("/") => response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                include_str!("../web/library/index.html"),
            ),
            Some("/app.js") => response(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                include_str!("../web/library/app.js"),
            ),
            Some("/theme.js") => response(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                include_str!("../web/theme.js"),
            ),
            Some("/base.css") => response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                include_str!("../web/operations/style.css"),
            ),
            Some("/style.css") => response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                include_str!("../web/library/style.css"),
            ),
            _ => denied(StatusCode::NOT_FOUND),
        });
    }
    if r.method() != hyper::Method::POST || path != Some("/api/library") {
        return Ok(denied(StatusCode::METHOD_NOT_ALLOWED));
    }
    let wanted = format!("Bearer {token}");
    if r.headers().get_all("authorization").iter().count() != 1
        || r.headers().get("authorization").map(|v| v.as_bytes()) != Some(wanted.as_bytes())
    {
        return Ok(denied(StatusCode::UNAUTHORIZED));
    }
    if r.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("application/json")
    {
        return Ok(denied(StatusCode::BAD_REQUEST));
    }
    let body = match Limited::new(r.into_body(), 16384).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(denied(StatusCode::PAYLOAD_TOO_LARGE)),
    };
    let request = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return Ok(denied(StatusCode::BAD_REQUEST)),
    };
    Ok(match query(&reader, request).await {
        Ok(value) => match serde_json::to_vec(&value) {
            Ok(bytes) => response(StatusCode::OK, "application/json", bytes),
            Err(_) => denied(StatusCode::SERVICE_UNAVAILABLE),
        },
        Err(Failure::AccessLimited) => denied(StatusCode::FORBIDDEN),
        Err(Failure::Missing) => denied(StatusCode::NOT_FOUND),
        Err(Failure::Invalid) => denied(StatusCode::BAD_REQUEST),
        Err(_) => denied(StatusCode::SERVICE_UNAVAILABLE),
    })
}
/// Bounded concurrent reads. Tokens/keys are operator-configured and never logged.
pub async fn serve(listener: TcpListener, token: String, reader: Reader) -> io::Result<()> {
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback()
        || token.len() < 32
        || token.len() > 4096
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(io::Error::other("invalid reader configuration"));
    }
    let host = addr.to_string();
    let token = Arc::new(token);
    let reader = Arc::new(reader);
    // Four requests execute; eight more accepted sockets may wait up to six
    // seconds. This absorbs browser asset bursts without unbounded tasks.
    let slots = Arc::new(Semaphore::new(12));
    let requests = Arc::new(Semaphore::new(4));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (stream,_)=accepted?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {continue;};
                let host=host.clone();let token=token.clone();let reader=reader.clone();let requests=requests.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let connection = async move {
                        let Ok(Ok(_request)) = tokio::time::timeout(Duration::from_secs(6), requests.acquire_owned()).await else { return; };
                        let mut builder=hyper::server::conn::http1::Builder::new();
                        builder.keep_alive(false).max_buf_size(16384).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(5));
                        let service=hyper::service::service_fn(move |r|handle(r,host.clone(),token.clone(),reader.clone()));
                        let _=builder.serve_connection(TokioIo::new(stream),service).await;
                    };
                    let _=tokio::time::timeout(Duration::from_secs(35),connection).await;
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
}
