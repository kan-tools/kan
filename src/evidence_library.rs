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
use std::{convert::Infallible, future::Future, io, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
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
            let mut partial = false;
            let configured = reader.configured_scopes();
            // Borrowed futures: cancellation drops every in-flight check. Four
            // waves of at most four five-second reads fit the connection budget.
            for group in configured.chunks(4) {
                let results = tokio::join!(
                    catalog_entry(reader, group.first()),
                    catalog_entry(reader, group.get(1)),
                    catalog_entry(reader, group.get(2)),
                    catalog_entry(reader, group.get(3))
                );
                for (scope, result) in [results.0, results.1, results.2, results.3]
                    .into_iter()
                    .flatten()
                {
                    match result {
                        Ok(pin) => scopes.push(serde_json::json!({"scope":scope,"pin":pin})),
                        Err(Failure::AccessLimited) => {}
                        Err(_) => partial = true,
                    }
                }
            }
            Ok(
                serde_json::json!({"version":1,"scopes":scopes,"coverage":if partial {"partial"} else {"complete"},"capabilities":["snapshot-inventory","source-ranges","provenance"],"unavailable":["semantic-search","normalized-sessions","annotations","saved-views","analysis","administrative-jobs"]}),
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
    let body = match tokio::time::timeout(
        Duration::from_secs(3),
        Limited::new(r.into_body(), 16384).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => return Ok(denied(StatusCode::PAYLOAD_TOO_LARGE)),
        Err(_) => return Ok(denied(StatusCode::REQUEST_TIMEOUT)),
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
    let budget = ConnectionBudget::new();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Some(permit) = budget.admit() else { continue; };
                let (host, token, reader) = (host.clone(), token.clone(), reader.clone());
                let budget = budget.clone();
                tasks.spawn(async move {
                    budget.run(permit, connection(stream, host, token, reader)).await;
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

async fn catalog_entry<'a>(
    reader: &Reader,
    scope: Option<&'a String>,
) -> Option<(&'a String, Result<Pin, Failure>)> {
    let scope = scope?;
    Some((scope, reader.snapshot(scope).await))
}

async fn connection(
    stream: tokio::net::TcpStream,
    host: String,
    token: Arc<String>,
    reader: Arc<Reader>,
) {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16384)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5));
    let service =
        hyper::service::service_fn(move |r| handle(r, host.clone(), token.clone(), reader.clone()));
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// Socket admission and execution deadlines used by the live server. Keeping
/// permit lifetime here makes cancellation release both bounds together.
#[derive(Clone)]
struct ConnectionBudget {
    sockets: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}
impl ConnectionBudget {
    fn new() -> Self {
        Self {
            sockets: Arc::new(Semaphore::new(12)),
            requests: Arc::new(Semaphore::new(4)),
        }
    }
    fn admit(&self) -> Option<OwnedSemaphorePermit> {
        self.sockets.clone().try_acquire_owned().ok()
    }
    async fn run(&self, permit: OwnedSemaphorePermit, work: impl Future<Output = ()>) {
        let _socket = permit;
        let connection = async {
            let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
            work.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(35), connection).await;
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn connection_admission_execution_and_deadlines_are_bounded() {
        let budget = ConnectionBudget::new();
        let entered = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..12 {
            let permit = budget.admit().expect("twelve accepted sockets");
            let (b, entered) = (budget.clone(), entered.clone());
            jobs.push(tokio::spawn(async move {
                b.run(permit, async move {
                    entered.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                })
                .await;
            }));
        }
        assert!(
            budget.admit().is_none(),
            "thirteenth socket must be refused"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            entered.load(Ordering::SeqCst),
            4,
            "exactly four jobs execute"
        );
        assert_eq!(budget.requests.available_permits(), 0);
        tokio::time::advance(Duration::from_millis(5999)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            jobs.iter().filter(|j| j.is_finished()).count(),
            0,
            "queue must survive until its deadline"
        );
        tokio::time::advance(Duration::from_millis(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            jobs.iter().filter(|j| j.is_finished()).count(),
            8,
            "all eight queued sockets expire at six seconds"
        );
        assert_eq!(budget.sockets.available_permits(), 8);
        assert_eq!(
            entered.load(Ordering::SeqCst),
            4,
            "expired queued work must never start"
        );
        tokio::time::advance(Duration::from_millis(28_998)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            jobs.iter().filter(|j| j.is_finished()).count(),
            8,
            "executing requests retain whole budget"
        );
        tokio::time::advance(Duration::from_millis(2)).await;
        tokio::task::yield_now().await;
        assert!(
            jobs.iter().all(|j| j.is_finished()),
            "whole connection expires at thirty-five seconds"
        );
        for job in jobs {
            job.await.unwrap();
        }
        assert_eq!(budget.sockets.available_permits(), 12);
        assert_eq!(budget.requests.available_permits(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_connection_releases_socket_and_execution_permits() {
        let budget = ConnectionBudget::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let b = budget.clone();
        let permit = budget.admit().unwrap();
        let job = tokio::spawn(async move {
            b.run(permit, async move {
                tx.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .await;
        });
        rx.await.unwrap();
        assert_eq!(budget.requests.available_permits(), 3);
        assert_eq!(budget.sockets.available_permits(), 11);
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert_eq!(budget.requests.available_permits(), 4);
        assert_eq!(budget.sockets.available_permits(), 12);
    }
}
