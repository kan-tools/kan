//! Experimental body capture. Queue admission is independent of provider success.
use crate::{evidence_delivery, evidence_service::hex, evidence_spool::Spool, sign::Identity};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub const CHUNK: usize = 64 * 1024;
pub const MAX_REQUEST: usize = 16 * 1024 * 1024;
const MAGIC: &[u8; 5] = b"KANC2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Observer {
    Collector,
    Gateway,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Completed,
    OutcomeUnknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    Started {
        method: String,
        route: String,
    },
    RequestChunk {
        offset: u64,
    },
    RequestEnd {
        bytes: u64,
    },
    ForwardingIntent,
    TransportLink {
        exchange: String,
    },
    HttpMetadata {
        direction: String,
        headers: Vec<(String, String)>,
        omitted: Vec<String>,
    },
    ResponseHead {
        status: u16,
    },
    ResponseChunk {
        offset: u64,
    },
    Terminal {
        outcome: Outcome,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub attempt: String,
    pub observer: Observer,
    pub ordinal: u64,
    pub observed_at_unix_micros: Option<u64>,
    pub elapsed_micros: u64,
    pub unconfirmed_before: u64,
    pub event: Event,
}
/// Volatile observation, not a remotely acknowledged completeness certificate.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub attempt: String,
    pub observer: Observer,
    pub observed: u64,
    pub locally_queued: u64,
    pub unconfirmed: u64,
    pub recording_gap: bool,
    pub remote_acknowledged: bool,
    pub status: Option<u16>,
    pub outcome: Option<Outcome>,
}
#[derive(Debug, thiserror::Error)]
#[error("capture admission unconfirmed")]
pub struct Unconfirmed;
/// Implementations must return success only after durable admission. Failures may
/// be ambiguous. Never retry inference here; retain original queued bytes instead.
pub trait Sink: Send {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed>;
    fn admit_with_wait(
        &mut self,
        operation: &[u8; 16],
        frame: &[u8],
        _wait: Duration,
    ) -> (Result<(), Unconfirmed>, Duration) {
        (self.admit(operation, frame), Duration::ZERO)
    }
}
pub struct EncryptedSpool<'a> {
    pub spool: Option<&'a mut Spool>,
    pub signer: &'a Identity,
    pub recipient: [u8; 32],
}
impl Sink for EncryptedSpool<'_> {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        self.admit_with_wait(operation, frame, Duration::from_millis(100))
            .0
    }
    fn admit_with_wait(
        &mut self,
        operation: &[u8; 16],
        frame: &[u8],
        wait: Duration,
    ) -> (Result<(), Unconfirmed>, Duration) {
        let Some(spool) = self.spool.as_deref_mut() else {
            return (Err(Unconfirmed), Duration::ZERO);
        };
        let (result, spent) = spool.with_capture_wait(wait, |spool| {
            evidence_delivery::queue(spool, self.signer, &self.recipient, operation, frame)
        });
        (result.map(|_| ()).map_err(|_| Unconfirmed), spent)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid capture route, request or deadline")]
    Invalid,
    #[error("capture randomness unavailable")]
    Random,
    #[error("provider outcome unknown (transport, deadline or output failure)")]
    OutcomeUnknown,
}

/// Ordered observer-local evidence. The caller supplies truthful event semantics;
/// this is not a cross-observer ordering or a provider acknowledgment protocol.
/// Health callbacks must not panic and should return promptly. Drop attempts a
/// terminal unknown observation; process crashes cannot execute Drop.
pub struct Recorder<'a> {
    sink: &'a mut dyn Sink,
    notify: &'a mut (dyn FnMut(&Health) + Send),
    nonce: [u8; 32],
    started: Instant,
    health: Health,
    finished: bool,
    admission_allowance: Duration,
}
impl<'a> Recorder<'a> {
    pub fn new(
        observer: Observer,
        sink: &'a mut dyn Sink,
        notify: &'a mut (dyn FnMut(&Health) + Send),
    ) -> Result<Self, Error> {
        let mut nonce = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Random)?;
        let health = Health {
            attempt: hex(&nonce),
            observer,
            observed: 0,
            locally_queued: 0,
            unconfirmed: 0,
            recording_gap: false,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        notify(&health);
        Ok(Self {
            sink,
            notify,
            nonce,
            started: Instant::now(),
            health,
            finished: false,
            admission_allowance: Duration::from_secs(1),
        })
    }
    /// One bounded observation; invalid shape is rejected before admission.
    /// Only chunk events carry bytes. An empty chunk is allowed.
    pub fn record(&mut self, event: Event, body: &[u8]) -> Result<(), Error> {
        if self.finished
            || body.len() > CHUNK
            || self.health.observed == u64::MAX
            || (!matches!(
                event,
                Event::RequestChunk { .. } | Event::ResponseChunk { .. }
            ) && !body.is_empty())
            || matches!(&event, Event::TransportLink { exchange } if crate::evidence_service::unhex(exchange,32).map_or(true, |v|v.len()!=32))
            || matches!(&event, Event::Started { method, route } if method.len() > 32 || route.len() > 2048)
        {
            return Err(Error::Invalid);
        }
        let ordinal = self.health.observed;
        let terminal = if let Event::Terminal { outcome } = &event {
            Some(*outcome)
        } else {
            None
        };
        let status = if let Event::ResponseHead { status } = &event {
            Some(*status)
        } else {
            None
        };
        let header = Header {
            version: 2,
            attempt: self.health.attempt.clone(),
            observer: self.health.observer,
            ordinal,
            observed_at_unix_micros: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| u64::try_from(d.as_micros()).ok()),
            elapsed_micros: self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            unconfirmed_before: self.health.unconfirmed,
            event,
        };
        let json = serde_json::to_vec(&header).expect("bounded typed capture header");
        if json.len() > 128 * 1024 {
            return Err(Error::Invalid);
        }
        let mut frame = Vec::with_capacity(9 + json.len() + body.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
        frame.extend_from_slice(&json);
        frame.extend_from_slice(body);
        let mut digest = Sha256::new();
        digest.update(b"tools.kan.capture.operation.v1\0");
        digest.update(self.nonce);
        digest.update([match self.health.observer {
            Observer::Collector => 0,
            Observer::Gateway => 1,
        }]);
        digest.update(ordinal.to_be_bytes());
        let operation: [u8; 16] = digest.finalize()[..16].try_into().expect("16 bytes");
        self.health.observed += 1;
        let (admitted, spent) = self.sink.admit_with_wait(
            &operation,
            &frame,
            self.admission_allowance.min(Duration::from_millis(100)),
        );
        // Charge actual SQLite busy-handler sleep, not healthy crypto/fsync work.
        // Exhaustion removes waiting, never later admission attempts.
        self.admission_allowance = self.admission_allowance.saturating_sub(spent);
        if admitted.is_ok() {
            self.health.locally_queued += 1;
        } else {
            self.health.unconfirmed += 1;
            self.health.recording_gap = true;
        }
        if let Some(status) = status {
            self.health.status = Some(status);
        }
        if let Some(outcome) = terminal {
            self.health.outcome = Some(outcome);
            self.finished = true;
        }
        // No body bytes, URL, credentials or storage error text in health.
        (self.notify)(&self.health);
        Ok(())
    }
    pub fn health(&self) -> &Health {
        &self.health
    }
}
impl Drop for Recorder<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.record(
                Event::Terminal {
                    outcome: Outcome::OutcomeUnknown,
                },
                &[],
            );
        }
    }
}

/// Route is supplied by configuration, never extracted from captured content.
/// The body-only entry point supplies no credentials. HTTP adapters supply
/// explicitly configured headers; none are discovered from the environment.
pub struct Route {
    url: reqwest::Url,
    client: reqwest::Client,
    mutual_tls: bool,
}
impl Route {
    pub(crate) fn is_mutual_tls(&self) -> bool {
        self.mutual_tls
    }
    pub(crate) fn is_origin(&self) -> bool {
        self.url.path() == "/"
    }
    pub(crate) fn anthropic_path(&self, path: &str) -> Result<Self, Error> {
        let (path, query) = path
            .split_once('?')
            .map_or((path, None), |(p, q)| (p, Some(q)));
        if !self.is_origin()
            || !matches!(path, "/v1/messages" | "/v1/messages/count_tokens")
            || query.is_some_and(|q| q != "beta=true")
        {
            return Err(Error::Invalid);
        }
        let mut url = self.url.clone();
        url.set_path(path);
        url.set_query(query);
        Ok(Self {
            url,
            client: self.client.clone(),
            mutual_tls: self.mutual_tls,
        })
    }
    pub fn new(endpoint: &str) -> Result<Self, Error> {
        Self::build(endpoint, None)
    }
    /// Explicit private CA and client identity; never ambient roots or credentials.
    pub fn mutual_tls(endpoint: &str, ca: &[u8], identity: &[u8]) -> Result<Self, Error> {
        Self::build(endpoint, Some((ca, identity)))
    }
    fn build(endpoint: &str, tls: Option<(&[u8], &[u8])>) -> Result<Self, Error> {
        if endpoint.len() > 2048 {
            return Err(Error::Invalid);
        }
        let url = reqwest::Url::parse(endpoint).map_err(|_| Error::Invalid)?;
        let loopback = url
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|a| a.is_loopback());
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.as_str().len() > 2048
        {
            return Err(Error::Invalid);
        }
        let builder = reqwest::Client::builder()
            .no_proxy()
            // Avoid hyper-util's pre-wire retry on a canceled pooled connection.
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();
        let builder = if let Some((ca, identity)) = tls {
            if url.scheme() != "https" {
                return Err(Error::Invalid);
            }
            builder
                .https_only(true)
                .tls_built_in_root_certs(false)
                .min_tls_version(reqwest::tls::Version::TLS_1_3)
                .add_root_certificate(
                    reqwest::Certificate::from_pem(ca).map_err(|_| Error::Invalid)?,
                )
                .identity(reqwest::Identity::from_pem(identity).map_err(|_| Error::Invalid)?)
        } else {
            builder
        };
        let client = builder.build().map_err(|_| Error::Invalid)?;
        Ok(Self {
            url,
            client,
            mutual_tls: tls.is_some(),
        })
    }
}

/// Single bounded POST; streaming response body goes only to `output`. Every
/// body chunk attempts durable encrypted admission before release. Capture
/// failure degrades health and never changes provider bytes or retries inference.
/// Deadline bounds async I/O, not synchronous capture callbacks/SQLite latency.
pub async fn forward<W: AsyncWrite + Unpin>(
    route: &Route,
    request: Vec<u8>,
    sink: &mut dyn Sink,
    notify: &mut (dyn FnMut(&Health) + Send),
    output: &mut W,
    deadline: Duration,
) -> Result<Health, Error> {
    forward_http(
        route,
        ForwardInput {
            body: request,
            observer: Observer::Gateway,
            headers: reqwest::header::HeaderMap::new(),
            exchange: None,
            metadata: None,
        },
        sink,
        notify,
        &mut BodyOutput(output),
        deadline,
    )
    .await
}

/// HTTP adapters receive the status/headers before any response body bytes.
/// Implementations must not block in `head`.
pub trait HttpOutput: AsyncWrite + Unpin {
    fn head(&mut self, status: u16, headers: &reqwest::header::HeaderMap) -> Result<(), Error>;
}
struct BodyOutput<'a, W>(&'a mut W);
impl<W: AsyncWrite + Unpin> AsyncWrite for BodyOutput<'_, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, b)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}
impl<W: AsyncWrite + Unpin> HttpOutput for BodyOutput<'_, W> {
    fn head(&mut self, _: u16, _: &reqwest::header::HeaderMap) -> Result<(), Error> {
        Ok(())
    }
}
pub struct ForwardInput {
    pub body: Vec<u8>,
    pub observer: Observer,
    pub headers: reqwest::header::HeaderMap,
    pub exchange: Option<String>,
    pub metadata: Option<reqwest::header::HeaderMap>,
}
pub async fn forward_http<W: HttpOutput>(
    route: &Route,
    input: ForwardInput,
    sink: &mut dyn Sink,
    notify: &mut (dyn FnMut(&Health) + Send),
    output: &mut W,
    deadline: Duration,
) -> Result<Health, Error> {
    let ForwardInput {
        body: request,
        observer,
        headers,
        exchange,
        metadata,
    } = input;
    if request.len() > MAX_REQUEST || deadline.is_zero() || deadline > Duration::from_secs(86400) {
        return Err(Error::Invalid);
    }
    let mut recorder = Recorder::new(observer, sink, notify)?;
    recorder.record(
        Event::Started {
            method: "POST".into(),
            route: route.url.to_string(),
        },
        &[],
    )?;
    if let Some(exchange) = exchange {
        if crate::evidence_service::unhex(&exchange, 32).map_or(true, |b| b.len() != 32) {
            return Err(Error::Invalid);
        }
        recorder.record(Event::TransportLink { exchange }, &[])?;
    }
    if let Some(headers) = &metadata {
        record_metadata(&mut recorder, "request", headers)?;
    }
    for (i, chunk) in request.chunks(CHUNK).enumerate() {
        recorder.record(
            Event::RequestChunk {
                offset: (i * CHUNK) as u64,
            },
            chunk,
        )?;
    }
    recorder.record(
        Event::RequestEnd {
            bytes: request.len() as u64,
        },
        &[],
    )?;
    recorder.record(Event::ForwardingIntent, &[])?;
    // Only awaited I/O consumes this budget. Synchronous admission/health work
    // must not turn a recording failure into a failed provider outcome.
    let mut budget = IoBudget {
        remaining: deadline,
    };
    let result = async {
        let mut response = budget
            .wait(
                route
                    .client
                    .post(route.url.clone())
                    .header("content-type", "application/octet-stream")
                    .headers(headers)
                    .body(request)
                    .send(),
            )
            .await?;
        recorder.record(
            Event::ResponseHead {
                status: response.status().as_u16(),
            },
            &[],
        )?;
        if metadata.is_some() {
            record_metadata(&mut recorder, "response", response.headers())?;
        }
        output.head(response.status().as_u16(), response.headers())?;
        let mut offset = 0u64;
        while let Some(bytes) = budget.wait(response.chunk()).await? {
            for chunk in bytes.chunks(CHUNK) {
                recorder.record(Event::ResponseChunk { offset }, chunk)?;
                offset = offset
                    .checked_add(chunk.len() as u64)
                    .ok_or(Error::OutcomeUnknown)?;
                budget.wait(output.write_all(chunk)).await?;
            }
        }
        budget.wait(output.flush()).await?;
        Ok::<_, Error>(())
    }
    .await;
    let success = result.is_ok();
    recorder.record(
        Event::Terminal {
            outcome: if success {
                Outcome::Completed
            } else {
                Outcome::OutcomeUnknown
            },
        },
        &[],
    )?;
    if success {
        Ok(recorder.health.clone())
    } else {
        Err(Error::OutcomeUnknown)
    }
}

struct IoBudget {
    remaining: Duration,
}
impl IoBudget {
    async fn wait<T, E>(
        &mut self,
        future: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, Error> {
        if self.remaining.is_zero() {
            return Err(Error::OutcomeUnknown);
        }
        let started = Instant::now();
        let result = tokio::time::timeout(self.remaining, future).await;
        self.remaining = self.remaining.saturating_sub(started.elapsed());
        if self.remaining.is_zero() {
            return Err(Error::OutcomeUnknown);
        }
        match result {
            Ok(Ok(value)) => Ok(value),
            _ => Err(Error::OutcomeUnknown),
        }
    }
}

/// Normalized HTTP headers. Secret-bearing fields are explicitly omitted, never
/// copied into evidence or health. This does not represent raw wire framing.
fn record_metadata(
    recorder: &mut Recorder<'_>,
    direction: &str,
    map: &reqwest::header::HeaderMap,
) -> Result<(), Error> {
    let mut headers = Vec::new();
    let mut omitted = Vec::new();
    for (name, value) in map {
        let name = name.as_str();
        if matches!(
            name,
            "authorization" | "x-api-key" | "proxy-authorization" | "cookie" | "set-cookie"
        ) {
            omitted.push(name.to_owned());
        } else {
            headers.push((name.to_owned(), hex(value.as_bytes())));
        }
    }
    recorder.record(
        Event::HttpMetadata {
            direction: direction.into(),
            headers,
            omitted,
        },
        &[],
    )
}
