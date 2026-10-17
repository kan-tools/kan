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
    Started { method: String, route: String },
    RequestChunk { offset: u64 },
    RequestEnd { bytes: u64 },
    ForwardingIntent,
    ResponseHead { status: u16 },
    ResponseChunk { offset: u64 },
    Terminal { outcome: Outcome },
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
pub trait Sink {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed>;
}
pub struct EncryptedSpool<'a> {
    pub spool: Option<&'a mut Spool>,
    pub signer: &'a Identity,
    pub recipient: [u8; 32],
}
impl Sink for EncryptedSpool<'_> {
    fn admit(&mut self, operation: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        let spool = self.spool.as_deref_mut().ok_or(Unconfirmed)?;
        evidence_delivery::queue(spool, self.signer, &self.recipient, operation, frame)
            .map(|_| ())
            .map_err(|_| Unconfirmed)
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
    notify: &'a mut dyn FnMut(&Health),
    nonce: [u8; 32],
    started: Instant,
    health: Health,
    finished: bool,
}
impl<'a> Recorder<'a> {
    pub fn new(
        observer: Observer,
        sink: &'a mut dyn Sink,
        notify: &'a mut dyn FnMut(&Health),
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
        if self.sink.admit(&operation, &frame).is_ok() {
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
/// No credentials or arbitrary request headers are supported in this profile.
pub struct Route {
    url: reqwest::Url,
    client: reqwest::Client,
}
impl Route {
    pub fn new(endpoint: &str) -> Result<Self, Error> {
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
        let client = reqwest::Client::builder()
            .no_proxy()
            // Avoid hyper-util's pre-wire retry on a canceled pooled connection.
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| Error::Invalid)?;
        Ok(Self { url, client })
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
    notify: &mut dyn FnMut(&Health),
    output: &mut W,
    deadline: Duration,
) -> Result<Health, Error> {
    if request.len() > MAX_REQUEST || deadline.is_zero() || deadline > Duration::from_secs(86400) {
        return Err(Error::Invalid);
    }
    let mut recorder = Recorder::new(Observer::Gateway, sink, notify)?;
    recorder.record(
        Event::Started {
            method: "POST".into(),
            route: route.url.to_string(),
        },
        &[],
    )?;
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
    let result = tokio::time::timeout(deadline, async {
        let mut response = route
            .client
            .post(route.url.clone())
            .header("content-type", "application/octet-stream")
            .body(request)
            .send()
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        recorder.record(
            Event::ResponseHead {
                status: response.status().as_u16(),
            },
            &[],
        )?;
        let mut offset = 0u64;
        while let Some(bytes) = response.chunk().await.map_err(|_| Error::OutcomeUnknown)? {
            for chunk in bytes.chunks(CHUNK) {
                recorder.record(Event::ResponseChunk { offset }, chunk)?;
                offset = offset
                    .checked_add(chunk.len() as u64)
                    .ok_or(Error::OutcomeUnknown)?;
                output
                    .write_all(chunk)
                    .await
                    .map_err(|_| Error::OutcomeUnknown)?;
            }
        }
        output.flush().await.map_err(|_| Error::OutcomeUnknown)?;
        Ok::<_, Error>(())
    })
    .await;
    let success = matches!(result, Ok(Ok(())));
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
