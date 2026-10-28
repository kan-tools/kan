//! Complementary harness snapshots. Capture original bytes without rewriting
//! transcript records or assuming a hook observes every internal harness event.
use crate::evidence_capture::{self as capture, Event, Health, Observer, Outcome, Recorder, Sink};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
#[derive(Serialize)]
pub struct Report {
    pub adapter: &'static str,
    pub bytes: String,
    pub sha256: String,
    pub health: Health,
    pub coverage: &'static str,
}
pub fn capture<R: Read>(
    mut input: R,
    session: &str,
    sink: &mut dyn Sink,
    notify: &mut (dyn FnMut(&Health) + Send),
) -> io::Result<Report> {
    if session.is_empty() || session.len() > 256 || !session.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(io::Error::other("invalid harness session identifier"));
    }
    let mut recorder =
        Recorder::new(Observer::Collector, sink, notify).map_err(io::Error::other)?;
    recorder
        .record(
            Event::Started {
                method: "HARNESS-SNAPSHOT".into(),
                route: "/kan/harness-jsonl/v1".into(),
            },
            &[],
        )
        .map_err(io::Error::other)?;
    let session_digest = crate::evidence_service::hex(&Sha256::digest(session.as_bytes()));
    let headers=[("x-kan-session", session_digest.as_str()),("x-kan-capture-adapter","kan-harness-jsonl/1"),("x-kan-capture-coverage","Supplied transcript/hook bytes only; unexported internal events and unattached subagent transcripts unknown")]
        .into_iter().map(|(name,value)|(name.to_string(),crate::evidence_service::hex(value.as_bytes()))).collect();
    recorder
        .record(
            Event::HttpMetadata {
                direction: "request".into(),
                headers,
                omitted: vec![],
            },
            &[],
        )
        .map_err(io::Error::other)?;
    let mut buffer = [0u8; capture::CHUNK];
    let mut count = 0u64;
    let mut hash = Sha256::new();
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        recorder
            .record(Event::RequestChunk { offset: count }, &buffer[..n])
            .map_err(io::Error::other)?;
        hash.update(&buffer[..n]);
        count = count
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("transcript length overflow"))?;
    }
    recorder
        .record(Event::RequestEnd { bytes: count }, &[])
        .map_err(io::Error::other)?;
    recorder
        .record(
            Event::Terminal {
                outcome: Outcome::Completed,
            },
            &[],
        )
        .map_err(io::Error::other)?;
    Ok(Report{adapter:"kan-harness-jsonl/1",bytes:count.to_string(),sha256:crate::evidence_service::hex(&hash.finalize()),health:recorder.health().clone(),
        coverage:"Exact supplied bytes; repeated snapshots remain separate attempts. No inference was forwarded. Hook delivery and hidden events are not certified."})
}
