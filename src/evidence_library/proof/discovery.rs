//! Explicit, resumable discovery. No plaintext projection is persisted.
use crate::{
    evidence_capture::Event,
    evidence_content::ContentError,
    evidence_reader::proof::{Pin, Reader, Source, Token},
    evidence_reconstruction::{self as capture, Decoded},
    evidence_service::Failure,
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

pub(super) async fn page(
    reader: &Reader,
    pin: &Pin,
    cursor: Option<&Token>,
    limit: usize,
    workers: Arc<tokio::sync::Semaphore>,
) -> Result<Value, ContentError> {
    if limit == 0 || limit > 20 {
        return Err(Failure::Invalid.into());
    }
    let _permit = workers
        .try_acquire_owned()
        .map_err(|_| ContentError::Busy)?;
    tokio::time::timeout(Duration::from_secs(20), async {
        let page = reader.page(pin, cursor, limit).await?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let selections: Vec<_> = page.records.into_iter().map(|r| r.selection).collect();
        let mut offset = 0;
        while offset < selections.len() {
            let end = (offset + crate::evidence_proof_service::READ_BATCH_LIMIT).min(selections.len());
            let sources = reader.sources_prefix(pin, &selections[offset..end]).await?;
            offset += sources.len();
            for source in sources {
            let (record, writer, description) = match source {
                Source::Available { record, writer, plaintext } => {
                    bytes = bytes.checked_add(plaintext.len()).ok_or(ContentError::Limited)?;
                    if bytes > 8 * 1024 * 1024 {
                        return Err(ContentError::Limited);
                    }
                    (record, Some(writer), describe(&plaintext))
                }
                Source::Missing { record } => (record, None, json!({"kind":"missing"})),
                Source::Corrupt { record } => (record, None, json!({"kind":"corrupt"})),
            };
            records.push(json!({"record":record,"writer":writer,"description":description}));
        }
        }
        // Neither a discovery result nor its cursor is an enduring grant.
        reader.page(pin, None, 1).await?;
        Ok(json!({"version":"kan-discovery/1","records":records,"next":page.next,
            "coverage":"Only the returned occurrences were inspected. Unavailable evidence cannot be assigned to an attempt. A completed inventory scan does not prove complete traffic capture."}))
    }).await.map_err(|_| ContentError::Limited)?
}

fn describe(bytes: &[u8]) -> Value {
    match capture::decode(bytes) {
        Ok(Decoded::Opaque) => json!({"kind":"opaque"}),
        Ok(Decoded::Unsupported(_)) => json!({"kind":"unsupported"}),
        Err(_) => json!({"kind":"malformed"}),
        Ok(Decoded::Capture(frame)) => {
            let h = frame.header;
            let session_link = crate::evidence_session::link(&h.event);
            let event = match &h.event {
                Event::Started { method, route } => {
                    json!({"type":"started","method":method,"route":route})
                }
                Event::RequestChunk { .. } => json!({"type":"request-chunk"}),
                Event::RequestEnd { .. } => json!({"type":"request-end"}),
                Event::ForwardingIntent => json!({"type":"forwarding-intent"}),
                Event::TransportLink { exchange } => {
                    json!({"type":"transport-link","exchange":exchange})
                }
                Event::HttpMetadataChunk { .. } => json!({"type":"http-metadata-chunk"}),
                Event::HttpMetadata { .. } => json!({"type":"http-metadata"}),
                Event::ResponseHead { status } => json!({"type":"response-head","status":status}),
                Event::ResponseChunk { .. } => json!({"type":"response-chunk"}),
                Event::Terminal { outcome } => json!({"type":"terminal","outcome":outcome}),
            };
            json!({"kind":"capture","attempt":h.attempt,"observer":h.observer,
                "ordinal":h.ordinal.to_string(),"observed_at_unix_micros":h.observed_at_unix_micros.map(|n|n.to_string()),
                "unconfirmed_before":h.unconfirmed_before.to_string(),"event":event,"session_link":session_link})
        }
    }
}
