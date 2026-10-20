//! Explicit publication of authored annotations through the existing encrypted
//! durable spool. Destinations are operator configuration, never browser paths.
use super::Readers;
use crate::{
    evidence_content::ContentError,
    evidence_service::{self, Failure},
    evidence_spool::Spool,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
pub struct AnnotationOutbox {
    erasure_history: Option<crate::evidence_erasure_history::Access>,
    path: PathBuf,
    endpoint: String,
    recipient: [u8; 32],
    writer: String,
    destination: Value,
    digest: String,
}
impl AnnotationOutbox {
    pub fn new(path: PathBuf, endpoint: String, recipient: [u8; 32]) -> Result<Self, Failure> {
        let url = reqwest::Url::parse(&endpoint).map_err(|_| Failure::Invalid)?;
        let host = url
            .host_str()
            .ok_or(Failure::Invalid)?
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .map_err(|_| Failure::Invalid)?;
        if url.scheme() != "http"
            || !host.is_loopback()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/v1/rpc"
        {
            return Err(Failure::Invalid);
        }
        let mut spool = Spool::open(&path).map_err(|_| Failure::Unavailable)?;
        let status = spool.status().map_err(|_| Failure::Corrupt)?;
        let destination = json!({"scope":status.scope,"issuer":status.audience,"recipient":evidence_service::hex(&recipient),"endpoint":endpoint});
        let digest = evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&(
                "annotation-destination/1",
                &destination,
                &path,
                &status.writer,
            ))
            .map_err(|_| Failure::Invalid)?,
        ));
        Ok(Self {
            erasure_history: None,
            path,
            endpoint,
            recipient,
            writer: status.writer,
            destination,
            digest,
        })
    }
    pub fn with_erasure_history(
        mut self,
        history: crate::evidence_erasure_history::Access,
    ) -> Result<Self, Failure> {
        self.digest = evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&(&self.digest, &history)).map_err(|_| Failure::Invalid)?,
        ));
        self.erasure_history = Some(history);
        self.open()?;
        Ok(self)
    }
    pub fn writer(&self) -> &str {
        &self.writer
    }
    fn open(&self) -> Result<Spool, Failure> {
        let mut spool = Spool::open(&self.path).map_err(|_| Failure::Unavailable)?;
        if let Some(history) = &self.erasure_history {
            spool = spool
                .with_erasure_history(history.clone())
                .map_err(|_| Failure::AccessLimited)?;
        }
        let current = spool.status().map_err(|_| Failure::Corrupt)?;
        if self.destination["scope"].as_str() != Some(current.scope.as_str())
            || self.destination["issuer"].as_str() != Some(current.audience.as_str())
            || current.writer != self.writer
        {
            return Err(Failure::AccessLimited);
        }
        Ok(spool)
    }
    fn operation(id: &str) -> Result<[u8; 16], Failure> {
        if id.len() != 64 || evidence_service::unhex(id, 32)?.len() != 32 {
            return Err(Failure::Invalid);
        }
        let hash = Sha256::digest(
            [
                b"tools.kan.annotation.operation.v1\0".as_slice(),
                id.as_bytes(),
            ]
            .concat(),
        );
        hash[..16].try_into().map_err(|_| Failure::Invalid)
    }
    fn status(&self, id: &str) -> Result<Value, Failure> {
        let operation = Self::operation(id)?;
        let spool = self.open()?;
        let state = spool
            .operation(&evidence_service::hex(&operation))
            .map_err(|_| Failure::Corrupt)?;
        Ok(
            json!({"destination":self.destination,"destination_digest":self.digest,"operation":evidence_service::hex(&operation),"state":state.as_ref().map_or("not-queued",|s|if s.erased {"erased"}else if s.pending {"queued"}else{"acknowledged"}),"record":state.as_ref().map(|s|json!({"position":s.position.to_string(),"manifest":s.manifest,"pending":s.pending,"erased":s.erased}))}),
        )
    }
}
impl Readers {
    pub(super) async fn annotation_delivery(&self, id: &str) -> Result<Value, ContentError> {
        let record = self
            .workspace()?
            .get("annotation", id)?
            .ok_or(Failure::AccessLimited)?;
        if record["author"] != self.workspace()?.author() {
            return Err(Failure::AccessLimited.into());
        }
        self.annotation_preview(
            serde_json::from_value(record["draft"].clone()).map_err(|_| Failure::Corrupt)?,
        )
        .await?;
        match &self.outbox {
            Some(outbox) => Ok(outbox.status(id)?),
            None => Ok(json!({"state":"not-configured"})),
        }
    }
    pub(super) async fn annotation_queue(
        &self,
        id: &str,
        destination: &str,
    ) -> Result<Value, ContentError> {
        let checked = self.annotation_delivery(id).await?;
        let outbox = self.outbox.as_ref().ok_or(Failure::Invalid)?;
        if destination != outbox.digest {
            return Err(Failure::Invalid.into());
        }
        if checked["state"] != "not-queued" {
            return Ok(checked);
        }
        let mut spool = outbox.open()?;
        self.workspace()?.queue_annotation(
            &mut spool,
            &outbox.recipient,
            &AnnotationOutbox::operation(id)?,
            id,
        )?;
        Ok(outbox.status(id)?)
    }
    pub(super) async fn annotation_drain(&self, destination: &str) -> Result<Value, ContentError> {
        let outbox = self.outbox.as_ref().ok_or(Failure::Invalid)?;
        if destination != outbox.digest {
            return Err(Failure::Invalid.into());
        }
        // A destination ACK does not authorize publication of erased/revoked
        // source material. Hold enrolled source custody through the send.
        let workspace = self.workspace()?;
        let source_custody = workspace.publication_lease()?;
        let mut spool = outbox.open()?;
        let _destination_custody = spool.erasure_lease().map_err(|_| Failure::AccessLimited)?;
        spool
            .reconcile_managed_erasure()
            .map_err(|_| Failure::Unavailable)?;
        let checked = spool.head().map_err(|_| Failure::AccessLimited)?;
        let _complete_source_custody = if let Some(raw) = &checked {
            let id = workspace.publication_annotation(raw)?;
            self.annotation_delivery(&id).await?;
            // Partial enrollment cannot make a managed publisher safe: every
            // known ancestor source must have independent current custody.
            if source_custody.is_empty() {
                None
            } else {
                Some(workspace.authorize_publication(raw)?)
            }
        } else {
            None
        };
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let delivered = if let Some(raw) = checked {
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::evidence_delivery::deliver_expected(&mut spool, &outbox.endpoint, &raw),
            )
            .await
            .map_err(|_| Failure::Unavailable)?
            .map_err(|_| Failure::Unavailable)?
        } else {
            None
        };
        let status = spool.status().map_err(|_| Failure::Corrupt)?;
        Ok(
            json!({"delivered":delivered.map(|d|json!({"operation":d.operation,"position":d.position.to_string(),"manifest":d.manifest})),"pending":status.pending.to_string(),"destination":outbox.destination,"destination_digest":outbox.digest}),
        )
    }
}
