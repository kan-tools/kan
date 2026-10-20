//! Explicit mixed-source presentation; proof sources never fall back to legacy.
use super::{query, Query};
use crate::{
    evidence_content::{self as content, ContentError},
    evidence_proof_service as wire,
    evidence_reader::{self as legacy, proof},
    evidence_service::{self as service, Failure},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};
pub mod analysis;
mod discovery;
mod imports;
pub mod knowledge;
pub mod outbox;
pub mod search;
pub mod sessions;
mod triggers;

pub struct Readers {
    pub(super) owner: Option<std::sync::Arc<super::Owner>>,
    analysis: Option<std::sync::Arc<analysis::Engine>>,
    outbox: Option<outbox::AnnotationOutbox>,
    pub(super) operations: Option<crate::evidence_dashboard::Embedded>,
    workspace: Option<std::sync::Arc<crate::evidence_workspace::Workspace>>,
    legacy: Option<legacy::Reader>,
    proof: BTreeMap<String, std::sync::Arc<proof::Reader>>,
    workers: std::sync::Arc<tokio::sync::Semaphore>,
}
impl Readers {
    pub fn new(
        legacy: Option<legacy::Reader>,
        proofs: Vec<proof::Reader>,
    ) -> Result<Self, Failure> {
        let count = legacy.as_ref().map_or(0, |r| r.configured_scopes().len()) + proofs.len();
        if count == 0 || count > 16 {
            return Err(Failure::Invalid);
        }
        let mut selected = BTreeMap::new();
        for reader in proofs {
            let binding = reader.binding();
            let id = source_id(binding);
            if selected.insert(id, std::sync::Arc::new(reader)).is_some() {
                return Err(Failure::Invalid);
            }
        }
        Ok(Self {
            owner: None,
            analysis: None,
            outbox: None,
            operations: None,
            workspace: None,
            legacy,
            proof: selected,
            workers: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
        })
    }
    pub fn with_annotation_outbox(
        mut self,
        outbox: outbox::AnnotationOutbox,
    ) -> Result<Self, Failure> {
        if outbox.writer() != self.workspace()?.author() {
            return Err(Failure::Invalid);
        }
        self.outbox = Some(outbox);
        Ok(self)
    }
    pub fn with_owner(mut self, owner: std::sync::Arc<super::Owner>) -> Self {
        self.owner = Some(owner);
        self
    }
    pub fn with_operations(mut self, operations: crate::evidence_dashboard::Embedded) -> Self {
        self.operations = Some(operations);
        self
    }
    pub fn with_workspace(mut self, workspace: crate::evidence_workspace::Workspace) -> Self {
        self.workspace = Some(std::sync::Arc::new(workspace));
        self
    }
    fn workspace(&self) -> Result<&crate::evidence_workspace::Workspace, Failure> {
        self.workspace.as_deref().ok_or(Failure::Invalid)
    }
    fn selected(&self, id: &str) -> Result<&proof::Reader, Failure> {
        self.proof
            .get(id)
            .map(|reader| reader.as_ref())
            .ok_or(Failure::AccessLimited)
    }
    async fn declarations(&self, annotations: bool) -> Result<Vec<Value>, ContentError> {
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let workspace = self.workspace.clone().ok_or(Failure::Invalid)?;
        tokio::task::spawn_blocking(move || {
            let _permit = _permit;
            if annotations {
                workspace.annotations()
            } else {
                workspace.views()
            }
        })
        .await
        .map_err(|_| Failure::Unavailable)?
        .map_err(Into::into)
    }
    async fn authorized_sources(&self) -> (std::collections::BTreeSet<String>, bool) {
        let keys: Vec<_> = self.proof.keys().cloned().collect();
        let mut authorized = std::collections::BTreeSet::new();
        let mut partial = false;
        for group in keys.chunks(4) {
            let results = tokio::join!(
                self.entry(group.first()),
                self.entry(group.get(1)),
                self.entry(group.get(2)),
                self.entry(group.get(3))
            );
            for (source, result) in group
                .iter()
                .zip([results.0, results.1, results.2, results.3])
            {
                match result {
                    Some(Ok(_)) => {
                        authorized.insert(source.clone());
                    }
                    Some(Err(Failure::AccessLimited)) => (),
                    _ => partial = true,
                }
            }
        }
        (authorized, partial)
    }
    async fn entry(&self, id: Option<&String>) -> Option<Result<Value, Failure>> {
        let id = id?;
        Some(tokio::time::timeout(Duration::from_secs(5), async {
            if let Some(reader) = self.proof.get(id) {
                let pin = reader.snapshot().await?;
                Ok(json!({"id":id,"scope":reader.binding().scope,"binding":reader.binding(),
                    "protocol":wire::PROTOCOL,"pin_wire":serde_json::to_string(&pin).map_err(|_|Failure::Invalid)?,"pin":pin,
                    "capabilities":["portable-references","snapshot-inventory","source-ranges","provenance","payload-availability","content-inspection","attempt-discovery","attempt-content","session-links","session-content","import-content"]}))
            } else {
                let reader = self.legacy.as_ref().ok_or(Failure::Invalid)?;
                let pin = reader.snapshot(id).await?;
                Ok(json!({"id":id,"scope":id,"protocol":"legacy","pin_wire":content::pin_wire(&pin)?,"pin":pin,
                    "capabilities":["portable-references","snapshot-inventory","source-ranges","provenance","content-inspection"]}))
            }
        }).await.unwrap_or(Err(Failure::Unavailable)))
    }
    /// CLI and other trusted local callers use the same request dispatch as HTTP.
    pub async fn execute(&self, request: Query) -> Result<Vec<u8>, Failure> {
        self.query(request).await.map_err(|e| match e {
            ContentError::Read(f) => f,
            ContentError::Limited | ContentError::Busy => Failure::Unavailable,
        })
    }
    pub(super) async fn query(&self, request: Query) -> Result<Vec<u8>, ContentError> {
        let value = match request {
            Query::ProofImport {
                source,
                pin,
                selections,
                plan,
                file,
                after,
            } => {
                self.import_content(&source, &pin, &selections, &plan, file, after)
                    .await?
            }
            Query::KnowledgeGraph { subject, day } => self.knowledge_graph(subject, day).await?,
            Query::AnnotationTriggers { id, retry } => self.annotation_triggers(&id, retry).await?,
            Query::AnalysisPreview { draft } => self.analysis_preview(draft).await?,
            Query::AnalysisSubmit {
                draft,
                preview,
                nonce,
                wait,
            } => self.analysis_submit(draft, preview, nonce, wait).await?,
            Query::AnalysisJobs => self.analysis_jobs().await?,
            Query::AnalysisJob { id, cancel } => self.analysis_job(id, cancel).await?,
            Query::ProofSession {
                identity,
                attempts,
                format,
            } => self.session_content(identity, attempts, format).await?,
            Query::AnnotationDelivery { id } => self.annotation_delivery(&id).await?,
            Query::AnnotationQueue { id, destination } => {
                self.annotation_queue(&id, &destination).await?
            }
            Query::AnnotationDrain { destination } => self.annotation_drain(&destination).await?,
            Query::AnnotationPreview { draft } => self.annotation_preview(draft).await?,
            Query::AnnotationSave { draft, preview } => {
                self.annotation_save(draft, preview).await?
            }
            Query::Annotations { subject, tag } => self.annotations(subject, tag).await?,
            Query::IndexPage { target, cursor } => {
                search::index(
                    self.selected(&target.source)?,
                    self.workspace()?,
                    &target,
                    cursor.as_ref(),
                    self.workers.clone(),
                )
                .await?
            }
            Query::SearchAttempt {
                target,
                selections,
                filter,
            } => {
                self.workspace()?;
                search::attempt(
                    self.selected(&target.source)?,
                    &target,
                    &selections,
                    &filter,
                    self.workers.clone(),
                )
                .await?
            }
            Query::SearchPage {
                target,
                cursor,
                filter,
            } => {
                search::search(
                    self.selected(&target.source)?,
                    self.workspace()?,
                    &target,
                    cursor.as_ref(),
                    &filter,
                    self.workers.clone(),
                )
                .await?
            }
            Query::SaveView {
                name,
                targets,
                filter,
            } => {
                filter.validate()?;
                if name.trim().is_empty()
                    || name.len() > 160
                    || targets.is_empty()
                    || targets.len() > 16
                {
                    return Err(Failure::Invalid.into());
                }
                let mut seen = std::collections::BTreeSet::new();
                for target in &targets {
                    if !seen.insert(&target.source) {
                        return Err(Failure::Invalid.into());
                    }
                    self.selected(&target.source)?
                        .page(&target.pin, None, 1)
                        .await?;
                }
                let workspace = self.workspace()?;
                let mut declaration = json!({"version":1,"name":name,"targets":targets,"filter":filter,"author":workspace.author(),"trust":"verified writer signatures and issuer-attested inventory; captured assertions remain untrusted"});
                use sha2::{Digest, Sha256};
                let id = service::hex(&Sha256::digest(
                    serde_json::to_vec(&declaration).map_err(|_| Failure::Invalid)?,
                ));
                declaration["id"] = json!(id);
                workspace.put("view", &id, declaration.clone())?;
                declaration
            }
            Query::Views => {
                let declarations = self.declarations(false).await?;
                let (authorized, partial) = self.authorized_sources().await;
                let views: Vec<_> = declarations
                    .into_iter()
                    .filter(|v| {
                        v["targets"].as_array().is_some_and(|targets| {
                            !targets.is_empty()
                                && targets.iter().all(|t| {
                                    t["source"].as_str().is_some_and(|s| authorized.contains(s))
                                })
                        })
                    })
                    .collect();
                json!({"views":views,"coverage":if partial {"partial"} else {"complete"}})
            }

            Query::ProofAttempt {
                source,
                pin,
                selections,
                format,
            } => {
                return content::proof_content(
                    self.selected(&source)?,
                    &pin,
                    &selections,
                    format,
                    self.workers.clone(),
                    true,
                )
                .await;
            }
            Query::ProofDiscover {
                source,
                pin,
                cursor,
                limit,
            } => {
                discovery::page(
                    self.selected(&source)?,
                    &pin,
                    cursor.as_ref(),
                    limit,
                    self.workers.clone(),
                )
                .await?
            }
            Query::ProofContent {
                source,
                pin,
                selections,
                format,
            } => {
                return content::proof_content(
                    self.selected(&source)?,
                    &pin,
                    &selections,
                    format,
                    self.workers.clone(),
                    false,
                )
                .await;
            }
            Query::Catalog
                if !self.proof.is_empty() || self.operations.is_some() || self.owner.is_some() =>
            {
                let mut configured = self
                    .legacy
                    .as_ref()
                    .map_or(Vec::new(), |r| r.configured_scopes());
                configured.extend(self.proof.keys().cloned());
                let mut scopes = Vec::new();
                let mut partial = false;
                for group in configured.chunks(4) {
                    let results = tokio::join!(
                        self.entry(group.first()),
                        self.entry(group.get(1)),
                        self.entry(group.get(2)),
                        self.entry(group.get(3))
                    );
                    for result in [results.0, results.1, results.2, results.3]
                        .into_iter()
                        .flatten()
                    {
                        match result {
                            Ok(entry) => scopes.push(entry),
                            Err(Failure::AccessLimited) => {}
                            Err(_) => partial = true,
                        }
                    }
                }
                let mut catalog = json!({"version":2,"scopes":scopes,"coverage":if partial {"partial"} else {"complete"},
                    "capabilities":["portable-references","snapshot-inventory","source-ranges","provenance","payload-availability","content-inspection","attempt-discovery","attempt-content","session-links","session-content","import-content"],
                    "unavailable":["semantic-search","normalized-sessions","annotations","saved-views","analysis","administrative-jobs"]});
                if self.owner.is_some() {
                    catalog["capabilities"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("owner-maintenance"));
                }
                if self.analysis.is_some() {
                    catalog["capabilities"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("analysis"));
                    catalog["unavailable"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|v| v != "analysis");
                }
                if self.operations.is_some() {
                    catalog["capabilities"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("operations-read"));
                }
                if self.workspace.is_some() && !self.proof.is_empty() {
                    catalog["capabilities"].as_array_mut().unwrap().extend([
                        json!("text-search"),
                        json!("saved-views"),
                        json!("annotations"),
                    ]);
                    catalog["unavailable"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|v| v != "saved-views" && v != "annotations");
                }
                catalog
            }
            Query::CitationSource {
                cite,
                offset,
                length,
            } => {
                let offset =
                    usize::try_from(content::coordinate(&offset)?).map_err(|_| Failure::Invalid)?;
                let length =
                    usize::try_from(content::coordinate(&length)?).map_err(|_| Failure::Invalid)?;
                if length == 0 || length > legacy::RANGE_LIMIT {
                    return Err(Failure::Invalid.into());
                }
                let reader = self.selected(&cite.source)?;
                let (pin, value) = reader.rebind_citation(&cite.selection).await?;
                let mut result = source_value(reader.binding(), value, offset, length)?;
                result["pin"] = json!(pin);
                result["pin_wire"] =
                    json!(serde_json::to_string(&pin).map_err(|_| Failure::Invalid)?);
                result
            }
            Query::RestoreAnnotation { reference, preview } => {
                self.restore_annotation(reference, preview).await?
            }
            Query::ResolveReference { reference } => {
                let source = source_id(&reference.binding);
                let (pin, record) = self
                    .selected(&source)?
                    .resolve_reference(&reference)
                    .await?;
                json!({"source":source,"pin":pin,"pin_wire":serde_json::to_string(&pin).map_err(|_|Failure::Invalid)?,"record":record,"reference":reference})
            }
            Query::ProofSnapshot { source } => {
                let pin = self.selected(&source)?.snapshot().await?;
                json!({"pin_wire":serde_json::to_string(&pin).map_err(|_|Failure::Invalid)?,"pin":pin})
            }
            Query::ProofPage {
                source,
                pin,
                cursor,
                limit,
            } => {
                let reader = self.selected(&source)?;
                let page = reader.page(&pin, cursor.as_ref(), limit).await?;
                // Reader::page verified this exact signed snapshot before use.
                let wire::Output::Snapshot { frontier, .. } =
                    &pin.reply.reply.result.as_ref().map_err(Clone::clone)?
                else {
                    return Err(Failure::Corrupt.into());
                };
                json!({"records":page.records,"next":page.next,"through":frontier.through,
                    "coverage":"Issuer-attested metadata · payload availability sampled per read"})
            }
            Query::ProofSource {
                source,
                pin,
                selection,
                offset,
                length,
            } => {
                let offset =
                    usize::try_from(content::coordinate(&offset)?).map_err(|_| Failure::Invalid)?;
                let length =
                    usize::try_from(content::coordinate(&length)?).map_err(|_| Failure::Invalid)?;
                if length == 0 || length > legacy::RANGE_LIMIT {
                    return Err(Failure::Invalid.into());
                }
                let reader = self.selected(&source)?;
                let result = reader.source(&pin, &selection).await?;
                source_value(reader.binding(), result, offset, length)?
            }
            other => {
                return query(self.legacy.as_ref().ok_or(Failure::AccessLimited)?, other).await
            }
        };
        serde_json::to_vec(&value).map_err(|_| Failure::Invalid.into())
    }
}
fn source_id(binding: &wire::Binding) -> String {
    format!(
        "proof:{}:{}:{}:{}",
        match binding.profile {
            wire::Profile::Admitted => "admitted",
            wire::Profile::Copied => "copied",
        },
        binding.archive,
        binding.scope,
        binding.issuer
    )
}
fn source_value(
    binding: &wire::Binding,
    value: proof::Source,
    offset: usize,
    length: usize,
) -> Result<Value, Failure> {
    let (record, writer, plaintext, availability) = match value {
        proof::Source::Available {
            record,
            writer,
            plaintext,
            ..
        } => (record, Some(writer), Some(plaintext), "available"),
        proof::Source::Missing { record } => (record, None, None, "missing"),
        proof::Source::Corrupt { record } => (record, None, None, "corrupt"),
    };
    let reference = proof::Reference::new(binding, &record);
    let mut result = json!({"reference":reference,"scope":binding.scope,"archive":binding.archive,"profile":binding.profile,
        "record":record,"writer":writer,"service_issuer":binding.issuer,"availability":availability,
        "signature":if plaintext.is_some() {"Retained writer signature verified on this read"} else {"Writer signature cannot be rechecked without valid retained source"},
        "admission":"Issuer-attested metadata; proof purpose shown separately",
        "content_trust":"Untrusted retained content; speaker and outcome claims are not authenticated facts"});
    if let Some(bytes) = plaintext {
        if offset > bytes.len() {
            return Err(Failure::Invalid);
        }
        let end = offset.saturating_add(length).min(bytes.len());
        let range = &bytes[offset..end];
        let fields = json!({"total_bytes":bytes.len().to_string(),"offset":offset.to_string(),
            "next":(end < bytes.len()).then(||end.to_string()),"bytes_hex":service::hex(range),
            "utf8":std::str::from_utf8(range).ok()});
        result
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .extend(fields.as_object().ok_or(Failure::Invalid)?.clone());
    }
    Ok(result)
}

impl Drop for Readers {
    fn drop(&mut self) {
        if let Some(engine) = &self.analysis {
            engine.stop();
        }
    }
}
