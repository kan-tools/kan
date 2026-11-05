//! Canonical typed claim compatibility records carried by the v2 reader.
//! Storage admission, claim authorship, legacy codec and view trust stay distinct.
use super::{knowledge, Readers};
use crate::{
    claim::{codec, v1::*},
    evidence_content::ContentError,
    evidence_service::{self, Failure},
    fold::{self, TrustBase},
    store::log::StoredClaim,
};
use atproto_dasl::Cid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};
pub(super) struct RecallOptions {
    pub trust: Vec<String>,
    pub budget: usize,
    pub derived: Vec<String>,
    pub derived_budget: usize,
    pub cursor: Option<Value>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    #[schemars(length(min = 64, max = 64))]
    pub nonce: String,
    #[schemars(range(min = 1, max = 9007199254740980.0))]
    pub recorded_at: u64,
}
impl Operation {
    pub fn fresh() -> Result<Self, Failure> {
        Ok(Self {
            nonce: evidence_service::hex(&rand::random::<[u8; 32]>()),
            recorded_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Failure::Unavailable)?
                .as_micros()
                .try_into()
                .map_err(|_| Failure::Invalid)?,
        })
    }
    fn validate(&self) -> Result<(), Failure> {
        if self.nonce.len() != 64
            || evidence_service::unhex(&self.nonce, 32).is_err()
            || self.recorded_at == 0
            || self.recorded_at > 9_007_199_254_740_980
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    /// Exact configured proof source: collection authorization, not a citation.
    pub source: String,
    /// observe, plan, decide, result, block, resolve, same, relate, mark, retract, reject.
    pub verb: String,
    #[serde(default = "general")]
    pub subject: String,
    pub text: Option<String>,
    pub target: Option<String>,
    pub relation: Option<String>,
    pub status: Option<StatusValue>,
    pub title: Option<String>,
    pub subject_kind: Option<SubjectKind>,
    #[serde(default)]
    pub cites: Vec<String>,
    #[serde(default)]
    #[schemars(with = "Vec<Value>")]
    pub evidence: Vec<knowledge::Citation>,
    #[serde(default)]
    #[schemars(with = "Vec<Value>")]
    pub artifacts: Vec<ArtifactRef>,
    /// Explicit promotion of reviewed reports; never set by report retrieval.
    #[serde(default)]
    pub derived_from: Vec<String>,
    /// Preserve this pair for retry. Omit for a new deliberately authored act.
    pub operation: Option<Operation>,
}
fn general() -> String {
    "general".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encoded {
    pub cid: String,
    pub bytes: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub version: u8,
    pub source: String,
    pub operation: Operation,
    pub order: u64,
    pub intent_hash: String,
    pub claims: Vec<Encoded>,
}
fn anchor(source: &str) -> Result<Anchor, Failure> {
    Ok(Anchor::Blob(
        crate::cid::content_cid(&json!({"type":"kan-record-collection/1","source":source}))
            .map_err(|_| Failure::Invalid)?,
    ))
}
impl Batch {
    pub fn annotation_id(
        source: &str,
        operation: &Operation,
        author: &str,
    ) -> Result<String, Failure> {
        operation.validate()?;
        use sha2::{Digest, Sha256};
        Ok(evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&json!([
                "kan-authored-operation/1",
                source,
                operation.nonce,
                author
            ]))
            .map_err(|_| Failure::Invalid)?,
        )))
    }
    fn operation_artifact(&self) -> Result<ArtifactRef, Failure> {
        Ok(ArtifactRef::ToolOutput(crate::cid::content_cid(&json!({"type":"kan-record-operation/1","source":self.source,"operation":self.operation})).map_err(|_|Failure::Corrupt)?))
    }
    pub fn decoded(&self, author: &str) -> Result<Vec<(Cid, StoredClaim)>, Failure> {
        self.operation.validate()?;
        if self.version != 1
            || self.source.len() > 1024
            || self.order == 0
            || self.order > i64::MAX as u64 - 3
            || evidence_service::unhex(&self.intent_hash, 32).is_err()
            || self.intent_hash.len() != 64
            || self.claims.is_empty()
            || self.claims.len() > 3
        {
            return Err(Failure::Corrupt);
        }
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for (i, encoded) in self.claims.iter().enumerate() {
            let raw = evidence_service::unhex(&encoded.bytes, 131072)?;
            let record = codec::decode_record(&raw, codec::VerificationContext::StaticDidKey)
                .map_err(|_| Failure::Corrupt)?;
            let codec::DecodedClaim::Supported(codec::SupportedClaim::V1(claim)) = record.claim
            else {
                return Err(Failure::Invalid);
            };
            let cid = crate::cid::content_cid(&claim.content).map_err(|_| Failure::Corrupt)?;
            if cid.to_string() != encoded.cid
                || !seen.insert(encoded.cid.clone())
                || claim.content.author.did != author
                || claim.content.author.agent.is_some()
                || claim.content.artifacts.last() != Some(&self.operation_artifact()?)
                || claim.content.workspace != anchor(&self.source)?
                || claim.content.recorded_at != Some(self.operation.recorded_at + i as u64)
                || record.rev != crate::store::encode_tid(self.order + i as u64)
            {
                return Err(Failure::Corrupt);
            }
            out.push((
                cid,
                StoredClaim {
                    claim,
                    rev: record.rev,
                },
            ));
        }
        Ok(out)
    }
}
fn parse_cids(values: &[String]) -> Result<Vec<Cid>, Failure> {
    if values.len() > 64 {
        return Err(Failure::Invalid);
    }
    values
        .iter()
        .map(|s| s.parse().map_err(|_| Failure::Invalid))
        .collect()
}
fn bodies(
    d: &Draft,
    history: &[(Cid, StoredClaim)],
    author: &str,
) -> Result<(SubjectRef, Vec<ClaimBody>), Failure> {
    crate::actions::validate_subject_name(&d.subject).map_err(|_| Failure::Invalid)?;
    if d.title.is_some() != d.subject_kind.is_some()
        || d.text
            .as_ref()
            .is_some_and(|s| s.trim().is_empty() || s.len() > 8192)
        || d.artifacts.len() > 16
        || d.evidence.len() > 8
    {
        return Err(Failure::Invalid);
    }
    let narrative = matches!(
        d.verb.as_str(),
        "observe" | "plan" | "decide" | "result" | "block" | "resolve"
    );
    let targeted = matches!(d.verb.as_str(), "same" | "relate" | "retract" | "reject");
    if d.text.is_some() != narrative
        || d.target.is_some() != targeted
        || (d.relation.is_some() != (d.verb == "relate"))
        || (d.title.is_some() && !narrative)
    {
        return Err(Failure::Invalid);
    }
    let mut subject = SubjectRef::Local(d.subject.clone());
    let text = || d.text.clone().ok_or(Failure::Invalid);
    let target = || d.target.clone().ok_or(Failure::Invalid);
    let mut out = match d.verb.as_str() {
        "observe" => vec![ClaimBody::Observation { text: text()? }],
        "plan" => vec![ClaimBody::Plan { text: text()? }],
        "decide" => vec![ClaimBody::Decision { text: text()? }],
        "result" => vec![ClaimBody::Result { text: text()? }],
        "block" => vec![
            ClaimBody::Blocker { text: text()? },
            ClaimBody::Status {
                value: StatusValue::Blocked,
            },
        ],
        "resolve" => vec![
            ClaimBody::Resolution { text: text()? },
            ClaimBody::Status {
                value: StatusValue::Resolved,
            },
        ],
        "mark" => vec![ClaimBody::Status {
            value: d.status.ok_or(Failure::Invalid)?,
        }],
        "same" | "relate" => {
            let t = target()?;
            crate::actions::validate_subject_name(&t).map_err(|_| Failure::Invalid)?;
            let kind = if d.verb == "same" {
                RelationKind::SameAs
            } else {
                serde_json::from_value(json!(d.relation.as_ref().ok_or(Failure::Invalid)?))
                    .map_err(|_| Failure::Invalid)?
            };
            if d.verb == "relate" && kind == RelationKind::SameAs {
                return Err(Failure::Invalid);
            }
            vec![ClaimBody::Relation {
                kind,
                target: SubjectRef::Local(t),
            }]
        }
        "retract" | "reject" => {
            let cid: Cid = target()?.parse().map_err(|_| Failure::Invalid)?;
            let stored = &history
                .iter()
                .find(|(id, _)| *id == cid)
                .ok_or(Failure::Missing)?
                .1;
            let own = stored.claim.content.author.did == author
                && stored.claim.content.author.agent.is_none();
            if own != (d.verb == "retract") {
                return Err(Failure::AccessLimited);
            }
            subject = stored.claim.content.subject.clone();
            vec![if own {
                ClaimBody::Retraction { supersedes: cid }
            } else {
                ClaimBody::Rejects { claim: cid }
            }]
        }
        _ => return Err(Failure::Invalid),
    };
    if let Some(value) = d.status {
        if matches!(d.verb.as_str(), "observe" | "plan" | "decide" | "result") {
            out.push(ClaimBody::Status { value });
        } else if d.verb != "mark" {
            return Err(Failure::Invalid);
        }
    }
    if let (Some(title), Some(subject_kind)) = (&d.title, d.subject_kind) {
        if title.trim().is_empty() || title.len() > 256 {
            return Err(Failure::Invalid);
        }
        out.push(ClaimBody::Subject {
            title: title.clone(),
            subject_kind,
        });
    }
    if out.len() > 3 {
        return Err(Failure::Invalid);
    }
    Ok((subject, out))
}
fn record_trust(
    specs: &[String],
    me: &str,
    history: &[(Cid, StoredClaim)],
) -> Result<TrustBase, Failure> {
    if specs.len() > 64 {
        return Err(Failure::Invalid);
    }
    if specs.is_empty() {
        return Ok(TrustBase::solo(AuthorId {
            did: me.into(),
            agent: None,
        }));
    }
    let mut weights = std::collections::HashMap::new();
    for spec in specs {
        if spec == "local" {
            for (_, stored) in history {
                weights.insert(stored.claim.content.author.clone(), 1.0);
            }
            continue;
        }
        let entry = crate::fold::trust::parse_entry(spec).map_err(|_| Failure::Invalid)?;
        if entry.did.starts_with("role:") {
            return Err(Failure::Invalid);
        }
        let did = if entry.did == "me" {
            me.to_owned()
        } else {
            entry.did
        };
        if !did.starts_with("did:key:") {
            return Err(Failure::Invalid);
        }
        weights.insert(AuthorId { did, agent: None }, entry.weight);
    }
    Ok(TrustBase::peer_contested(weights))
}
struct History {
    claims: Vec<(Cid, StoredClaim)>,
    origins: std::collections::BTreeMap<String, Value>,
}
impl Readers {
    async fn record_scope(&self, source: &str) -> Result<(), ContentError> {
        self.selected(source)?.snapshot().await?;
        Ok(())
    }
    async fn record_history(
        &self,
        source: &str,
        include_origins: bool,
    ) -> Result<History, ContentError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.record_history_inner(source, include_origins),
        )
        .await
        .map_err(|_| ContentError::Limited)?
    }
    async fn record_history_inner(
        &self,
        source: &str,
        include_origins: bool,
    ) -> Result<History, ContentError> {
        self.record_scope(source).await?;
        let mut after = None;
        let mut history = Vec::new();
        let mut origins = std::collections::BTreeMap::new();
        let mut bytes = 0usize;
        // A declared execution bound, not a lifetime record limit. Never fold a
        // silently incomplete prefix and describe it as the current subject.
        for _ in 0..100 {
            let page = self
                .annotations_page(None, None, after.clone(), 100)
                .await?;
            if page["coverage"] != "complete" {
                return Err(Failure::Unavailable.into());
            }
            for value in page["records"].as_array().ok_or(Failure::Corrupt)? {
                let draft: knowledge::Draft =
                    serde_json::from_value(value["draft"].clone()).map_err(|_| Failure::Corrupt)?;
                if let Some(batch) = draft.authored {
                    if batch.source != source {
                        continue;
                    }
                    bytes = bytes
                        .checked_add(
                            serde_json::to_vec(&batch)
                                .map_err(|_| Failure::Corrupt)?
                                .len(),
                        )
                        .ok_or(ContentError::Limited)?;
                    if bytes > 8 * 1024 * 1024 {
                        return Err(ContentError::Limited);
                    }
                    let decoded =
                        batch.decoded(value["author"].as_str().ok_or(Failure::Corrupt)?)?;
                    if include_origins {
                        let mut evidence = Vec::new();
                        for cite in &draft.cites {
                            let (_, source) = self
                                .selected(&cite.source)?
                                .rebind_citation(&cite.selection)
                                .await?;
                            let (record, availability) = match source {
                                crate::evidence_reader::proof::Source::Available {
                                    record, ..
                                } => (record, "available"),
                                crate::evidence_reader::proof::Source::Missing { record } => {
                                    (record, "missing")
                                }
                                crate::evidence_reader::proof::Source::Corrupt { record } => {
                                    (record, "corrupt")
                                }
                                crate::evidence_reader::proof::Source::KeyUnavailable {
                                    record,
                                    ..
                                } => (record, "key-unavailable"),
                                crate::evidence_reader::proof::Source::Erased { .. } => {
                                    return Err(Failure::AccessLimited.into())
                                }
                            };
                            let reference = self.occurrence_reference(
                                &cite.source,
                                serde_json::to_value(record).map_err(|_| Failure::Corrupt)?,
                            )?;
                            evidence.push(json!({"source":cite.source,"uri":reference["uri"],"availability":availability}));
                        }
                        for (cid, _) in &decoded {
                            origins.insert(cid.to_string(),json!({"annotation":value["id"],"operation":batch.operation,"evidence":evidence,"derived_from":draft.derived_from,"claim_authorship":"canonical kan-claim-v1 compatibility signature; storage admission is separate"}));
                        }
                    }
                    history.extend(decoded);
                }
            }
            match page["next"].as_str() {
                Some(next) => after = Some(next.into()),
                None => {
                    self.record_scope(source).await?;
                    return Ok(History {
                        claims: history,
                        origins,
                    });
                }
            }
        }
        Err(ContentError::Limited)
    }
    pub(super) async fn record(&self, mut draft: Draft, save: bool) -> Result<Value, ContentError> {
        let mut requested = draft.clone();
        self.record_scope(&draft.source).await?;
        let workspace = self.workspace()?;
        if draft.derived_from.len() > 8 {
            return Err(Failure::Invalid.into());
        }
        draft.derived_from.sort();
        draft.derived_from.dedup();
        for id in &draft.derived_from {
            let job = workspace
                .get("analysis-job", id)?
                .ok_or(Failure::AccessLimited)?;
            let result = workspace
                .get("analysis-result", id)?
                .ok_or(Failure::Missing)?;
            if result["state"] != "succeeded" {
                return Err(Failure::Invalid.into());
            }
            let inputs: super::analysis::Draft =
                serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?;
            for cite in inputs.cites {
                self.selected(&cite.source)?
                    .check_citation_access(&cite.pin, &cite.selection)
                    .await?;
                let encoded = serde_json::to_vec(&cite).map_err(|_| Failure::Corrupt)?;
                if !draft
                    .evidence
                    .iter()
                    .any(|c| serde_json::to_vec(c).ok().as_ref() == Some(&encoded))
                {
                    draft.evidence.push(cite);
                }
            }
            let artifact = ArtifactRef::ToolOutput(
                crate::cid::content_cid(&result).map_err(|_| Failure::Corrupt)?,
            );
            if !draft.artifacts.contains(&artifact) {
                draft.artifacts.push(artifact);
            }
        }
        let history = if matches!(draft.verb.as_str(), "retract" | "reject") {
            self.record_history(&draft.source, false).await?.claims
        } else {
            Vec::new()
        };
        let operation = draft.operation.take().map_or_else(Operation::fresh, Ok)?;
        operation.validate()?;
        let (subject, bodies) = bodies(&draft, &history, &workspace.author())?;
        for cite in &draft.evidence {
            self.selected(&cite.source)?
                .check_citation_access(&cite.pin, &cite.selection)
                .await?;
        }
        use sha2::{Digest, Sha256};
        let intent = evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&draft).map_err(|_| Failure::Invalid)?,
        ));
        let id = Batch::annotation_id(&draft.source, &operation, &workspace.author())?;
        let subject_name = match &subject {
            SubjectRef::Local(s) => s.clone(),
            _ => return Err(Failure::Invalid.into()),
        };
        let source = draft.source.clone();
        if !save {
            requested.operation = Some(operation);
            let mut evidence = Vec::new();
            for cite in &draft.evidence {
                let (_, source) = self
                    .selected(&cite.source)?
                    .rebind_citation(&cite.selection)
                    .await?;
                let record = match source {
                    crate::evidence_reader::proof::Source::Available { record, .. } => record,
                    _ => return Err(Failure::Missing.into()),
                };
                evidence.push(
                    self.occurrence_reference(
                        &cite.source,
                        serde_json::to_value(record).map_err(|_| Failure::Corrupt)?,
                    )?["uri"]
                        .clone(),
                );
            }
            let value = json!({"version":"kan-record-preview/1","id":id,"author":workspace.author(),"subject":subject,"kinds":bodies.iter().map(crate::json::claim_kind_name).collect::<Vec<_>>(),"evidence":evidence,"draft":requested,"effect":"No record, queue or model request. Saving this draft is a separate explicit authored operation; access and derived inputs are checked again."});
            if serde_json::to_vec(&value)
                .map_err(|_| Failure::Corrupt)?
                .len()
                > 12 * 1024
            {
                return Err(ContentError::Limited);
            }
            return Ok(value);
        }

        let owner = self.workspace.clone().ok_or(Failure::Invalid)?;
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let (annotation, id, source) = tokio::task::spawn_blocking(move || {
            // Cancellation can abandon the result, not the operation identity
            // or the owner/permit held through its atomic append.
            let _permit = permit;
            let annotation = owner.append_authored(&id, &source, &operation, &intent, |order| {
                let operation_artifact = ArtifactRef::ToolOutput(
                    crate::cid::content_cid(&json!({
                        "type": "kan-record-operation/1", "source": source, "operation": operation
                    })).map_err(|_| Failure::Invalid)?
                );
                let mut claims = Vec::new();
                let mut previous = None;
                for (i, body) in bodies.into_iter().enumerate() {
                    let cites = if matches!(body, ClaimBody::Status { .. }) && previous.is_some() {
                        vec![previous.clone().ok_or(Failure::Invalid)?]
                    } else if matches!(body,ClaimBody::Subject{..}) {
                        Vec::new()
                    } else {
                        parse_cids(&draft.cites)?
                    };
                    let content = ClaimContent {
                        author: AuthorId { did: owner.author(), agent: None },
                        workspace: anchor(&source)?, subject: subject.clone(), body, cites,
                        artifacts: draft.artifacts.iter().cloned()
                            .chain(std::iter::once(operation_artifact.clone())).collect(),
                        recorded_at: Some(operation.recorded_at + i as u64),
                    };
                    let claim = owner.sign_record(content)?;
                    let cid = crate::cid::content_cid(&claim.content).map_err(|_| Failure::Corrupt)?;
                    let raw = codec::encode_v1(claim, crate::store::encode_tid(order + i as u64))
                        .map_err(|_| Failure::Invalid)?;
                    claims.push(Encoded { cid: cid.to_string(), bytes: evidence_service::hex(&raw) });
                    previous = Some(cid);
                }
                let batch = Batch {
                    version: 1, source: source.clone(), operation: operation.clone(), order,
                    intent_hash: intent.clone(), claims,
                };
                batch.decoded(&owner.author())?;
                let annotation = knowledge::Draft {
                    subject: subject_name,
                    text: draft.text.clone().unwrap_or_else(||
                        format!("{} {}", draft.verb, draft.target.clone().unwrap_or_default())),
                    tags: vec![], cites: draft.evidence.clone(), supersedes: None, withdraws: None,
                    derived_from: draft.derived_from.clone(), relations: vec![], authored: Some(batch),
                };
                annotation.validate()?;
                Ok(json!({"version":1,"author":owner.author(),"analysis_trigger_plan":[],
                    "draft":annotation,"id":id,"recorded_at":crate::evidence_operations::now().to_string()}))
            })?;
            Ok::<_, Failure>((annotation, id, source))
        }).await.map_err(|_| Failure::Unavailable)??;
        let batch: Batch = serde_json::from_value(annotation["draft"]["authored"].clone())
            .map_err(|_| Failure::Corrupt)?;
        let mut value = json!({"version":"kan-record-result/1","id":id,"source":source,"claim_codec":codec::V1_CODEC,"claims":batch.claims.iter().map(|c|c.cid.clone()).collect::<Vec<_>>(),"operation":batch.operation,"durability":"encrypted-workspace","publication":"not-configured","scope_admission":"legacy-claim compatibility; storage admission is separate","record":annotation});
        if self.outbox.is_some() {
            match self.annotation_delivery(&id).await {
                Ok(delivery) => {
                    if let Some(destination) = delivery["destination_digest"].as_str() {
                        match self.annotation_queue(&id, destination).await {
                            Ok(queued) => {
                                value["publication"] = queued["state"].clone();
                                value["delivery"] = queued;
                            }
                            Err(_) => {
                                value["publication"] = json!("queue-failed; local record retained");
                            }
                        }
                    }
                }
                Err(_) => {
                    value["publication"] = json!("publication-check-failed; local record retained");
                }
            }
        }
        Ok(value)
    }
    pub(super) async fn recall(
        &self,
        source: String,
        verb: String,
        subject: Option<String>,
        options: RecallOptions,
    ) -> Result<Value, ContentError> {
        let RecallOptions {
            trust: trusted,
            budget,
            derived,
            derived_budget,
            cursor,
        } = options;
        if (verb == "context" && subject.is_some())
            || (verb != "context" && budget != 1024)
            || derived.len() > 8
            || derived_budget > 1024
        {
            return Err(Failure::Invalid.into());
        }
        if let Some(subject) = &subject {
            crate::actions::validate_subject_name(subject).map_err(|_| Failure::Invalid)?;
        }
        let History {
            claims: history,
            origins,
        } = self.record_history(&source, true).await?;
        let trust = record_trust(&trusted, &self.workspace()?.author(), &history)?;
        let excluded = fold::excluded_by_trust(&history, &trust);
        let view = fold::fold(history.clone(), &trust);
        use sha2::{Digest, Sha256};
        let evaluation = json!({"version":"kan-compat-evaluation/1","source":source,
            "claims":history.iter().map(|(id,_)|id.to_string()).collect::<Vec<_>>(),"trust":crate::json::TrustJson::with_empty_reason(&trust,None),
            "normalizer":"canonical-v1-fold/1","relations":"explicit-v1-witnesses/1","derivations":derived,
            "query":{"verb":verb,"subject":subject},"unsupported":["weighted trust semantics","higher identity witnesses","computed Git ancestry"]});
        let view_id = evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&evaluation).map_err(|_| Failure::Corrupt)?,
        ));
        let superseded: BTreeSet<_> = view
            .classes
            .iter()
            .flat_map(|class| {
                let live = fold::state::classify(&class.claims, &[]).live_cids();
                class
                    .claims
                    .iter()
                    .filter(move |(id, c)| {
                        c.content.body.kind() == ClaimKind::Status && !live.contains(id)
                    })
                    .map(|(id, _)| id.to_string())
            })
            .collect();
        let render = |cid: &Cid, claim: &Claim| {
            let mut value = serde_json::to_value(crate::json::ClaimJson::new(
                cid,
                claim,
                superseded.contains(&cid.to_string()),
            ))
            .map_err(|_| Failure::Corrupt)?;
            value["origin"] = origins
                .get(&cid.to_string())
                .cloned()
                .ok_or(Failure::Corrupt)?;
            Ok::<_, Failure>(value)
        };
        let result = match verb.as_str() {
            "context" => {
                if budget == 0 || budget > 4096 {
                    return Err(Failure::Invalid.into());
                }
                let estimator = crate::context::TiktokenEstimator::cl100k();
                let result = crate::context::assemble_reporting(&view, budget, &estimator);
                json!({"claims":result.selected.iter().map(|(id,c)|render(id,c)).collect::<Result<Vec<_>,_>>()?,"budget":budget,"omitted_claims":result.omitted_claims,"omitted_subjects":result.omitted_subjects})
            }
            "show" | "status" | "issues" => {
                let mut classes = Vec::new();
                for class in &view.classes {
                    if subject
                        .as_ref()
                        .is_some_and(|s| !class.subjects.contains(&SubjectRef::Local(s.clone())))
                    {
                        continue;
                    }
                    let state = fold::state::classify(&class.claims, &[]);
                    let (name, value, cid) = crate::json::state_fields(&state);
                    if verb == "issues" && !crate::actions::is_open_issue_with_state(class, &state)
                    {
                        continue;
                    }
                    classes.push(json!({"subjects":class.subjects,"state":name,"value":value,"cid":cid,"claims":class.claims.iter().map(|(id,c)|render(id,c)).collect::<Result<Vec<_>,_>>()?,"witnesses":class.witnesses.iter().map(|w|json!({"claim":w.claim_cid.to_string(),"author":w.author,"from":w.from,"to":w.to})).collect::<Vec<_>>() }));
                }
                // A CID lookup includes retained retracted records, under trust.
                if verb == "show" {
                    if let Some(id) = subject.as_deref().and_then(|s| s.parse::<Cid>().ok()) {
                        classes.clear();
                        for (cid, stored) in &history {
                            if *cid == id && trust.trusts(&stored.claim.content.author) {
                                classes.push(json!({"record":render(cid,&stored.claim)?,"history":"retained; may be retracted or rejected in the folded view"}));
                            }
                        }
                    }
                }
                json!({"subjects":classes})
            }
            _ => return Err(Failure::Invalid.into()),
        };
        let mut value = json!({"version":"kan-recall-result/1","source":source,"claim_codec":codec::V1_CODEC,"view":result,"excluded_by_trust":excluded.values().sum::<usize>(),"trust":crate::json::TrustJson::with_empty_reason(&trust,None),"trust_note":"Default me is narrower than v1 local. Explicit local includes authenticated retained collection authors. Weights are membership only; role aliases require the separate identity adapter.","coverage":"Complete within the bounded authorized authored-record traversal, not complete capture. Git-derived ancestry is not configured.","day_json_compatibility":false});
        let mut entries = Vec::new();
        if let Some(claims) = value["view"]
            .as_object_mut()
            .and_then(|v| v.remove("claims"))
        {
            for claim in claims.as_array().ok_or(Failure::Corrupt)? {
                entries.push(json!({"type":"claim","claim":claim}));
            }
        }
        if let Some(classes) = value["view"]
            .as_object_mut()
            .and_then(|v| v.remove("subjects"))
        {
            for mut class in classes.as_array().ok_or(Failure::Corrupt)?.clone() {
                let claims = class
                    .as_object_mut()
                    .ok_or(Failure::Corrupt)?
                    .remove("claims");
                let witnesses = class
                    .as_object_mut()
                    .ok_or(Failure::Corrupt)?
                    .remove("witnesses");
                let names = class["subjects"].clone();
                entries.push(json!({"type":"subject-state","subject":class}));
                if let Some(claims) = claims {
                    for claim in claims.as_array().ok_or(Failure::Corrupt)? {
                        entries.push(json!({"type":"claim","subjects":names,"claim":claim}));
                    }
                }
                if let Some(witnesses) = witnesses {
                    for witness in witnesses.as_array().ok_or(Failure::Corrupt)? {
                        entries.push(
                            json!({"type":"same-as-witness","subjects":names,"witness":witness}),
                        );
                    }
                }
            }
        }
        let (supplement, omitted) = self
            .derived_supplement(&source, subject.as_deref(), &derived, derived_budget)
            .await?;
        entries.extend(supplement);
        value["evaluation"] = json!({"id":view_id,"version":"kan-compat-evaluation/1","normalizer":"canonical-v1-fold/1","relations":"explicit-v1-witnesses/1","derived_reports":derived,"derived_budget":derived_budget,"derived_omitted":omitted,"authority":"Derived supplements do not change this authored fold, trust or identity. Inspect authored witnesses and retained report lineage separately."});
        value["entries"] = json!(entries);
        crate::evidence_library::mcp::pages::list(
            value,
            "entries",
            &json!({"source":source,"verb":verb,"subject":subject,"trust":trusted,"budget":budget,"derived":derived,"derived_budget":derived_budget}),
            cursor,
        )
        .map_err(|e| match e {
            crate::evidence_library::mcp::pages::Error::Cursor => Failure::Invalid.into(),
            crate::evidence_library::mcp::pages::Error::Limited => ContentError::Limited,
            _ => Failure::Corrupt.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft(verb: &str) -> Draft {
        serde_json::from_value(json!({"source":"proof:synthetic-collection","verb":verb,"subject":"issue/a","text":"A deliberate statement"})).unwrap()
    }
    fn batch(
        d: &Draft,
        signer: &crate::sign::Identity,
        history: &[(Cid, StoredClaim)],
        nonce: &str,
        time: u64,
        order: u64,
    ) -> Batch {
        let (subject, bodies) = bodies(d, history, signer.did().as_str()).unwrap();
        let operation = Operation {
            nonce: nonce.repeat(64),
            recorded_at: time,
        };
        let mut batch = Batch {
            version: 1,
            source: d.source.clone(),
            operation,
            order,
            intent_hash: "a".repeat(64),
            claims: vec![],
        };
        let artifact = batch.operation_artifact().unwrap();
        let mut previous = None;
        for (i, body) in bodies.into_iter().enumerate() {
            let cites = if matches!(body, ClaimBody::Status { .. }) && previous.is_some() {
                vec![previous.clone().unwrap()]
            } else if matches!(body, ClaimBody::Subject { .. }) {
                Vec::new()
            } else {
                parse_cids(&d.cites).unwrap()
            };
            let content = ClaimContent {
                author: AuthorId {
                    did: signer.did().to_string(),
                    agent: None,
                },
                workspace: anchor(&d.source).unwrap(),
                subject: subject.clone(),
                body,
                cites,
                artifacts: vec![artifact.clone()],
                recorded_at: Some(time + i as u64),
            };
            let cid = crate::cid::content_cid(&content).unwrap();
            let claim = Claim {
                content,
                sig: signer.sign(&cid.to_bytes()).unwrap(),
            };
            let raw = codec::encode_v1(claim, crate::store::encode_tid(order + i as u64)).unwrap();
            batch.claims.push(Encoded {
                cid: cid.to_string(),
                bytes: evidence_service::hex(&raw),
            });
            previous = Some(cid);
        }
        batch
    }
    #[test]
    fn narrative_and_paired_action_matrix_preserves_typed_claim_bodies() {
        for (verb, kind, status) in [
            ("observe", ClaimKind::Observation, None),
            ("plan", ClaimKind::Plan, None),
            ("decide", ClaimKind::Decision, None),
            ("result", ClaimKind::Result, None),
            ("block", ClaimKind::Blocker, Some(StatusValue::Blocked)),
            (
                "resolve",
                ClaimKind::Resolution,
                Some(StatusValue::Resolved),
            ),
        ] {
            let signer = crate::sign::Identity::generate();
            let b = batch(&draft(verb), &signer, &[], "a", 100, 200);
            let claims = b.decoded(signer.did().as_str()).unwrap();
            assert_eq!(claims[0].1.claim.content.body.kind(), kind);
            if let Some(status) = status {
                assert_eq!(claims.len(), 2);
                assert_eq!(
                    claims[1].1.claim.content.body,
                    ClaimBody::Status { value: status }
                );
                assert_eq!(claims[1].1.claim.content.cites, vec![claims[0].0.clone()]);
            } else {
                assert_eq!(claims.len(), 1);
            }
            assert!(b
                .decoded(crate::sign::Identity::generate().did().as_str())
                .is_err());
            let mut changed = b.clone();
            changed.source = "another collection".into();
            assert!(changed.decoded(signer.did().as_str()).is_err());
            let mut changed = b.clone();
            changed.claims[0].bytes.replace_range(..2, "00");
            assert!(changed.decoded(signer.did().as_str()).is_err());
        }
    }
    #[test]
    fn operation_identity_is_not_attested_time_and_append_order_is_not_recorded_time() {
        let signer = crate::sign::Identity::generate();
        let d = draft("decide");
        let first = batch(&d, &signer, &[], "a", 500, 1000);
        let retry = batch(&d, &signer, &[], "a", 500, 1000);
        assert_eq!(first.claims[0].bytes, retry.claims[0].bytes);
        let decoded = first.decoded(signer.did().as_str()).unwrap();
        assert_eq!(decoded[0].1.rev.len(), 13);
        assert_eq!(decoded[0].1.rev, crate::store::encode_tid(1000));
        // The attested append order must still match the canonical envelope.
        let mut wrong_order = first.clone();
        wrong_order.order += 1;
        assert!(wrong_order.decoded(signer.did().as_str()).is_err());
        wrong_order.order = i64::MAX as u64;
        assert!(wrong_order.decoded(signer.did().as_str()).is_err());
        let new = batch(&d, &signer, &[], "b", 500, 1004);
        assert_ne!(
            first.claims[0].cid, new.claims[0].cid,
            "a distinct deliberate act is not an exact retry"
        );
        let old_clock = batch(&d, &signer, &[], "c", 1, 1008);
        assert!(
            old_clock.decoded(signer.did().as_str()).unwrap()[0].1.rev
                > first.decoded(signer.did().as_str()).unwrap()[0].1.rev
        );
        assert_ne!(
            Batch::annotation_id(&d.source, &first.operation, signer.did().as_str()).unwrap(),
            Batch::annotation_id("other", &first.operation, signer.did().as_str()).unwrap()
        );
    }
    #[test]
    fn same_relate_status_declaration_retraction_and_rejection_reuse_reference_fold() {
        let a = crate::sign::Identity::generate();
        let b = crate::sign::Identity::generate();
        let mut d = draft("decide");
        d.status = Some(StatusValue::Open);
        d.title = Some("An issue".into());
        d.subject_kind = Some(SubjectKind::Issue);
        let first = batch(&d, &a, &[], "a", 100, 200)
            .decoded(a.did().as_str())
            .unwrap();
        assert_eq!(first.len(), 3);
        let mut same = draft("same");
        same.text = None;
        same.target = Some("alias/a".into());
        let link = batch(&same, &a, &first, "b", 110, 204)
            .decoded(a.did().as_str())
            .unwrap();
        let mut other = draft("mark");
        other.text = None;
        other.status = Some(StatusValue::Blocked);
        let contrary = batch(&other, &b, &first, "c", 120, 208)
            .decoded(b.did().as_str())
            .unwrap();
        let mut history = first.clone();
        history.extend(link);
        history.extend(contrary);
        let local = record_trust(&["local".into()], a.did().as_str(), &history).unwrap();
        let view = fold::fold(history.clone(), &local);
        assert_eq!(view.classes.len(), 1);
        assert_eq!(view.classes[0].subjects.len(), 2);
        assert_eq!(view.classes[0].witnesses.len(), 1);
        assert!(matches!(
            fold::state::classify(&view.classes[0].claims, &[]),
            fold::state::StateView::Contested { .. }
        ));
        let mine = record_trust(&["me".into()], a.did().as_str(), &history).unwrap();
        assert_eq!(
            fold::excluded_by_trust(&history, &mine)
                .values()
                .sum::<usize>(),
            1
        );
        let mut correction = draft("retract");
        correction.text = None;
        correction.target = Some(first[0].0.to_string());
        assert!(bodies(&correction, &history, b.did().as_str()).is_err());
        correction.verb = "reject".into();
        assert!(bodies(&correction, &history, b.did().as_str()).is_ok());
        assert!(bodies(&correction, &history, a.did().as_str()).is_err());
        correction.verb = "retract".into();
        let retract = batch(&correction, &a, &history, "d", 130, 212)
            .decoded(a.did().as_str())
            .unwrap();
        history.extend(retract.clone());
        assert!(!fold::fold(history.clone(), &local)
            .classes
            .iter()
            .flat_map(|c| &c.claims)
            .any(|(id, _)| id == &first[0].0));
        correction.target = Some(retract[0].0.to_string());
        history.extend(
            batch(&correction, &a, &history, "e", 140, 216)
                .decoded(a.did().as_str())
                .unwrap(),
        );
        assert!(fold::fold(history, &local)
            .classes
            .iter()
            .flat_map(|c| &c.claims)
            .any(|(id, _)| id == &first[0].0));
        let mut relation = same;
        relation.verb = "relate".into();
        relation.relation = Some("DependsOn".into());
        assert!(matches!(
            &bodies(&relation, &[], a.did().as_str()).unwrap().1[0],
            ClaimBody::Relation {
                kind: RelationKind::DependsOn,
                ..
            }
        ));
        relation.relation = Some("SameAs".into());
        assert!(bodies(&relation, &[], a.did().as_str()).is_err());
        assert!(record_trust(&["roles".into()], a.did().as_str(), &[]).is_err());
        assert!(record_trust(&["me=NaN".into()], a.did().as_str(), &[]).is_err());
    }
}
