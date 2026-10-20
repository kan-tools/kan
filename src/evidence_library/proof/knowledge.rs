//! Explicit reader-authored annotations. Captured assertions remain separate.
use super::Readers;
use crate::{
    evidence_content::ContentError,
    evidence_reader::proof::{Pin, Token},
    evidence_service::Failure,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub source: String,
    pub pin: Pin,
    pub selection: Token,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub kind: crate::claim::v1::RelationKind,
    pub target: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub subject: String,
    pub text: String,
    pub tags: Vec<String>,
    pub cites: Vec<Citation>,
    /// Correction points to an earlier annotation; no earlier data is replaced.
    pub supersedes: Option<String>,
    /// Explicit human promotion keeps the model-job provenance separate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relations: Vec<Relation>,
}
impl Readers {
    pub(super) async fn annotation_preview(&self, mut draft: Draft) -> Result<Value, ContentError> {
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        if draft.subject.trim().is_empty()
            || draft.subject.len() > 256
            || draft.text.trim().is_empty()
            || draft.text.len() > 8192
            || draft.tags.len() > 32
            || draft.tags.iter().any(|s| s.is_empty() || s.len() > 64)
            || draft.cites.is_empty()
            || draft.cites.len() > 8
            || draft.derived_from.len() > 8
            || draft.relations.len() > 16
            || draft
                .relations
                .iter()
                .any(|r| r.target.trim().is_empty() || r.target.len() > 256)
        {
            return Err(Failure::Invalid.into());
        }
        draft.tags.sort();
        draft.tags.dedup();
        let mut relations = Vec::new();
        for relation in draft.relations {
            if !relations.contains(&relation) {
                relations.push(relation);
            }
        }
        draft.relations = relations;
        let workspace = self.workspace()?;
        if let Some(previous) = &draft.supersedes {
            if previous.len() != 64
                || !previous
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(Failure::Invalid.into());
            }
            let old = workspace
                .get("annotation", previous)?
                .ok_or(Failure::AccessLimited)?;
            if old["author"] != workspace.author() || old["draft"]["subject"] != draft.subject {
                return Err(Failure::AccessLimited.into());
            }
            let prior: Draft =
                serde_json::from_value(old["draft"].clone()).map_err(|_| Failure::Corrupt)?;
            // A correction cites both its original annotation and all the original
            // evidence, so it cannot quietly drop inconvenient provenance.
            for job in prior.derived_from {
                if !draft.derived_from.contains(&job) {
                    draft.derived_from.push(job);
                }
            }
            for citation in prior.cites {
                let encoded = serde_json::to_value(&citation).map_err(|_| Failure::Invalid)?;
                if !draft
                    .cites
                    .iter()
                    .any(|c| serde_json::to_value(c).ok().as_ref() == Some(&encoded))
                {
                    draft.cites.push(citation);
                }
            }
            if draft.cites.len() > 8 {
                return Err(Failure::Invalid.into());
            }
        }
        draft.derived_from.sort();
        draft.derived_from.dedup();
        if draft.derived_from.len() > 8 {
            return Err(Failure::Invalid.into());
        }
        for id in &draft.derived_from {
            let job = workspace
                .get("analysis-job", id)?
                .ok_or(Failure::AccessLimited)?;
            if workspace.get("analysis-result", id)?.is_none() {
                return Err(Failure::Missing.into());
            }
            let inputs: super::analysis::Draft =
                serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?;
            for cite in inputs.cites {
                let encoded = serde_json::to_value(&cite).map_err(|_| Failure::Invalid)?;
                if !draft
                    .cites
                    .iter()
                    .any(|c| serde_json::to_value(c).ok().as_ref() == Some(&encoded))
                {
                    draft.cites.push(cite);
                }
            }
        }
        if draft.cites.len() > 8 {
            return Err(Failure::Invalid.into());
        }
        let mut evidence = Vec::new();
        for cite in &draft.cites {
            let source = self
                .selected(&cite.source)?
                .source(&cite.pin, &cite.selection)
                .await?;
            let (record, availability) = match source {
                crate::evidence_reader::proof::Source::Available { record, .. } => {
                    (record, "available")
                }
                crate::evidence_reader::proof::Source::Missing { record } => (record, "missing"),
                crate::evidence_reader::proof::Source::Corrupt { record } => (record, "corrupt"),
            };
            evidence
                .push(json!({"source":cite.source,"record":record,"availability":availability}));
        }
        let (authorized, partial) = self.authorized_sources().await;
        if draft.cites.iter().any(|c| !authorized.contains(&c.source)) {
            return Err(if partial {
                Failure::Unavailable
            } else {
                Failure::AccessLimited
            }
            .into());
        }
        let declaration = json!({"version":1,"author":workspace.author(),"analysis_trigger_plan":self.annotation_analysis_plan(&draft.tags),"draft":draft});
        let id = crate::evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&declaration).map_err(|_| Failure::Invalid)?,
        ));
        Ok(
            json!({"id":id,"declaration":declaration,"evidence":evidence,"effect":"Append an attributed annotation. Retained evidence and previous annotations are unchanged."}),
        )
    }
    pub(super) async fn annotation_save(
        &self,
        draft: Draft,
        preview: String,
    ) -> Result<Value, ContentError> {
        let checked = self.annotation_preview(draft).await?;
        if checked["id"] != preview {
            return Err(Failure::Invalid.into());
        }
        let mut declaration = checked["declaration"].clone();
        declaration["id"] = json!(preview);
        if let Some(prior) = self.workspace()?.get("annotation", &preview)? {
            self.schedule_annotation(&prior).await?;
            return Ok(prior);
        }
        declaration["recorded_at"] = json!(crate::evidence_operations::now().to_string());
        self.workspace()?
            .put("annotation", &preview, declaration.clone())?;
        self.schedule_annotation(&declaration).await?;
        Ok(declaration)
    }
    pub(super) async fn annotations(
        &self,
        subject: Option<String>,
        tag: Option<String>,
    ) -> Result<Value, ContentError> {
        if subject.as_ref().is_some_and(|s| s.len() > 256)
            || tag.as_ref().is_some_and(|s| s.len() > 64)
        {
            return Err(Failure::Invalid.into());
        }
        let declarations = self.declarations(true).await?;
        let (authorized, partial) = self.authorized_sources().await;
        let mut records = Vec::new();
        for declaration in declarations {
            let draft: Draft = serde_json::from_value(declaration["draft"].clone())
                .map_err(|_| Failure::Corrupt)?;
            if draft.cites.is_empty()
                || draft.cites.iter().any(|c| !authorized.contains(&c.source))
                || subject.as_ref().is_some_and(|s| s != &draft.subject)
                || tag.as_ref().is_some_and(|t| !draft.tags.contains(t))
            {
                continue;
            }
            records.push(declaration);
        }
        Ok(
            json!({"records":records,"coverage":if partial {"partial"} else {"complete"},"authority":"Reader-authored annotations; captured speaker claims and imported v1 claims are separate."}),
        )
    }
    /// Relations are attributed assertions with retained correction history.
    /// This view does not rewrite identity or collapse competing assertions.
    pub(super) async fn knowledge_graph(
        &self,
        subject: Option<String>,
        day: bool,
    ) -> Result<Value, ContentError> {
        if subject.as_ref().is_some_and(|s| s.len() > 256) {
            return Err(Failure::Invalid.into());
        }
        let visible = self.annotations(None, None).await?;
        let records = visible["records"].as_array().ok_or(Failure::Corrupt)?;
        let mut subjects = std::collections::BTreeMap::<String, Vec<&Value>>::new();
        let mut corrected = std::collections::BTreeMap::<String, Vec<String>>::new();
        for record in records {
            let name = record["draft"]["subject"]
                .as_str()
                .ok_or(Failure::Corrupt)?;
            subjects.entry(name.into()).or_default().push(record);
            if let Some(prior) = record["draft"]["supersedes"].as_str() {
                corrected
                    .entry(prior.into())
                    .or_default()
                    .push(record["id"].as_str().ok_or(Failure::Corrupt)?.into());
            }
        }
        fn process(name: &str) -> Option<&'static str> {
            ["telos", "atom", "bridge", "thread"]
                .into_iter()
                .find(|prefix| name.starts_with(&format!("{prefix}/")))
        }
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut selected_records = Vec::new();
        for (name, items) in &subjects {
            if subject.as_ref().is_none_or(|s| s == name) && (!day || process(name).is_some()) {
                nodes.push(json!({"subject":name,"kind":process(name).unwrap_or("subject"),"declarations":items.len(),"tags":items.iter().flat_map(|r|r["draft"]["tags"].as_array().into_iter().flatten().filter_map(Value::as_str)).collect::<std::collections::BTreeSet<_>>()}));
                if subject.is_some() {
                    for record in items {
                        selected_records.push(json!({"declaration":record,"corrected_by":corrected.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default()}));
                    }
                }
            }
            for record in items {
                let draft: Draft = serde_json::from_value(record["draft"].clone())
                    .map_err(|_| Failure::Corrupt)?;
                for relation in draft.relations {
                    if subject
                        .as_ref()
                        .is_none_or(|s| s == name || s == &relation.target)
                        && (!day || process(name).is_some() || process(&relation.target).is_some())
                    {
                        edges.push(json!({"from":name,"to":relation.target,"kind":relation.kind,"annotation":record["id"],"author":record["author"],"corrected_by":corrected.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default(),"cites":draft.cites}));
                    }
                }
            }
        }
        Ok(
            json!({"subjects":nodes,"relations":edges,"records":selected_records,"coverage":visible["coverage"],
            "authority":"Reader-authored declarations only. Relations retain direction and attribution; identity is not merged. Corrections are history, and multiple corrections may coexist. Unseen or unauthorized declarations are not counted."}),
        )
    }
}
