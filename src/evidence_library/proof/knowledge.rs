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
        {
            return Err(Failure::Invalid.into());
        }
        draft.tags.sort();
        draft.tags.dedup();
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
}
