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
    /// An attributed withdrawal retains the original assertion and its evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdraws: Option<String>,
    /// Explicit human promotion keeps the model-job provenance separate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relations: Vec<Relation>,
}
impl Draft {
    fn validate(&self) -> Result<(), Failure> {
        if self.subject.trim().is_empty()
            || self.subject.len() > 256
            || self.text.trim().is_empty()
            || self.text.len() > 8192
            || self.tags.len() > 32
            || self.tags.iter().any(|s| s.is_empty() || s.len() > 64)
            || self.cites.is_empty()
            || self.cites.len() > 8
            || self.derived_from.len() > 8
            || self.relations.len() > 16
            || (self.withdraws.is_some()
                && (self.supersedes.is_some()
                    || !self.tags.is_empty()
                    || !self.relations.is_empty()))
            || self
                .relations
                .iter()
                .any(|r| r.target.trim().is_empty() || r.target.len() > 256)
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
}
impl Readers {
    pub(super) async fn restore_annotation(
        &self,
        reference: crate::evidence_reader::proof::Reference,
        preview: Option<String>,
    ) -> Result<Value, ContentError> {
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let workspace = self.workspace()?;
        let source = super::source_id(&reference.binding);
        let reader = self.selected(&source)?;
        let (pin, record) = reader.resolve_reference(&reference).await?;
        let crate::evidence_reader::proof::Source::Available {
            writer, plaintext, ..
        } = reader.source(&pin, &record.selection).await?
        else {
            return Err(Failure::Missing.into());
        };
        if plaintext.len() > 262144 {
            return Err(Failure::Invalid.into());
        }
        let publication: Value =
            serde_json::from_slice(&plaintext).map_err(|_| Failure::Invalid)?;
        if publication["format"] != "kan-annotation/1"
            || publication.as_object().is_none_or(|m| m.len() != 2)
        {
            return Err(Failure::Invalid.into());
        }
        let declaration = &publication["declaration"];
        let object = declaration.as_object().ok_or(Failure::Invalid)?;
        let fields = [
            "version",
            "author",
            "analysis_trigger_plan",
            "draft",
            "id",
            "recorded_at",
        ];
        if object.len() != fields.len()
            || fields.iter().any(|k| !object.contains_key(*k))
            || declaration["version"] != 1
            || declaration["author"] != writer
        {
            return Err(Failure::Invalid.into());
        }
        let draft: Draft =
            serde_json::from_value(declaration["draft"].clone()).map_err(|_| Failure::Invalid)?;
        draft.validate()?;
        crate::evidence_content::coordinate(
            declaration["recorded_at"]
                .as_str()
                .ok_or(Failure::Invalid)?,
        )?;
        let id = declaration["id"].as_str().ok_or(Failure::Invalid)?;
        let mut original = declaration.clone();
        original
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .remove("id");
        original
            .as_object_mut()
            .ok_or(Failure::Invalid)?
            .remove("recorded_at");
        if crate::evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&original).map_err(|_| Failure::Invalid)?,
        )) != id
        {
            return Err(Failure::Corrupt.into());
        }
        let (authorized, partial) = self.authorized_sources().await;
        if !authorized.contains(&source)
            || draft.cites.iter().any(|c| !authorized.contains(&c.source))
        {
            return Err(if partial {
                Failure::Unavailable
            } else {
                Failure::AccessLimited
            }
            .into());
        }
        let contract = json!({"version":1,"workspace_author":workspace.author(),"reference":reference,"declaration":declaration});
        let digest = crate::evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&contract).map_err(|_| Failure::Invalid)?,
        ));
        let mut restored = declaration.clone();
        restored["recovered_from"] = json!({"source":source,"reference":reference,"writer":writer});
        if let Some(expected) = preview {
            if expected != digest {
                return Err(Failure::Invalid.into());
            }
            reader.page(&pin, None, 1).await?;
            if let Some(prior) = workspace.get("annotation", id)? {
                let mut plain = prior.clone();
                plain
                    .as_object_mut()
                    .ok_or(Failure::Corrupt)?
                    .remove("recovered_from");
                if plain != *declaration {
                    return Err(Failure::Conflict.into());
                }
                restored = prior;
            } else {
                workspace.put("annotation", id, restored.clone())?;
            }
            Ok(
                json!({"state":"restored","annotation":restored,"automatic_analysis":"not-triggered","publication":"not-performed"}),
            )
        } else {
            Ok(
                json!({"state":"preview","digest":digest,"contract":contract,"effect":"Restore the exact published annotation into this encrypted workspace, retaining its original author, ID, timestamp, citations and publication origin. Do not trigger analysis or republish. Missing correction parents or analysis jobs remain unresolved."}),
            )
        }
    }
    pub(super) async fn annotation_preview(&self, mut draft: Draft) -> Result<Value, ContentError> {
        let _permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        draft.validate()?;
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
        let mut parent_origin = None;
        if let Some(previous) = draft.supersedes.as_ref().or(draft.withdraws.as_ref()) {
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
            if prior.withdraws.is_some()
                || (draft.withdraws.is_some()
                    && draft
                        .derived_from
                        .iter()
                        .any(|id| !prior.derived_from.contains(id)))
            {
                return Err(Failure::Invalid.into());
            }
            parent_origin = old["recovered_from"]["source"].as_str().map(str::to_owned);
            // A correction or withdrawal cites its original annotation and all the original
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
        // Withdrawal preserves recorded lineage even when the old job is no
        // longer available locally; it does not promote another model result.
        for id in draft
            .derived_from
            .iter()
            .filter(|_| draft.withdraws.is_none())
        {
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
                .cited_source(&cite.pin, &cite.selection)
                .await?;
            let (record, availability) = match source {
                crate::evidence_reader::proof::Source::Available { record, .. } => {
                    (record, "available")
                }
                crate::evidence_reader::proof::Source::KeyUnavailable { record, .. } => {
                    (record, "key-unavailable")
                }
                crate::evidence_reader::proof::Source::Missing { record } => (record, "missing"),
                crate::evidence_reader::proof::Source::Corrupt { record } => (record, "corrupt"),
            };
            evidence
                .push(json!({"source":cite.source,"record":record,"availability":availability}));
        }
        let (authorized, partial) = self.authorized_sources().await;
        if draft.cites.iter().any(|c| !authorized.contains(&c.source))
            || parent_origin
                .as_ref()
                .is_some_and(|source| !authorized.contains(source))
        {
            return Err(if partial {
                Failure::Unavailable
            } else {
                Failure::AccessLimited
            }
            .into());
        }
        let withdrawing = draft.withdraws.is_some();
        let declaration = json!({"version":1,"author":workspace.author(),"analysis_trigger_plan":if withdrawing { json!([]) } else { self.annotation_analysis_plan(&draft.tags) },"draft":draft});
        let id = crate::evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&declaration).map_err(|_| Failure::Invalid)?,
        ));
        Ok(
            json!({"id":id,"declaration":declaration,"evidence":evidence,"effect":if withdrawing {"Append the author’s withdrawal and its reason. Preserve the original assertion, source citations and analysis lineage; do not schedule automatic analysis."} else {"Append an attributed annotation. Retained evidence and previous annotations are unchanged."}}),
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
            if declaration["recovered_from"]["source"]
                .as_str()
                .is_some_and(|s| !authorized.contains(s))
                || draft.cites.is_empty()
                || draft.cites.iter().any(|c| !authorized.contains(&c.source))
            {
                continue;
            }
            records.push(declaration);
        }
        let mut withdrawals = linked_records(&records, "withdraws")?;
        records.retain(|r| {
            subject
                .as_ref()
                .is_none_or(|s| r["draft"]["subject"].as_str() == Some(s))
                && tag.as_ref().is_none_or(|t| {
                    r["draft"]["tags"]
                        .as_array()
                        .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(t)))
                })
        });
        withdrawals.retain(|id, _| records.iter().any(|r| r["id"].as_str() == Some(id)));
        Ok(
            json!({"records":records,"withdrawals":withdrawals,"coverage":if partial {"partial"} else {"complete"},"authority":"Reader-authored annotations; captured speaker claims and imported v1 claims are separate."}),
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
        let corrected = linked_records(records, "supersedes")?;
        let withdrawn = linked_records(records, "withdraws")?;
        for record in records {
            let name = record["draft"]["subject"]
                .as_str()
                .ok_or(Failure::Corrupt)?;
            subjects.entry(name.into()).or_default().push(record);
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
                        selected_records.push(json!({"declaration":record,"corrected_by":corrected.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default(),"withdrawn_by":withdrawn.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default()}));
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
                        edges.push(json!({"from":name,"to":relation.target,"kind":relation.kind,"annotation":record["id"],"author":record["author"],"corrected_by":corrected.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default(),"withdrawn_by":withdrawn.get(record["id"].as_str().ok_or(Failure::Corrupt)?).cloned().unwrap_or_default(),"cites":draft.cites}));
                    }
                }
            }
        }
        Ok(
            json!({"subjects":nodes,"relations":edges,"records":selected_records,"coverage":visible["coverage"],
            "authority":"Reader-authored declarations only. Relations retain direction and attribution; identity is not merged. Corrections and withdrawals retain history; withdrawn edges are labeled, not removed. Unseen or unauthorized declarations are not counted."}),
        )
    }
}

/// Only an authorized same-author, same-subject assertion can qualify another.
/// A restored publication naming an arbitrary ID cannot change its display state.
fn linked_records(
    records: &[Value],
    field: &str,
) -> Result<std::collections::BTreeMap<String, Vec<String>>, Failure> {
    let by_id: std::collections::BTreeMap<_, _> = records
        .iter()
        .map(|record| {
            record["id"]
                .as_str()
                .map(|id| (id, record))
                .ok_or(Failure::Corrupt)
        })
        .collect::<Result<_, _>>()?;
    let mut links = std::collections::BTreeMap::<String, Vec<String>>::new();
    for record in records {
        let Some(id) = record["draft"][field].as_str() else {
            continue;
        };
        let Some(parent) = by_id.get(id) else {
            continue;
        };
        if parent["author"] == record["author"]
            && parent["draft"]["subject"] == record["draft"]["subject"]
            && parent["draft"]["withdraws"].is_null()
        {
            links
                .entry(id.into())
                .or_default()
                .push(record["id"].as_str().ok_or(Failure::Corrupt)?.into());
        }
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_links_cannot_withdraw_another_authors_or_subjects_assertion() {
        let original = json!({"id":"original","author":"alice","draft":{"subject":"subject"}});
        let withdrawal = json!({"id":"withdrawal","author":"alice","draft":{"subject":"subject","withdraws":"original"}});
        let mut foreign = withdrawal.clone();
        foreign["author"] = json!("bob");
        let mut other_subject = withdrawal.clone();
        other_subject["draft"]["subject"] = json!("other");
        for invalid in [foreign, other_subject] {
            assert!(linked_records(&[original.clone(), invalid], "withdraws")
                .unwrap()
                .is_empty());
        }
        assert!(
            linked_records(std::slice::from_ref(&withdrawal), "withdraws")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            linked_records(&[original, withdrawal], "withdraws").unwrap()["original"],
            vec!["withdrawal"]
        );
    }
}
