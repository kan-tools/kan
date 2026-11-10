//! Bounded authored-graph selection, evaluated by the canonical fold. This is a
//! frozen interpretation input, never a second graph, grant or mutable subject.
use super::{records, Readers};
use crate::{
    claim::v1::*,
    evidence_content::ContentError,
    evidence_service::{self, Failure},
    fold,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectSelection {
    pub source: String,
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Segment prefix: project/a matches itself and project/a/*, not project/ab.
    pub prefix: Option<String>,
    #[serde(default)]
    pub trust: Vec<String>,
    #[serde(default)]
    pub relation_depth: usize,
    #[serde(default = "subjects_limit")]
    pub max_subjects: usize,
    #[serde(default = "claims_limit")]
    pub max_claims: usize,
}
fn subjects_limit() -> usize {
    16
}
fn claims_limit() -> usize {
    128
}
impl ProjectSelection {
    fn valid(&self) -> bool {
        self.source.len() <= 1024
            && self.subjects.len() <= 16
            && (!self.subjects.is_empty() || self.prefix.is_some())
            && self
                .subjects
                .iter()
                .all(|s| crate::actions::validate_subject_name(s).is_ok())
            && self
                .prefix
                .as_ref()
                .is_none_or(|s| crate::actions::validate_subject_name(s).is_ok())
            && self.trust.len() <= 16
            && self.relation_depth <= 2
            && (1..=32).contains(&self.max_subjects)
            && (1..=256).contains(&self.max_claims)
    }
}
fn select(
    view: &fold::FoldedView,
    query: &ProjectSelection,
) -> Result<BTreeSet<usize>, ContentError> {
    let mut selected = BTreeSet::new();
    for (index, class) in view.classes.iter().enumerate() {
        if class.subjects.iter().any(|s| match s {
            SubjectRef::Local(s) => {
                query.subjects.contains(s)
                    || query.prefix.as_ref().is_some_and(|p| {
                        s == p || s.strip_prefix(p).is_some_and(|tail| tail.starts_with('/'))
                    })
            }
            _ => false,
        }) {
            selected.insert(index);
        }
    }
    if selected.is_empty() {
        return Err(Failure::Missing.into());
    }
    // One canonical identity class is indivisible. Relation neighborhoods are
    // explicit live authored edges; equal labels never merge distinct subjects.
    for _ in 0..query.relation_depth {
        let previous = selected.clone();
        for (index, class) in view.classes.iter().enumerate() {
            for (_, claim) in &class.claims {
                if let ClaimBody::Relation { target, .. } = &claim.content.body {
                    if let Some(other) = view
                        .classes
                        .iter()
                        .position(|c| c.subjects.contains(target))
                    {
                        if previous.contains(&index) || previous.contains(&other) {
                            selected.insert(index);
                            selected.insert(other);
                        }
                    }
                }
            }
        }
    }
    if selected
        .iter()
        .map(|i| view.classes[*i].subjects.len())
        .sum::<usize>()
        > query.max_subjects
    {
        return Err(ContentError::Limited);
    }
    Ok(selected)
}
impl Readers {
    pub(super) async fn project_selection(
        &self,
        query: &ProjectSelection,
        derivations: &[String],
    ) -> Result<Value, ContentError> {
        if !query.valid() {
            return Err(Failure::Invalid.into());
        }
        let history = self.record_history(&query.source, true).await?;
        history.require_complete()?;
        let trust =
            records::record_trust(&query.trust, &self.workspace()?.author(), &history.claims)?;
        let view = fold::fold(history.claims.clone(), &trust);
        let selected = select(&view, query)?;
        let mut subjects = Vec::new();
        let mut classes = Vec::new();
        let mut live = BTreeSet::new();
        for i in &selected {
            let class = &view.classes[*i];
            subjects.extend(class.subjects.clone());
            let state = fold::state::classify(&class.claims, &[]);
            let (state, value, cid) = crate::json::state_fields(&state);
            live.extend(class.claims.iter().map(|(cid, _)| cid.to_string()));
            classes.push(json!({"subjects":class.subjects,"state":state,"value":value,"cid":cid,
                "flagged_oversized":class.flagged_oversized,"witnesses":class.witnesses.iter().map(|w|
                json!({"claim":w.claim_cid.to_string(),"author":w.author,"from":w.from,"to":w.to})).collect::<Vec<_>>()}));
        }
        // Keep the correction history in selected classes, not just the folded
        // live view. A source must not lose a counterclaim in a summary input.
        let mut claims = Vec::new();
        let mut units = Vec::new();
        for (cid, stored) in &history.claims {
            if !trust.trusts(&stored.claim.content.author)
                || !subjects.contains(&stored.claim.content.subject)
            {
                continue;
            }
            if claims.len() >= query.max_claims {
                return Err(ContentError::Limited);
            }
            let id = cid.to_string();
            let origin = history.origins.get(&id).ok_or(Failure::Corrupt)?;
            let active = live.contains(&id);
            claims.push(
                json!({"cid":id,"rev":stored.rev,"claim":stored.claim,"origin":origin,"live_at_selection":active}),
            );
            let text = stored
                .claim
                .content
                .body
                .text()
                .map(str::to_owned)
                .unwrap_or(
                    serde_json::to_string(&stored.claim.content.body)
                        .map_err(|_| Failure::Corrupt)?,
                );
            units.push(json!({"id":format!("claim:{id}"),"source":query.source,"text":text,"kind":"authored-claim",
                "role":"authored","rev":stored.rev,"author":stored.claim.content.author,"claim":stored.claim,"origin":origin,
                "live_at_selection":active,"recall_request":{"source":query.source,"verb":"show","subject":id,"trust":query.trust},
                "authority":"Signed authored assertion; fold participation and historical correction state are explicit. It is not independently verified truth."}));
        }
        let mut frontier = history
            .claims
            .iter()
            .map(|(c, stored)| json!({"cid":c.to_string(),"rev":stored.rev}))
            .collect::<Vec<_>>();
        frontier.sort_by_key(|v| v["cid"].as_str().unwrap_or_default().to_owned());
        let evaluation = json!({"version":"kan-project-evaluation/2","source":query.source,"frontier":frontier,
            "trust":crate::json::TrustJson::with_empty_reason(&trust,None),"selection":query,
            "derivations":derivations,"fold":"canonical-v1-fold/1","relations":"explicit-live-v1-witnesses/1",
            "unsupported":["weighted trust semantics","higher identity witnesses","computed Git ancestry"],
            "scope":"Frozen selected classes including trusted correction history; bounded relation neighborhood, not all project knowledge or complete capture."});
        use sha2::{Digest, Sha256};
        let id = evidence_service::hex(&Sha256::digest(
            serde_json::to_vec(&evaluation).map_err(|_| Failure::Corrupt)?,
        ));
        let manifest = json!({"version":"kan-project-input/1","evaluation":{"id":id,"definition":evaluation},"selection":query,
            "classes":classes,"claims":claims,"units":units});
        if serde_json::to_vec(&manifest)
            .map_err(|_| Failure::Corrupt)?
            .len()
            > 256 * 1024
        {
            return Err(ContentError::Limited);
        }
        Ok(manifest)
    }
    /// Access is checked against retained signed records, not a cached grant or
    /// today's fold result. Appends/corrections cannot rewrite this frontier.
    pub(super) async fn check_project_manifest(
        &self,
        manifest: &Value,
    ) -> Result<Vec<String>, ContentError> {
        let selection: ProjectSelection =
            serde_json::from_value(manifest["selection"].clone()).map_err(|_| Failure::Corrupt)?;
        if !selection.valid() || manifest["version"] != "kan-project-input/1" {
            return Err(Failure::Corrupt.into());
        }
        let history = self.record_history(&selection.source, true).await?;
        history.require_complete()?;
        let trust = records::record_trust(
            &selection.trust,
            &self.workspace()?.author(),
            &history.claims,
        )?;
        let claims = manifest["claims"]
            .as_array()
            .filter(|c| !c.is_empty() && c.len() <= selection.max_claims)
            .ok_or(Failure::Corrupt)?;
        let mut parents = BTreeSet::new();
        for claim in claims {
            let (_, found) = history
                .claims
                .iter()
                .find(|(cid, _)| claim["cid"] == cid.to_string())
                .ok_or(Failure::AccessLimited)?;
            if claim
                .get("rev")
                .is_some_and(|r| r.as_str() != Some(found.rev.as_str()))
                || !trust.trusts(&found.claim.content.author)
                || claim["claim"]
                    != serde_json::to_value(&found.claim).map_err(|_| Failure::Corrupt)?
            {
                return Err(Failure::Corrupt.into());
            }
            let origin = history
                .origins
                .get(claim["cid"].as_str().ok_or(Failure::Corrupt)?)
                .ok_or(Failure::Corrupt)?;
            for parent in origin["derived_from"].as_array().ok_or(Failure::Corrupt)? {
                parents.insert(parent.as_str().ok_or(Failure::Corrupt)?.to_owned());
                if parents.len() > 64 {
                    return Err(ContentError::Limited);
                }
            }
        }
        Ok(parents.into_iter().collect())
    }
}

pub(super) fn summary(manifest: &Value) -> Value {
    if manifest.is_null() {
        return Value::Null;
    }
    json!({"id":manifest["evaluation"]["id"],"selection":manifest["selection"],
        "unsupported":manifest["evaluation"]["definition"]["unsupported"],
        "frontier_claims":manifest["evaluation"]["definition"]["frontier"].as_array().map(Vec::len),
        "selected_claims":manifest["claims"].as_array().map(Vec::len),
        "coverage":manifest["evaluation"]["definition"]["scope"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn class(names: &[&str]) -> fold::SubjectView {
        fold::SubjectView {
            subjects: names
                .iter()
                .map(|s| SubjectRef::Local((*s).into()))
                .collect(),
            claims: Vec::new(),
            flagged_oversized: false,
            witnesses: Vec::new(),
        }
    }
    #[test]
    fn prefix_matches_segments_and_never_splits_a_canonical_identity_class() {
        let query: ProjectSelection =
            serde_json::from_value(json!({"source":"s","prefix":"project/a"})).unwrap();
        let view = fold::FoldedView {
            classes: vec![
                class(&["project/a", "alias/a"]),
                class(&["project/a/child"]),
                class(&["project/ab"]),
            ],
        };
        assert_eq!(select(&view, &query).unwrap(), BTreeSet::from([0, 1]));
        let mut limited = query.clone();
        limited.max_subjects = 2;
        assert!(matches!(
            select(&view, &limited),
            Err(ContentError::Limited)
        ));
        let missing: ProjectSelection =
            serde_json::from_value(json!({"source":"s","subjects":["missing"]})).unwrap();
        assert!(matches!(
            select(&view, &missing),
            Err(ContentError::Read(Failure::Missing))
        ));
        let mut invalid = query;
        invalid.relation_depth = 3;
        assert!(!invalid.valid());
    }
}
