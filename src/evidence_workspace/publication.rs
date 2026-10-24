//! Independent sender enrollment and exact source bindings. The encrypted
//! workspace authenticates what was queued; a deterministic operation ID alone
//! never establishes which plaintext a signed opaque request contains.
use super::*;
use crate::evidence_erasure_history::{Access, Snapshot};
use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: PathBuf,
    pub signing_key: PathBuf,
    pub recipient_key: PathBuf,
    pub sources: Vec<Access>,
}
impl Config {
    pub fn open(&self) -> Result<Arc<Workspace>> {
        if !self.database.is_absolute()
            || !self.signing_key.is_absolute()
            || !self.recipient_key.is_absolute()
            || self.sources.is_empty()
            || self.sources.len() > 16
            || self.sources.iter().any(|h| h.minimum.is_none())
        {
            return Err(Failure::Invalid);
        }
        // A missing restored workspace must not silently create a new authority.
        private(&self.database, false)?;
        Ok(Arc::new(
            Workspace::open(
                &self.database,
                Identity::load_existing(&self.signing_key).map_err(invalid)?,
                crypto::read_private_key(&self.recipient_key).map_err(invalid)?,
            )?
            .with_erasure_histories(self.sources.clone())?,
        ))
    }
}
impl Workspace {
    pub(crate) fn publication_annotation(&self, raw: &[u8]) -> Result<String> {
        let request = evidence_service::SignedRequest::decode(raw)?;
        if request.request.principal != self.author() {
            return Err(Failure::AccessLimited);
        }
        let manifest = evidence_service::append_manifest(raw)?.cid().to_string();
        let binding = self
            .get("annotation-publication", &manifest)?
            .ok_or(Failure::AccessLimited)?;
        if binding["version"] != 1 || binding["manifest"] != manifest {
            return Err(Failure::Corrupt);
        }
        let id = binding["annotation"].as_str().ok_or(Failure::Corrupt)?;
        let annotation = self.get("annotation", id)?.ok_or(Failure::AccessLimited)?;
        if annotation["id"] != id || annotation["author"] != self.author() {
            return Err(Failure::AccessLimited);
        }
        Ok(id.into())
    }
    /// Verify an exact queued request, all known ancestor citations and current
    /// independently enrolled custody. Retain these leases through external I/O.
    pub fn authorize_publication(&self, raw: &[u8]) -> Result<Vec<Snapshot>> {
        let leases = self.publication_lease()?;
        if leases.is_empty() {
            return Err(Failure::AccessLimited);
        }
        let id = self.publication_annotation(raw)?;
        let mut pending = VecDeque::from([("annotation".to_string(), id)]);
        let mut seen = BTreeSet::new();
        let mut bytes = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Some((kind, id)) = pending.pop_front() {
            if !seen.insert((kind.clone(), id.clone())) {
                continue;
            }
            if seen.len() > 4096 || Instant::now() >= deadline {
                return Err(Failure::Unavailable);
            }
            let record = self.get(&kind, &id)?.ok_or(Failure::AccessLimited)?;
            if record["id"] != id {
                return Err(Failure::Corrupt);
            }
            bytes += serde_json::to_vec(&record).map_err(invalid)?.len();
            if bytes > 8 * 1024 * 1024 {
                return Err(Failure::Unavailable);
            }
            let draft = &record["draft"];
            let cites = draft["cites"].as_array().ok_or(Failure::Corrupt)?;
            if cites.is_empty() || cites.len() > 8 {
                return Err(Failure::Corrupt);
            }
            for cite in cites {
                let token: crate::evidence_reader::proof::Token =
                    serde_json::from_value(cite["selection"].clone()).map_err(invalid)?;
                let (binding, _) = token.attributed_source()?;
                if !self.erasure_histories.iter().any(|h| &h.binding == binding) {
                    return Err(Failure::AccessLimited);
                }
            }
            let edges: &[(&str, &str)] = if kind == "annotation" {
                &[("supersedes", "annotation"), ("withdraws", "annotation")]
            } else {
                &[
                    ("retry_of", "analysis-job"),
                    ("trigger_annotation", "annotation"),
                ]
            };
            for (field, parent_kind) in edges {
                match draft.get(*field) {
                    None | Some(Value::Null) => {}
                    Some(Value::String(id)) => {
                        pending.push_back(((*parent_kind).into(), id.clone()))
                    }
                    _ => return Err(Failure::Corrupt),
                }
            }
            if let Some(parents) = draft.get("derived_from") {
                let parents = parents.as_array().ok_or(Failure::Corrupt)?;
                if parents.len() > 8 {
                    return Err(Failure::Corrupt);
                }
                for parent in parents {
                    pending.push_back((
                        "analysis-job".into(),
                        parent.as_str().ok_or(Failure::Corrupt)?.into(),
                    ));
                }
            }
        }
        Ok(leases)
    }
}
