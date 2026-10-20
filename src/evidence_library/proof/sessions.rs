//! Bounded cross-archive conversation presentation. Explicit selections and
//! observer membership claims remain separate from authenticated source identity.
use super::Readers;
use crate::{
    evidence_content::{self as content, ContentError, Format},
    evidence_reader::proof::{Pin, Token},
    evidence_service::Failure,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub writer: String,
    pub observer: String,
    pub scheme: String,
    pub session: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub source: String,
    pub pin: Pin,
    pub selections: Vec<Token>,
}
impl Readers {
    pub(super) async fn session_content(
        &self,
        identity: Identity,
        attempts: Vec<Selection>,
        format: Format,
    ) -> Result<Value, ContentError> {
        if identity.writer.is_empty()
            || identity.writer.len() > 256
            || !matches!(identity.observer.as_str(), "collector" | "gateway")
            || !matches!(
                identity.scheme.as_str(),
                "kan-header" | "claude-code-header"
            )
            || identity.session.is_empty()
            || identity.session.len() > 128
            || attempts.is_empty()
            || attempts.len() > 8
            || attempts.iter().any(|a| a.selections.is_empty())
            || attempts.iter().map(|a| a.selections.len()).sum::<usize>() > 1024
        {
            return Err(Failure::Invalid.into());
        }
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut rendered = Vec::new();
            let mut bytes = 0usize;
            let mut seen = std::collections::BTreeSet::new();
            for attempt in &attempts {
                // Duplicate archive selections are caller mistakes. Distinct
                // archive copies are preserved, never silently deduplicated.
                let key = serde_json::to_vec(&(
                    &attempt.source, &attempt.pin, &attempt.selections,
                )).map_err(|_| Failure::Invalid)?;
                if !seen.insert(key) {
                    return Err(Failure::Invalid.into());
                }
                let raw = content::proof_content(
                    self.selected(&attempt.source)?, &attempt.pin, &attempt.selections,
                    format, self.workers.clone(), true,
                ).await?;
                bytes = bytes.checked_add(raw.len()).ok_or(ContentError::Limited)?;
                if bytes > 96 * 1024 * 1024 {
                    return Err(ContentError::Limited);
                }
                let value: Value = serde_json::from_slice(&raw).map_err(|_| Failure::Corrupt)?;
                let groups = value["groups"].as_array().ok_or(Failure::Corrupt)?;
                let mut links = Vec::new();
                for group in groups {
                    if group["writer"] != identity.writer || group["observer"] != identity.observer {
                        return Err(Failure::Invalid.into());
                    }
                    for metadata in group["metadata"].as_array().ok_or(Failure::Corrupt)? {
                        let link = &metadata["session_link"];
                        if link["state"] == "claimed" {
                            links.push(link.clone());
                        }
                    }
                }
                let matches = links.iter().filter(|link|
                    link["scheme"] == identity.scheme && link["session"] == identity.session
                ).count();
                let membership = if links.is_empty() { "unconfirmed" }
                    else if matches == links.len() { "claimed" }
                    else { "conflicting" };
                rendered.push(json!({
                    "source":attempt.source, "pin":attempt.pin,
                    "membership":membership, "links":links, "content":value,
                }));
            }
            // Recheck every source after gathering, including earlier archives.
            // A later denial never returns an earlier plaintext prefix.
            for attempt in &attempts {
                self.selected(&attempt.source)?.page(&attempt.pin, None, 1).await?;
            }
            Ok(json!({
                "version":"kan-session-content/1",
                "identity":{"writer":identity.writer,"observer":identity.observer,
                    "scheme":identity.scheme,"session":identity.session},
                "attempts":rendered,
                "coverage":"Explicit selected attempts only. Supplied request history, archive copies, branch and compaction claims remain distinct. Display order is selection order, not verified chronology. Missing or conflicting membership remains visible."
            }))
        }).await.map_err(|_| ContentError::Limited)?
    }
}
