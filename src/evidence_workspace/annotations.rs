//! Paged declarations with incoming correction/withdrawal metadata from the
//! entire encrypted workspace. Unrelated annotation bodies are not retained.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) struct Page {
    pub records: Vec<Value>,
    pub related: Vec<Value>,
    pub next: Option<String>,
}
impl Workspace {
    pub(crate) fn annotations_page(&self, after: Option<&str>, limit: usize) -> Result<Page> {
        let (records, next) = self.declarations_page("annotation", after, limit)?;
        let selected: BTreeMap<_, _> = records
            .iter()
            .map(|r| {
                Ok((
                    r["id"].as_str().ok_or(Failure::Corrupt)?.to_owned(),
                    (
                        r["author"].clone(),
                        r["draft"]["subject"].clone(),
                        r["draft"]["withdraws"].is_null(),
                    ),
                ))
            })
            .collect::<Result<_>>()?;
        let ids: BTreeSet<_> = selected.keys().cloned().collect();
        let mut related = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut related_bytes = 0usize;
        if !ids.is_empty() {
            let conn = self.conn.lock().map_err(invalid)?;
            let tx = conn.unchecked_transaction().map_err(invalid)?;
            let _custody = self.check_erasure_histories(&tx)?;
            let mut q = tx
                .prepare("SELECT id,body FROM entries WHERE kind='annotation' ORDER BY id")
                .map_err(invalid)?;
            let mut rows = q.query([]).map_err(invalid)?;
            while let Some(row) = rows.next().map_err(invalid)? {
                if std::time::Instant::now() >= deadline {
                    return Err(Failure::Unavailable);
                }
                let id: String = row.get(0).map_err(invalid)?;
                if erasure::erased(self, &tx, "annotation", &id)? {
                    continue;
                }
                let bytes: Vec<u8> = row.get(1).map_err(invalid)?;
                let value = self.unseal("annotation", &id, &bytes)?;
                let annotation = value["id"].as_str().ok_or(Failure::Corrupt)?;
                if ids.contains(annotation) {
                    continue;
                }
                let draft = &value["draft"];
                let matches = ["supersedes", "withdraws"].into_iter().any(|field| {
                    draft[field]
                        .as_str()
                        .and_then(|id| selected.get(id))
                        .is_some_and(|(author, subject, assertion)| {
                            *assertion && author == &value["author"] && subject == &draft["subject"]
                        })
                });
                if matches {
                    // Only attribution, links and exact access-check citations
                    // are needed; do not copy the neighbor's text or recipes.
                    let neighbor = serde_json::json!({"id":annotation,"author":value["author"],
                        "recovered_from":value["recovered_from"],"draft":{"subject":draft["subject"],
                        "text":"","tags":[],"cites":draft["cites"],
                        "supersedes":draft["supersedes"],"withdraws":draft["withdraws"]}});
                    related_bytes = related_bytes
                        .checked_add(serde_json::to_vec(&neighbor).map_err(invalid)?.len())
                        .ok_or(Failure::Unavailable)?;
                    // An execution budget, never a retention/declaration limit.
                    // Refuse the page rather than omit cross-page history and
                    // falsely render an assertion as uncorrected/unwithdrawn.
                    if related_bytes > 8 * 1024 * 1024 {
                        return Err(Failure::Unavailable);
                    }
                    related.push(neighbor);
                }
            }
        }
        Ok(Page {
            records,
            related,
            next,
        })
    }
}
