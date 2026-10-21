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
        // This authenticates retained history, not just the displayed page.
        // Use the long-read budget: the 1,003-declaration regression exhausts
        // the short 20-second budget on a contended debug CI runner.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
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

// Disposable in-memory inverse citation index. It contains only hashes and
// opaque entry IDs; signed encrypted declarations remain the sole authority.
// An oversized index falls back to bounded scans, never a retention limit.
pub(super) struct Lookup {
    data_version: i64,
    entries: Option<BTreeMap<[u8; 32], BTreeSet<String>>>,
}
pub(crate) fn citation_key(
    source: &str,
    coordinate: &crate::evidence_proof_service::Coordinate,
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(&(source, coordinate)).map_err(invalid)?).into())
}
fn citation_keys(value: &Value) -> Result<BTreeSet<[u8; 32]>> {
    let draft: crate::evidence_library::AnnotationDraft =
        serde_json::from_value(value["draft"].clone()).map_err(invalid)?;
    draft
        .cites
        .iter()
        .map(|cite| {
            let (_, coordinate) = cite.selection.attributed_source()?;
            citation_key(&cite.source, coordinate)
        })
        .collect()
}
impl Workspace {
    /// A bounded page of annotations that could cite this search result page.
    /// Startup authenticates the inverse index once; subsequent pages decrypt
    /// only candidates. External commits invalidate it via SQLite data_version;
    /// local annotation appends invalidate it explicitly. Erasure is checked on
    /// each candidate, including when an old index still names a deleted entry.
    pub(crate) fn search_annotations_page(
        &self,
        keys: &BTreeSet<[u8; 32]>,
        after: Option<&str>,
        subject: Option<&str>,
        tag: Option<&str>,
    ) -> Result<(Vec<Value>, Option<String>)> {
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let _custody = self.check_erasure_histories(&tx)?;
        let data_version = tx
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(invalid)?;
        let mut lookup = self.annotation_lookup.lock().map_err(invalid)?;
        if lookup
            .as_ref()
            .is_none_or(|cache| cache.data_version != data_version)
        {
            let mut entries = BTreeMap::<_, BTreeSet<String>>::new();
            let mut links = 0usize;
            let mut overflow = false;
            let mut q = tx
                .prepare("SELECT id,body FROM entries WHERE kind='annotation' ORDER BY id")
                .map_err(invalid)?;
            let mut rows = q.query([]).map_err(invalid)?;
            while let Some(row) = rows.next().map_err(invalid)? {
                let id: String = row.get(0).map_err(invalid)?;
                if erasure::erased(self, &tx, "annotation", &id)? {
                    continue;
                }
                let body: Vec<u8> = row.get(1).map_err(invalid)?;
                let value = self.unseal("annotation", &id, &body)?;
                for key in citation_keys(&value)? {
                    entries.entry(key).or_default().insert(id.clone());
                    links += 1;
                }
                if links > 262144 {
                    overflow = true;
                    break;
                }
            }
            *lookup = Some(Lookup {
                data_version,
                entries: (!overflow).then_some(entries),
            });
        }
        let mut ids = BTreeSet::new();
        if let Some(entries) = &lookup.as_ref().ok_or(Failure::Corrupt)?.entries {
            for key in keys {
                if let Some(matches) = entries.get(key) {
                    for id in matches
                        .range((
                            std::ops::Bound::Excluded(after.unwrap_or("").to_owned()),
                            std::ops::Bound::Unbounded,
                        ))
                        .take(101)
                    {
                        ids.insert(id.clone());
                        if ids.len() > 101 {
                            ids.pop_last();
                        }
                    }
                }
            }
        } else {
            let mut q = tx
                .prepare(
                    "SELECT id FROM entries WHERE kind='annotation' AND id>? ORDER BY id LIMIT 101",
                )
                .map_err(invalid)?;
            for id in q
                .query_map([after.unwrap_or("")], |r| r.get::<_, String>(0))
                .map_err(invalid)?
            {
                ids.insert(id.map_err(invalid)?);
            }
        }
        let mut out = Vec::new();
        let mut last = None;
        let mut bytes = 0usize;
        for (i, id) in ids.into_iter().enumerate() {
            if i == 100 {
                return Ok((out, last));
            }
            let body: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT body FROM entries WHERE kind='annotation' AND id=?",
                    [&id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(invalid)?;
            if let Some(body) = body {
                if bytes > 0 && bytes + body.len() > 1024 * 1024 {
                    return Ok((out, last));
                }
                bytes += body.len();
                if !erasure::erased(self, &tx, "annotation", &id)? {
                    let value = self.unseal("annotation", &id, &body)?;
                    if subject.is_none_or(|s| value["draft"]["subject"].as_str() == Some(s))
                        && tag.is_none_or(|t| {
                            value["draft"]["tags"]
                                .as_array()
                                .is_some_and(|ts| ts.iter().any(|v| v.as_str() == Some(t)))
                        })
                        && !citation_keys(&value)?.is_disjoint(keys)
                    {
                        out.push(value);
                    }
                }
            }
            last = Some(id);
        }
        Ok((out, None))
    }
}
