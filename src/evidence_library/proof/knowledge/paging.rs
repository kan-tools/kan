use super::*;
impl Readers {
    pub(in crate::evidence_library) async fn annotations_page(
        &self,
        subject: Option<String>,
        tag: Option<String>,
        after: Option<String>,
        limit: usize,
    ) -> Result<Value, ContentError> {
        if limit == 0
            || limit > 100
            || subject.as_ref().is_some_and(|s| s.len() > 256)
            || tag.as_ref().is_some_and(|s| s.len() > 64)
        {
            return Err(Failure::Invalid.into());
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let workspace = self.workspace.clone().ok_or(Failure::Invalid)?;
        let page = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            workspace.annotations_page(after.as_deref(), limit)
        })
        .await
        .map_err(|_| Failure::Unavailable)??;
        let selected: std::collections::BTreeSet<_> = page
            .records
            .iter()
            .map(|r| r["id"].as_str().map(str::to_owned).ok_or(Failure::Corrupt))
            .collect::<Result<_, _>>()?;
        let (mut records, mut erased, partial) = self
            .authorize_annotations(page.records.into_iter().chain(page.related).collect())
            .await?;
        // Neighbors participate in attributed link checks even on another page
        // or outside the current tag filter. Their bodies are never returned.
        let mut withdrawals = linked_records(&records, "withdraws")?;
        let mut corrections = linked_records(&records, "supersedes")?;
        records.retain(|r| {
            selected.contains(r["id"].as_str().unwrap_or(""))
                && subject
                    .as_ref()
                    .is_none_or(|s| r["draft"]["subject"].as_str() == Some(s))
                && tag.as_ref().is_none_or(|t| {
                    r["draft"]["tags"]
                        .as_array()
                        .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(t)))
                })
        });
        erased.retain(|r| selected.contains(r["id"].as_str().unwrap_or("")));
        for links in [&mut withdrawals, &mut corrections] {
            links.retain(|id, _| records.iter().any(|r| r["id"].as_str() == Some(id)));
        }
        Ok(
            json!({"records":records,"erased":erased,"withdrawals":withdrawals,"corrections":corrections,"next":page.next,
            "coverage":if partial {"partial"}else{"complete"},
            "scope":"this page with currently authorized incoming correction/withdrawal links across the workspace",
            "authority":"Reader-authored annotations; captured speaker claims and imported v1 claims are separate."}),
        )
    }
}
