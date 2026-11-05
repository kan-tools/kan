//! Bundled, on-demand derived reports. Plans bind an explicit pinned interval;
//! report reads require no provider credential and never promote annotations.
use super::{analysis, knowledge, Readers};
use crate::{
    evidence_content::ContentError, evidence_reader::proof::Pin, evidence_service::Failure,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub source: String,
    #[schemars(range(min = 1, max = 9007199254740991.0))]
    pub from: u64,
    #[schemars(range(min = 1, max = 9007199254740991.0))]
    pub through: u64,
    pub recipe: String,
    #[schemars(with = "Option<std::collections::BTreeMap<String,Value>>")]
    pub pin: Option<Pin>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized: Option<analysis::Finalized>,
}
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Excerpt {
    pub group: usize,
    pub direction: String,
    pub item: usize,
    pub part: String,
}
impl Excerpt {
    pub(crate) fn valid(&self) -> bool {
        self.group < 64
            && self.item < 100_000
            && matches!(self.direction.as_str(), "request" | "response")
            && matches!(self.part.as_str(), "text" | "tool")
    }
    fn from_unit(value: &str) -> Option<Self> {
        let parts: Vec<_> = value.split('/').collect();
        if parts.len() != 4 {
            return None;
        }
        let value = Self {
            group: parts[0].strip_prefix('g')?.parse().ok()?,
            direction: parts[1].into(),
            item: parts[2].strip_prefix('i')?.parse().ok()?,
            part: parts[3].into(),
        };
        value.valid().then_some(value)
    }
}
fn fragments(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let mut end = (at + 2048).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        out.push(text[at..end].to_owned());
        at = end;
    }
    out
}
// Input references are bounded rows too, never an unbounded repeated header.
fn report_page(mut value: Value, cursor: Option<Value>) -> Result<Value, ContentError> {
    let query = json!({"id": value["id"]});
    let mut rows = Vec::new();
    // Useful report text first. Full input manifests remain an explicit tail,
    // rather than making an agent read long URIs before the first statement.
    for (field, kind) in [("blocks", "block"), ("inputs", "input")] {
        let values = value
            .as_object_mut()
            .and_then(|m| m.remove(field))
            .and_then(|v| v.as_array().cloned())
            .ok_or(Failure::Corrupt)?;
        value[format!("{field}_count")] = json!(values.len());
        rows.extend(values.into_iter().map(|v| json!({"kind":kind,"value":v})));
        value[field] = json!([]);
    }
    value["entries"] = json!(rows);
    value["input_coverage"] = json!("Input references and text fragments both paginate. Follow next to retain the complete selected manifest and report; input numbers remain stable across pages.");
    let mut page = crate::evidence_library::mcp::pages::list(value, "entries", &query, cursor)
        .map_err(|e| match e {
            crate::evidence_library::mcp::pages::Error::Cursor => {
                ContentError::Read(Failure::Invalid)
            }
            crate::evidence_library::mcp::pages::Error::Limited => ContentError::Limited,
            _ => ContentError::Read(Failure::Corrupt),
        })?;
    let entries = page
        .as_object_mut()
        .and_then(|m| m.remove("entries"))
        .and_then(|v| v.as_array().cloned())
        .ok_or(Failure::Corrupt)?;
    for row in entries {
        let field = match row["kind"].as_str() {
            Some("input") => "inputs",
            Some("block") => "blocks",
            _ => return Err(Failure::Corrupt.into()),
        };
        page[field]
            .as_array_mut()
            .ok_or(Failure::Corrupt)?
            .push(row["value"].clone());
    }
    Ok(page)
}
impl Readers {
    /// Derived material has its own budget and never enters the authored fold.
    /// Callers append these rows AFTER all authored rows before pagination.
    pub(super) async fn derived_supplement(
        &self,
        source: &str,
        subject: Option<&str>,
        ids: &[String],
        budget: usize,
    ) -> Result<(Vec<Value>, usize), ContentError> {
        use crate::context::TokenEstimator;
        let estimator = crate::context::TiktokenEstimator::cl100k();
        let mut remaining = budget;
        let mut rows = Vec::new();
        let mut omitted = 0;
        let mut seen = std::collections::BTreeSet::new();
        for id in ids {
            if id.len() != 64 || crate::evidence_service::unhex(id, 32).is_err() || !seen.insert(id)
            {
                return Err(Failure::Invalid.into());
            }
            let job = self
                .workspace()?
                .get("analysis-job", id)?
                .ok_or(Failure::AccessLimited)?;
            let draft: analysis::Draft =
                serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?;
            // Recheck ALL dependency sources, not just the collection being
            // recalled; a cached result is never a cached grant.
            self.report_inputs(&draft, id).await?;
            if !draft.cites.iter().any(|c| c.source == source) {
                return Err(Failure::Invalid.into());
            }
            let result = self
                .workspace()?
                .get("analysis-result", id)?
                .ok_or(Failure::Missing)?;
            let Some(candidates) = result["consolidation"]["candidates"]
                .as_array()
                .filter(|_| result["state"] == "succeeded")
            else {
                rows.push(json!({"type":"derived-state","report":id,"state":"No validated structured consolidation; inspect the retained report explicitly."}));
                continue;
            };
            for (n, candidate) in candidates.iter().enumerate() {
                if subject.is_some_and(|label| {
                    !candidate["subjects"].as_array().is_some_and(|ss| {
                        ss.iter()
                            .any(|s| s["source"] == source && s["label"] == label)
                    })
                }) {
                    continue;
                }
                let row = json!({"type":"derived-supplement","report":id,"candidate":n,"statement":candidate,
                    "recipe":job["preview"]["recipe"]["id"],"revision":job["preview"]["recipe"]["revision"],"model":result["parsed"]["model"],
                    "authority":"Unpromoted model-derived suggestion; may disagree with authored claims. Recorded acceptance is not authored acceptance by this viewer.","report_request":{"id":id}});
                let tokens =
                    estimator.estimate(&serde_json::to_string(&row).map_err(|_| Failure::Corrupt)?);
                if tokens > remaining {
                    omitted += 1;
                    continue;
                }
                remaining -= tokens;
                rows.push(row);
            }
        }
        Ok((rows, omitted))
    }
    async fn extract_draft(
        &self,
        mut selection: Selection,
    ) -> Result<(Selection, analysis::Draft), ContentError> {
        if selection.through > 9_007_199_254_740_991
            || selection.from == 0
            || selection.through < selection.from
            || selection.through - selection.from >= 8
        {
            return Err(ContentError::Limited);
        }
        let reader = self.selected(&selection.source)?;
        let pin = match selection.pin.take() {
            Some(p) => p,
            None => reader.snapshot().await?,
        };
        let mut cursor = None;
        let mut cites = Vec::new();
        let mut done = false;
        // Explicit scan budget; never silently return a prefix of the interval.
        for _ in 0..500 {
            let page = reader.page(&pin, cursor.as_ref(), 20).await?;
            for record in page.records {
                let sequence = crate::evidence_content::coordinate(&record.sequence)?;
                if sequence >= selection.from && sequence <= selection.through {
                    cites.push(knowledge::Citation {
                        source: selection.source.clone(),
                        pin: pin.clone(),
                        selection: record.selection,
                    });
                }
                // Proof pages walk backward from the pinned frontier. Continue
                // through the inclusive lower bound, not just the newest row.
                if sequence <= selection.from {
                    done = true;
                    break;
                }
            }
            if done {
                break;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        if cites.len() as u64 != selection.through - selection.from + 1 {
            return Err(Failure::Missing.into());
        }
        // The bundle manifest and decoded input order are chronological.
        cites.reverse();
        selection.pin = Some(pin);
        Ok((
            selection.clone(),
            analysis::Draft {
                recipe: selection.recipe,
                cites,
                retry_of: None,
                trigger_annotation: None,
                decode: true,
                derived_from: selection.derived_from,
                finalized: selection.finalized,
            },
        ))
    }
    pub(super) async fn extract_plan(&self, selection: Selection) -> Result<Value, ContentError> {
        let (selection, draft) = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.extract_draft(selection),
        )
        .await
        .map_err(|_| ContentError::Limited)??;
        let mut value = self.analysis_preview(draft).await?;
        value
            .as_object_mut()
            .ok_or(Failure::Corrupt)?
            .remove("inputs");
        value["selection"] = serde_json::to_value(selection).map_err(|_| Failure::Invalid)?;
        value["authority"]=json!("Preview only. Exact selected inputs, derived report; no annotation promotion or provider request yet.");
        if serde_json::to_vec(&value)
            .map_err(|_| Failure::Corrupt)?
            .len()
            > 12 * 1024
        {
            return Err(ContentError::Limited);
        }
        Ok(value)
    }
    pub(super) async fn extract_run(
        &self,
        selection: Selection,
        preview: String,
        nonce: String,
        wait: bool,
    ) -> Result<Value, ContentError> {
        if selection.pin.is_none() {
            return Err(Failure::Invalid.into());
        }
        let (_, draft) = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.extract_draft(selection),
        )
        .await
        .map_err(|_| ContentError::Limited)??;
        let result = self.analysis_submit(draft, preview, nonce, wait).await?;
        Ok(
            json!({"version":"kan-extraction-job/1","id":result["job"]["id"],"state":result["state"],"report":{"tool":"kan_v2_report","id":result["job"]["id"]},"promotion":"not-performed"}),
        )
    }
    // A report handle is a locator only: rebind EVERY source under current
    // access on every use, exactly as the report view does, without an Engine.
    async fn direct_report_inputs(
        &self,
        draft: &analysis::Draft,
        id: &str,
    ) -> Result<Vec<Value>, ContentError> {
        let mut inputs = Vec::new();
        for (n, cite) in draft.cites.iter().enumerate() {
            let (_, source) = self
                .selected(&cite.source)?
                .rebind_citation(&cite.selection)
                .await?;
            let availability = match &source {
                crate::evidence_reader::proof::Source::Available { .. } => "available",
                crate::evidence_reader::proof::Source::Missing { .. } => "missing",
                crate::evidence_reader::proof::Source::Corrupt { .. } => "corrupt",
                crate::evidence_reader::proof::Source::KeyUnavailable { .. } => "key-unavailable",
                crate::evidence_reader::proof::Source::Erased { .. } => "erased",
            };
            let record = match source {
                crate::evidence_reader::proof::Source::Available { record, .. } => record,
                crate::evidence_reader::proof::Source::Erased { .. } => {
                    return Err(Failure::AccessLimited.into())
                }
                crate::evidence_reader::proof::Source::Missing { record }
                | crate::evidence_reader::proof::Source::Corrupt { record }
                | crate::evidence_reader::proof::Source::KeyUnavailable { record, .. } => record,
            };
            let reference = self.occurrence_reference(
                &cite.source,
                serde_json::to_value(record).map_err(|_| Failure::Corrupt)?,
            )?;
            inputs.push(json!({"input":n,"source":cite.source,"uri":reference["uri"],"availability":availability,"reference_request":{"report":{"id":id,"input":n}}}));
        }
        Ok(inputs)
    }
    pub(super) async fn report_dependency_access(
        &self,
        draft: &analysis::Draft,
        id: &str,
    ) -> Result<Vec<Value>, ContentError> {
        let mut pending = vec![(id.to_owned(), draft.clone())];
        let mut seen = std::collections::BTreeSet::new();
        let mut root = None;
        while let Some((key, draft)) = pending.pop() {
            if !seen.insert(key.clone()) {
                continue;
            }
            if seen.len() > 64 || draft.derived_from.len() > 8 {
                return Err(ContentError::Limited);
            }
            let inputs = self.direct_report_inputs(&draft, &key).await?;
            if key == id {
                root = Some(inputs);
            }
            for parent in &draft.derived_from {
                if parent.len() != 64 || crate::evidence_service::unhex(parent, 32).is_err() {
                    return Err(Failure::Corrupt.into());
                }
                let job = self
                    .workspace()?
                    .get("analysis-job", parent)?
                    .ok_or(Failure::AccessLimited)?;
                let result = self
                    .workspace()?
                    .get("analysis-result", parent)?
                    .ok_or(Failure::AccessLimited)?;
                if result["state"] != "succeeded" {
                    return Err(Failure::AccessLimited.into());
                }
                pending.push((
                    parent.clone(),
                    serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?,
                ));
            }
        }
        root.ok_or(Failure::Corrupt.into())
    }
    async fn report_inputs(
        &self,
        draft: &analysis::Draft,
        id: &str,
    ) -> Result<Vec<Value>, ContentError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.report_dependency_access(draft, id),
        )
        .await
        .map_err(|_| ContentError::Limited)?
    }
    pub(super) async fn report_input(
        &self,
        id: String,
        input: usize,
    ) -> Result<Value, ContentError> {
        if id.len() != 64 || crate::evidence_service::unhex(&id, 32).is_err() || input >= 8 {
            return Err(Failure::Invalid.into());
        }
        let job = self
            .workspace()?
            .get("analysis-job", &id)?
            .ok_or(Failure::AccessLimited)?;
        let draft: analysis::Draft =
            serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?;
        let inputs = self.report_inputs(&draft, &id).await?;
        let mut value = inputs.get(input).cloned().ok_or(Failure::Invalid)?;
        if draft.decode {
            let first = draft.cites.first().ok_or(Failure::Corrupt)?;
            let original_pin = serde_json::to_vec(&first.pin).map_err(|_| Failure::Corrupt)?;
            if draft.cites.len() > 8
                || draft.cites.iter().any(|c| {
                    c.source != first.source
                        || serde_json::to_vec(&c.pin).ok().as_ref() != Some(&original_pin)
                })
            {
                return Err(Failure::Invalid.into());
            }
            let tokens = draft
                .cites
                .iter()
                .map(|c| c.selection.clone())
                .collect::<Vec<_>>();
            let (pin, sources) = self
                .selected(&first.source)?
                .rebind_citations(&tokens)
                .await?;
            if sources.iter().any(|source| {
                matches!(source, crate::evidence_reader::proof::Source::Erased { .. })
            }) {
                return Err(Failure::AccessLimited.into());
            }
            let selections = sources
                .into_iter()
                .map(|source| {
                    use crate::evidence_reader::proof::Source;
                    let record = match source {
                        Source::Available { record, .. }
                        | Source::Missing { record }
                        | Source::Corrupt { record }
                        | Source::KeyUnavailable { record, .. }
                        | Source::Erased { record } => record,
                    };
                    record.selection
                })
                .collect::<Vec<_>>();
            value["content_request"] = json!({"action":"proof-content","source":first.source,"pin":pin,"selections":selections,"format":"anthropic-messages-auto"});
            value["report_selection"] = json!({"id":id,"input":input,"inputs_count":draft.cites.len(),"coverage":"Reconstruct only the frozen report manifest. Show enclosing items whose text or tool input intersects the focused input; their exact citations may cross input boundaries. States remain explicit. Not complete capture."});
        }
        Ok(value)
    }
    pub(super) async fn report(
        &self,
        id: String,
        cursor: Option<Value>,
    ) -> Result<Value, ContentError> {
        if id.len() != 64 || crate::evidence_service::unhex(&id, 32).is_err() {
            return Err(Failure::Invalid.into());
        }
        let workspace = self.workspace()?;
        let job = workspace
            .get("analysis-job", &id)?
            .ok_or(Failure::AccessLimited)?;
        let draft: analysis::Draft =
            serde_json::from_value(job["draft"].clone()).map_err(|_| Failure::Corrupt)?;
        let inputs = self.report_inputs(&draft, &id).await?;
        let output = workspace.get("analysis-result", &id)?;
        let mut blocks = Vec::new();
        if let Some(result) = &output {
            if result["state"] == "succeeded" && result["consolidation"].is_object() {
                let saved = workspace
                    .get("analysis-input", &id)?
                    .ok_or(Failure::Corrupt)?;
                let units = saved["projection"][0]["units"]
                    .as_array()
                    .ok_or(Failure::Corrupt)?;
                for (n, candidate) in result["consolidation"]["candidates"]
                    .as_array()
                    .ok_or(Failure::Corrupt)?
                    .iter()
                    .enumerate()
                {
                    let mut witnesses = Vec::new();
                    for key in candidate["evidence"].as_array().ok_or(Failure::Corrupt)? {
                        let key = key.as_str().ok_or(Failure::Corrupt)?;
                        let unit = units
                            .iter()
                            .find(|u| u["id"] == key)
                            .ok_or(Failure::Corrupt)?;
                        let excerpt = Excerpt::from_unit(key).ok_or(Failure::Corrupt)?;
                        let input = unit["citations"][0]["input"]
                            .as_str()
                            .and_then(|s| s.parse::<usize>().ok())
                            .ok_or(Failure::Corrupt)?;
                        if input >= draft.cites.len() {
                            return Err(Failure::Corrupt.into());
                        }
                        witnesses.push(json!({"unit":key,"reference_request":{"report":{"id":id,"input":input,"excerpt":excerpt}},"source_ranges":unit["citations"],"coarse":unit["coarse"]}));
                    }
                    for (index, text) in
                        fragments(candidate["text"].as_str().ok_or(Failure::Corrupt)?)
                            .into_iter()
                            .enumerate()
                    {
                        blocks.push(json!({"block":n,"fragment":index,"text":text,"kind":candidate["kind"],"basis":candidate["basis"],"stance":candidate["stance"],"speaker":candidate["speaker"],"subjects":candidate["subjects"],"relation":candidate["relation"],"uncertainty":candidate["uncertainty"],"witnesses":witnesses}));
                    }
                }
                for (n, text) in result["consolidation"]["limitations"]
                    .as_array()
                    .ok_or(Failure::Corrupt)?
                    .iter()
                    .enumerate()
                {
                    for (index, text) in fragments(text.as_str().ok_or(Failure::Corrupt)?)
                        .into_iter()
                        .enumerate()
                    {
                        blocks.push(json!({"block":format!("limitation/{n}"),"fragment":index,"kind":"limitation","text":text}));
                    }
                }
            } else if let Some(content) = result["parsed"]["content"].as_array() {
                for (n, part) in content.iter().enumerate() {
                    if let Some(text) = part["text"].as_str() {
                        for (index, fragment) in fragments(text).into_iter().enumerate() {
                            blocks.push(json!({"block":n,"fragment":index,"text":fragment}));
                        }
                    } else {
                        blocks.push(json!({"block":n,"state":"nontext model output; inspect advanced job lineage"}));
                    }
                }
            }
        }
        if blocks.is_empty() {
            blocks.push(json!({"state":if output.is_some() {"No readable model text; inspect retained job result and failure state."} else {"No result yet; pending or interrupted. Report reading never retries a provider call."}}));
        }
        let mut recipe = job["preview"]["recipe"].clone();
        if let Some(map) = recipe.as_object_mut() {
            map.remove("instructions");
            map.remove("questions");
        }
        let value = json!({"version":"kan-derived-report/1","id":id,"recipe":recipe,"worker":job["preview"]["worker"],"requested_model":job["preview"]["model"],"returned_model":output.as_ref().map(|o|o["parsed"]["model"].clone()),"state":output.as_ref().map_or(json!("pending-or-interrupted; inspect job status"),|o|o["state"].clone()),"blocks":blocks,"inputs":inputs,"usage":output.as_ref().map(|o|o["parsed"]["usage"].clone()),"usage_state":if output.as_ref().is_some_and(|o|!o["parsed"]["usage"].is_null()) {"provider-reported; not a billing receipt"} else {"unavailable"},"coverage":"Only the exact selected input manifest. Model claims and citations need review; this is not complete capture or an accepted decision.","promotion":"not-performed; explicit authored operation required"});
        report_page(value, cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_pages_preserve_all_eight_large_references_and_unicode_without_repeating_header() {
        let inputs: Vec<Value> = (0..8).map(|n| json!({"input":n,"source":"source","uri":format!("kan://{}-{}",n,"a".repeat(2200)),"reference_request":{"report":{"id":"b".repeat(64),"input":n}},"availability":if n==6 {"key-unavailable"}else{"available"}})).collect();
        let text = "é🙂 bounded report ".repeat(1000);
        let blocks: Vec<Value> = fragments(&text)
            .into_iter()
            .enumerate()
            .map(|(n, t)| json!({"block":0,"fragment":n,"text":t}))
            .collect();
        let full = json!({"id":"a".repeat(64),"recipe":{"instructions":"x".repeat(1200)},"inputs":inputs,"blocks":blocks,"state":"succeeded"});
        let original = full.clone();
        assert!(serde_json::to_vec(&full["inputs"]).unwrap().len() > 12 * 1024);
        let first = report_page(full.clone(), None).unwrap();
        let next = first["next"].clone();
        assert!(!next.is_null());
        let mut cursor = None;
        let mut seen = Vec::new();
        let mut joined = String::new();
        let mut pages = 0;
        loop {
            let page = report_page(full.clone(), cursor).unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() <= 12 * 1024);
            assert_eq!(page["inputs_count"], 8);
            seen.extend(page["inputs"].as_array().unwrap().iter().cloned());
            for block in page["blocks"].as_array().unwrap() {
                joined.push_str(block["text"].as_str().unwrap());
            }
            pages += 1;
            assert!(pages < 100);
            if page["next"].is_null() {
                break;
            }
            cursor = Some(page["next"].clone());
        }
        assert_eq!(seen, inputs);
        assert_eq!(joined, text);
        assert!(pages > 1);
        assert_eq!(full, original);
        let mut changed = full.clone();
        changed["inputs"][6]["availability"] = json!("available");
        assert!(matches!(
            report_page(changed, Some(next.clone())),
            Err(ContentError::Read(Failure::Invalid))
        ));
        let mut changed = full.clone();
        changed["id"] = json!("b".repeat(64));
        assert!(matches!(
            report_page(changed, Some(next)),
            Err(ContentError::Read(Failure::Invalid))
        ));
        let mut oversized = full;
        oversized["inputs"][0]["uri"] = json!("x".repeat(20000));
        assert!(matches!(
            report_page(oversized, None),
            Err(ContentError::Limited)
        ));
    }
}
