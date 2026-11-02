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
impl Readers {
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
            inputs.push(json!({"input":n,"source":cite.source,"uri":reference["uri"],"availability":availability}));
        }
        let output = workspace.get("analysis-result", &id)?;
        let mut blocks = Vec::new();
        if let Some(result) = &output {
            if let Some(content) = result["parsed"]["content"].as_array() {
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
        let value = json!({"version":"kan-derived-report/1","id":id,"recipe":job["preview"]["recipe"],"requested_model":job["preview"]["model"],"returned_model":output.as_ref().map(|o|o["parsed"]["model"].clone()),"state":output.as_ref().map_or(json!("pending-or-interrupted; inspect job status"),|o|o["state"].clone()),"blocks":blocks,"inputs":inputs,"usage":output.as_ref().map(|o|o["parsed"]["usage"].clone()),"usage_state":if output.as_ref().is_some_and(|o|!o["parsed"]["usage"].is_null()) {"provider-reported; not a billing receipt"} else {"unavailable"},"coverage":"Only the exact selected input manifest. Model claims and citations need review; this is not complete capture or an accepted decision.","promotion":"not-performed; explicit authored operation required"});
        crate::evidence_library::mcp::pages::list(value, "blocks", &json!({"id":id}), cursor)
            .map_err(|e| match e {
                crate::evidence_library::mcp::pages::Error::Cursor => Failure::Invalid.into(),
                crate::evidence_library::mcp::pages::Error::Limited => ContentError::Limited,
                _ => Failure::Corrupt.into(),
            })
    }
}
