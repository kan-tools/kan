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
    #[serde(default)]
    #[schemars(range(min = 0, max = 9007199254740991.0))]
    pub from: u64,
    #[serde(default)]
    #[schemars(range(min = 0, max = 9007199254740991.0))]
    pub through: u64,
    pub recipe: String,
    #[schemars(with = "Option<std::collections::BTreeMap<String,Value>>")]
    pub pin: Option<Pin>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized: Option<analysis::Finalized>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<analysis::StatementTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<analysis::ProjectSelection>,
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
// Retain each exact question/rubric and its complete typed answer. In particular,
// never reduce a distribution to its winning label or interpret it as acceptance.
// JSON text fragments use the same bounded report rows as generative text, so a
// large rubric/distribution cannot become an unpaged repeated header.
fn decision_blocks(request: &Value, response: &Value) -> Result<Vec<Value>, Failure> {
    if !analysis::Adapter::TypesafeSystemOne.accepts(request, response) {
        return Err(Failure::Corrupt);
    }
    let mut blocks = Vec::new();
    for (n, (id, question)) in request["questions"]
        .as_object()
        .ok_or(Failure::Corrupt)?
        .iter()
        .enumerate()
    {
        let text = serde_json::to_string_pretty(
            &json!({"question":question,"answer":response["answers"][id]}),
        )
        .map_err(|_| Failure::Corrupt)?
            + "\n";
        for (index, text) in fragments(&text).into_iter().enumerate() {
            blocks.push(json!({"block":n,"fragment":index,"kind":"decision-assessment","question_id":id,"text":text}));
        }
    }
    Ok(blocks)
}
// Frozen authored input/context is ordinary report evidence too. Model text
// stays first; large signed records and identity witnesses paginate as bounded
// JSON text fragments, rather than requiring advanced/raw job inspection.
fn project_blocks(manifest: &Value) -> Result<Vec<Value>, Failure> {
    let mut blocks = Vec::new();
    if manifest["evaluation"].is_object() {
        let text =
            serde_json::to_string_pretty(&manifest["evaluation"]).map_err(|_| Failure::Corrupt)?;
        for (fragment, text) in fragments(&text).into_iter().enumerate() {
            blocks.push(json!({"block":"project/evaluation","kind":"authored-evaluation","fragment":fragment,"text":text}));
        }
    }
    for (field, kind) in [
        ("classes", "authored-context"),
        ("claims", "authored-input"),
    ] {
        for (n, value) in manifest[field]
            .as_array()
            .ok_or(Failure::Corrupt)?
            .iter()
            .enumerate()
        {
            let text = serde_json::to_string_pretty(value).map_err(|_| Failure::Corrupt)?;
            for (fragment, text) in fragments(&text).into_iter().enumerate() {
                blocks.push(json!({"block":format!("project/{field}/{n}"),"kind":kind,"fragment":fragment,"text":text}));
            }
        }
    }
    Ok(blocks)
}
// Input references are bounded rows too, never an unbounded repeated header.
fn report_page(mut value: Value, cursor: Option<Value>) -> Result<Value, ContentError> {
    let query = json!({"id": value["id"]});
    value["evaluation"] = json!({"version":"kan-report-evaluation/1","id":value["id"],
        "normalizer":"frozen-retained-report/1","authority":"This immutable report interpretation, not authored acceptance. References retain this origin; decoded pages also identify their current authenticated read view."});
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
            if !draft.cites.iter().any(|c| c.source == source)
                && draft.project.as_ref().is_none_or(|p| p.source != source)
            {
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
                rows.push(json!({"type":"derived-state","report":id,"origin_evaluation":{"id":id,"version":"kan-report-evaluation/1"},"state":"No validated structured consolidation; inspect the retained report explicitly."}));
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
                    "origin_evaluation":{"id":id,"version":"kan-report-evaluation/1"},
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
        if selection
            .project
            .as_ref()
            .is_some_and(|p| p.source != selection.source)
        {
            return Err(Failure::Invalid.into());
        }
        if selection.from == 0 && selection.through == 0 && selection.project.is_some() {
            if selection.pin.is_some() {
                return Err(Failure::Invalid.into());
            }
            return Ok((
                selection.clone(),
                analysis::Draft {
                    recipe: selection.recipe,
                    cites: Vec::new(),
                    retry_of: None,
                    trigger_annotation: None,
                    decode: true,
                    derived_from: selection.derived_from,
                    finalized: selection.finalized,
                    assessment: selection.assessment,
                    project: selection.project,
                },
            ));
        }
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
                assessment: selection.assessment,
                project: selection.project,
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
        // Capture intervals require an explicit proof pin. Authored-only
        // selections instead bind their complete claim frontier in the checked
        // preview digest; they deliberately have no capture pin to supply.
        let authored_only =
            selection.project.is_some() && selection.from == 0 && selection.through == 0;
        if selection.pin.is_none() && !authored_only {
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
        self.report_dependency_graph(draft, id)
            .await
            .map(|(inputs, _)| inputs)
    }
    pub(super) async fn report_dependency_graph(
        &self,
        draft: &analysis::Draft,
        id: &str,
    ) -> Result<(Vec<Value>, Vec<(String, analysis::Draft)>), ContentError> {
        let mut pending = vec![(id.to_owned(), draft.clone())];
        let mut seen = std::collections::BTreeSet::new();
        let mut root = None;
        let mut graph = Vec::new();
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
            graph.push((key.clone(), draft.clone()));
            let mut parents = draft.derived_from.clone();
            if draft.project.is_some() {
                let saved = self
                    .workspace()?
                    .get("analysis-input", &key)?
                    .ok_or(Failure::Corrupt)?;
                parents.extend(self.check_project_manifest(&saved["project"]).await?);
            }
            for parent in &parents {
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
        Ok((root.ok_or(Failure::Corrupt)?, graph))
    }
    pub(super) async fn report_inputs(
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
            value["report_selection"] = json!({"id":id,"evaluation":{"id":id,"version":"kan-report-evaluation/1"},"input":input,"inputs_count":draft.cites.len(),"coverage":"Reconstruct only the frozen report manifest. Show enclosing items whose text or tool input intersects the focused input; their exact citations may cross input boundaries. States remain explicit. Not complete capture."});
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
                        if key.starts_with("prior:") {
                            witnesses.push(json!({"unit":key,"report_request":unit["report_request"],"candidate":unit["candidate"],"origin_units":unit["origin_units"],
                                "authority":"Prior model interpretation; follow parent report for original frozen source witnesses. No direct occurrence range is invented."}));
                            continue;
                        }
                        if key.starts_with("claim:") {
                            witnesses.push(json!({"unit":key,"recall_request":unit["recall_request"],"origin_evaluation":{"id":saved["project"]["evaluation"]["id"],"version":saved["project"]["evaluation"]["definition"]["version"]},"live_at_selection":unit["live_at_selection"],"claim_cid":key.strip_prefix("claim:").ok_or(Failure::Corrupt)?,"authorship":unit["author"]}));
                            continue;
                        }
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
                if result["consolidation"]["contract"].is_object() {
                    let text = serde_json::to_string_pretty(&result["consolidation"]["contract"])
                        .map_err(|_| Failure::Corrupt)?;
                    for (fragment, text) in fragments(&text).into_iter().enumerate() {
                        blocks.push(json!({"block":"flow-contract","fragment":fragment,"kind":"flow-contract","text":text}));
                    }
                }
            } else if result["state"] == "succeeded" && result["adapter"] == "typesafe-system-one" {
                let saved = workspace
                    .get("analysis-input", &id)?
                    .ok_or(Failure::Corrupt)?;
                blocks = decision_blocks(&saved["request"], &result["parsed"])?;
                if result["statement_assessment"].is_object() {
                    let mut assessment = result["statement_assessment"].clone();
                    let units = saved["projection"][0]["units"]
                        .as_array()
                        .ok_or(Failure::Corrupt)?;
                    for field in ["target", "reason"] {
                        if assessment["witness"][field].is_null() {
                            continue;
                        }
                        let key = assessment["witness"][field]["span"]["unit"]
                            .as_str()
                            .ok_or(Failure::Corrupt)?;
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
                        assessment["witness"][field]["reference_request"] =
                            json!({"report":{"id":id,"input":input,"excerpt":excerpt}});
                    }
                    let text =
                        serde_json::to_string_pretty(&assessment).map_err(|_| Failure::Corrupt)?;
                    for (fragment, text) in fragments(&text).into_iter().enumerate() {
                        blocks.push(json!({"kind":"statement-assessment","block":"statement-assessment","fragment":fragment,"text":text}));
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
        if draft.project.is_some() {
            let saved = workspace
                .get("analysis-input", &id)?
                .ok_or(Failure::Corrupt)?;
            blocks.extend(project_blocks(&saved["project"])?);
        }
        if blocks.is_empty() {
            blocks.push(json!({"state":if output.is_some() {"No readable model text; inspect retained job result and failure state."} else {"No result yet; pending or interrupted. Report reading never retries a provider call."}}));
        }
        let mut recipe = job["preview"]["recipe"].clone();
        if let Some(map) = recipe.as_object_mut() {
            map.remove("instructions");
            map.remove("questions");
        }
        let value = json!({"version":"kan-derived-report/1","id":id,"recipe":recipe,"worker":job["preview"]["worker"],"requested_model":job["preview"]["model"],"returned_model":output.as_ref().map(|o|o["parsed"]["model"].clone()),"state":output.as_ref().map_or(json!("pending-or-interrupted; inspect job status"),|o|o["state"].clone()),"project_evaluation":job["preview"]["project_evaluation"],"blocks":blocks,"inputs":inputs,"usage":output.as_ref().map(|o|o["parsed"]["usage"].clone()),"usage_state":if output.as_ref().is_some_and(|o|!o["parsed"]["usage"].is_null()) {"provider-reported; not a billing receipt"} else {"unavailable"},"authority":"Unpromoted model interpretation. Confidence and probabilities are model outputs, not calibrated truth or authored acceptance.","coverage":"Only the exact selected input manifest. Model claims and citations need review; this is not complete capture or an accepted decision.","promotion":"not-performed; explicit authored operation required"});
        report_page(value, cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_authored_context_and_full_signed_claims_are_normal_bounded_report_fallback() {
        let manifest = json!({"classes":[{"subjects":["p"],"witnesses":[{"claim":"identity-witness"}],"state":"Conflicted"}],
            "claims":[{"cid":"original-claim","rev":"original-order","claim":{"text":"é🙂 original signed assertion ".repeat(1000)},"live_at_selection":false}]});
        let full =
            json!({"id":"d".repeat(64),"inputs":[],"blocks":project_blocks(&manifest).unwrap()});
        let mut cursor = None;
        let mut joined = std::collections::BTreeMap::<String, String>::new();
        let mut pages = 0;
        loop {
            let page = report_page(full.clone(), cursor).unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() <= 12 * 1024);
            for row in page["blocks"].as_array().unwrap() {
                joined
                    .entry(row["block"].as_str().unwrap().to_owned())
                    .or_default()
                    .push_str(row["text"].as_str().unwrap());
            }
            pages += 1;
            assert!(pages < 30);
            if page["next"].is_null() {
                break;
            }
            cursor = Some(page["next"].clone());
        }
        assert!(pages > 1);
        assert_eq!(
            serde_json::from_str::<Value>(&joined["project/classes/0"]).unwrap(),
            manifest["classes"][0]
        );
        assert_eq!(
            serde_json::from_str::<Value>(&joined["project/claims/0"]).unwrap(),
            manifest["claims"][0]
        );
    }
    #[test]
    fn decision_reports_preserve_exact_rubrics_and_distributions_in_bounded_pages() {
        let request = json!({"questions":{
            "stance":{"type":"choice","instructions":"Classify only observed é🙂 statements. ".repeat(500),"criteria":{"accepted":"Explicitly adopted","unknown":"Unclear"}},
            "support":{"type":"score","instructions":"How explicit is the support?","criteria":["Absent","Reason recorded"]},
            "decision":{"type":"noul","instructions":"Is an adoption recorded?"}
        }});
        let response = json!({"model":"synthetic-local-worker","answers":{
            "stance":{"type":"choice","choice":"unknown","confidence":0.2,"probabilities":{"accepted":0.49,"unknown":0.51}},
            "support":{"type":"score","score":0.75,"confidence":0.3,"probabilities":{"0":0.25,"1":0.75}},
            "decision":{"type":"noul","noul":0.65}
        }});
        let blocks = decision_blocks(&request, &response).unwrap();
        let full = json!({"id":"a".repeat(64),"inputs":[],"blocks":blocks});
        let mut joined = std::collections::BTreeMap::<String, String>::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = report_page(full.clone(), cursor).unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() <= 12 * 1024);
            for block in page["blocks"].as_array().unwrap() {
                assert_eq!(block["kind"], "decision-assessment");
                joined
                    .entry(block["question_id"].as_str().unwrap().into())
                    .or_default()
                    .push_str(block["text"].as_str().unwrap());
            }
            pages += 1;
            assert!(pages < 100);
            if page["next"].is_null() {
                break;
            }
            cursor = Some(page["next"].clone());
        }
        assert!(pages > 1);
        assert_eq!(joined.len(), 3);
        for (id, text) in joined {
            let exact: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(exact["question"], request["questions"][&id]);
            assert_eq!(exact["answer"], response["answers"][&id]);
        }
        let mut invalid = response;
        invalid["answers"]["stance"]["probabilities"]["unknown"] = json!(0.9);
        assert!(matches!(
            decision_blocks(&request, &invalid),
            Err(Failure::Corrupt)
        ));
    }
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
        let mut cursor = None;
        let mut prefix = String::new();
        let mut pages = 0;
        loop {
            match report_page(oversized.clone(), cursor) {
                Ok(page) => {
                    // Text precedes manifests. An oversized later reference
                    // must refuse when reached, never be skipped or imply a
                    // complete selection after a successful text prefix.
                    assert!(serde_json::to_vec(&page).unwrap().len() <= 12 * 1024);
                    assert!(page["inputs"].as_array().unwrap().is_empty());
                    assert!(!page["blocks"].as_array().unwrap().is_empty());
                    for block in page["blocks"].as_array().unwrap() {
                        prefix.push_str(block["text"].as_str().unwrap());
                    }
                    assert!(!page["next"].is_null());
                    cursor = Some(page["next"].clone());
                    pages += 1;
                    assert!(pages < 100);
                }
                Err(ContentError::Limited) => break,
                _ => panic!("oversized report reference must refuse explicitly"),
            }
        }
        assert!(pages > 0);
        assert_eq!(prefix, text);
    }
}
