//! Instance-authorized tag scheduling uses the ordinary analysis preview and
//! runner. Trigger failures remain inspectable alongside the retained annotation.
use super::{analysis, knowledge, Readers};
use crate::{evidence_content::ContentError, evidence_service::Failure};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
impl Readers {
    pub(super) fn annotation_analysis_plan(&self, tags: &[String]) -> Value {
        self.analysis
            .as_ref()
            .map_or(json!([]), |engine| engine.trigger_plan(tags))
    }
    pub(super) async fn annotation_triggers(
        &self,
        id: &str,
        retry: bool,
    ) -> Result<Value, ContentError> {
        let record = self
            .workspace()?
            .get("annotation", id)?
            .ok_or(Failure::AccessLimited)?;
        let draft: knowledge::Draft =
            serde_json::from_value(record["draft"].clone()).map_err(|_| Failure::Corrupt)?;
        self.annotation_preview(draft.clone()).await?;
        let mut attempts = Vec::new();
        for n in 0..32 {
            match self
                .workspace()?
                .get("analysis-trigger", &format!("{id}/{n}"))?
            {
                Some(value) => attempts.push(value),
                None => break,
            }
        }
        let plan = record
            .get("analysis_trigger_plan")
            .cloned()
            .unwrap_or(json!([]));
        if draft.withdraws.is_some() {
            if plan != json!([]) {
                return Err(Failure::Invalid.into());
            }
            return Ok(
                json!({"annotation":id,"plan":[],"attempts":[],"state":"withdrawal-does-not-trigger-analysis"}),
            );
        }
        if retry {
            if attempts.len() >= 32 {
                return Err(ContentError::Limited);
            }
            if plan != self.annotation_analysis_plan(&draft.tags) {
                return Err(Failure::Invalid.into());
            }
            let mut outcomes = Vec::new();
            for trigger in plan.as_array().ok_or(Failure::Corrupt)? {
                let recipe = trigger["recipe"]["id"].as_str().ok_or(Failure::Corrupt)?;
                let job = analysis::Draft {
                    recipe: recipe.into(),
                    cites: draft.cites.clone(),
                    retry_of: None,
                    trigger_annotation: Some(id.into()),
                };
                let result = async {
                    let preview = self.analysis_preview(job.clone()).await?;
                    let nonce = crate::evidence_service::hex(&Sha256::digest(
                        serde_json::to_vec(&json!(["annotation-trigger/1", id, trigger]))
                            .map_err(|_| Failure::Invalid)?,
                    ));
                    self.analysis_submit(
                        job,
                        preview["digest"].as_str().ok_or(Failure::Corrupt)?.into(),
                        nonce,
                        false,
                    )
                    .await
                }
                .await;
                outcomes.push(match result {
                    Ok(status)=>json!({"recipe":recipe,"state":"scheduled","job":status["job"]["id"]}),
                    Err(_)=>json!({"recipe":recipe,"state":"not-scheduled","reason":"Input access, availability, queue capacity, configuration or quota prevented scheduling. Inspect configuration and retry explicitly."}),
                });
            }
            let receipt = json!({"annotation":id,"attempt":attempts.len(),"at":crate::evidence_operations::now().to_string(),"outcomes":outcomes});
            self.workspace()?.put(
                "analysis-trigger",
                &format!("{id}/{}", attempts.len()),
                receipt.clone(),
            )?;
            attempts.push(receipt);
        }
        Ok(json!({"annotation":id,"plan":plan,"attempts":attempts}))
    }
    pub(super) async fn schedule_annotation(&self, record: &Value) -> Result<(), ContentError> {
        let plan = record
            .get("analysis_trigger_plan")
            .and_then(Value::as_array);
        if plan.is_none_or(Vec::is_empty) {
            return Ok(());
        }
        let id = record["id"].as_str().ok_or(Failure::Corrupt)?;
        if self
            .workspace()?
            .get("analysis-trigger", &format!("{id}/0"))?
            .is_none()
        {
            self.annotation_triggers(id, true).await?;
        }
        Ok(())
    }
}
