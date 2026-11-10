//! Statement assessment is an interpretation of exact occurrences, not a
//! truth/acceptance oracle. No witness means no reason-link inference.
use super::{Failure, Recipe};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpan {
    /// Exact visible unit id returned by the decoded content view.
    pub unit: String,
    /// UTF-8 byte offsets in that unit's text, end exclusive.
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatementTarget {
    pub target: EvidenceSpan,
    pub reason: Option<EvidenceSpan>,
}
fn protocol() -> Value {
    serde_json::from_str(include_str!("statement-assessment.json"))
        .expect("static statement protocol")
}
pub(super) fn recipe() -> Recipe {
    Recipe { id: "statement-assessment".into(), revision: "1".into(), purpose: "day-assessment".into(),
        instructions: "Assess only the exact marked target and optional reason in their verbatim source context. A prescription, a reported adoption, current effectiveness and a reason link are separate. Do not infer truth, authorship, acceptance, effectiveness or calibration. Missing reason occurrences are not submitted for reason-link inference. Governing windows are deterministic punctuation/paragraph aids, not a semantic parse; retain the supplied full units and polarity.".into(),
        questions: serde_json::from_value(protocol()["questions"].clone()).expect("static statement questions") }
}
pub(super) fn named(recipe: &Recipe) -> bool {
    recipe.id == "statement-assessment"
}
pub(super) fn canonical(value: &Recipe) -> bool {
    serde_json::to_value(value).ok() == serde_json::to_value(recipe()).ok()
}
// Verbatim boundaries avoid periods in versions/paths. Spans crossing sentence
// boundaries take their union. No trimming or rewriting of the target itself.
fn window(text: &str, start: usize, end: usize) -> (usize, usize) {
    let mut boundaries = vec![0, text.len()];
    let mut prior = None;
    let mut whitespace_newlines = None;
    for (at, c) in text.char_indices() {
        if c.is_whitespace() {
            let n = whitespace_newlines.get_or_insert(0usize);
            if c == '\n' {
                *n += 1;
            }
        } else {
            if let Some(newlines) = whitespace_newlines.take() {
                if (prior.is_some_and(|p| matches!(p, '.' | '!' | '?'))
                    && (c.is_uppercase() || matches!(c, '“' | '"' | '‘')))
                    || newlines >= 2
                {
                    boundaries.push(at);
                }
            }
            prior = Some(c);
        }
    }
    (
        boundaries
            .iter()
            .copied()
            .filter(|b| *b <= start)
            .max()
            .unwrap_or(0),
        boundaries
            .iter()
            .copied()
            .filter(|b| *b >= end)
            .min()
            .unwrap_or(text.len()),
    )
}
fn resolve(span: &EvidenceSpan, units: &[Value]) -> Result<Value, Failure> {
    let unit = units
        .iter()
        .find(|u| u["id"] == span.unit)
        .ok_or(Failure::Invalid)?;
    let text = unit["text"].as_str().ok_or(Failure::Invalid)?;
    if span.unit.len() > 128
        || span.start >= span.end
        || span.end.saturating_sub(span.start) > 4096
        || !text.is_char_boundary(span.start)
        || !text.is_char_boundary(span.end)
    {
        return Err(Failure::Invalid);
    }
    let selected = text
        .get(span.start..span.end)
        .filter(|s| !s.trim().is_empty())
        .ok_or(Failure::Invalid)?;
    let (start, end) = window(text, span.start, span.end);
    Ok(
        json!({"span":span,"text":selected,"source":unit["source"],"citations":unit["citations"],
        "coarse":unit["coarse"],"governing_context":{"start":start,"end":end,"text":&text[start..end],
        "method":"verbatim punctuation/paragraph window; not a semantic parse"}}),
    )
}
pub(super) fn prepare(
    target: &StatementTarget,
    projection: &mut Value,
    recipe: &mut Recipe,
) -> Result<Value, Failure> {
    let units = projection["units"].as_array().ok_or(Failure::Corrupt)?;
    let witness = json!({"version":"kan-statement-witness/1","target":resolve(&target.target,units)?,
        "reason":target.reason.as_ref().map(|s|resolve(s,units)).transpose()?,
        "reason_state":if target.reason.is_some(){"supplied"}else{"not-supplied; reason_link not evaluated"}});
    let selected: Vec<_> = units
        .iter()
        .filter(|u| {
            u["id"] == target.target.unit
                || target.reason.as_ref().is_some_and(|r| u["id"] == r.unit)
        })
        .cloned()
        .collect();
    // Selected full unit text, exact span and context remain together. Refuse
    // an oversized prompt later; never silently truncate its governing context.
    projection["units"] = json!(selected);
    projection["assessment"] = witness.clone();
    projection["selection_policy"] = json!("Only explicitly witnessed units, with their full visible text. Other frozen records remain report input fallback; this is not complete capture.");
    if target.reason.is_none() {
        recipe.questions.remove("reason_link");
    }
    Ok(witness)
}
pub(super) fn mapped(witness: &Value, response: &Value) -> Option<Value> {
    let mut fields = serde_json::Map::new();
    for head in ["prescription", "adoption_assertion", "reason_link"] {
        if head == "reason_link" && witness["reason"].is_null() {
            fields.insert(
                head.into(),
                json!({"state":"not-supplied","assessment":null,"inference_performed":false}),
            );
            continue;
        }
        let category = response["answers"][head]["choice"].as_str()?;
        let mapping = protocol()["mappings"][head][category].as_str()?.to_owned();
        fields.insert(
            head.into(),
            json!({"category":category,"assessment":mapping,"inference_performed":true}),
        );
    }
    Some(
        json!({"version":"kan-statement-assessment/1","fields":fields,"witness":witness,
        "authority":"Unpromoted categorical model interpretation of supplied occurrences; reported adoption is not current effectiveness or authored acceptance. Distributions are not calibrated probabilities."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_unicode_occurrences_and_missing_reason_are_structural_not_model_guesses() {
        let text = "Earlier. Keep café🙂 because it is legible. Later.";
        let units = vec![
            json!({"id":"g0/request/i2/text","text":text,"source":"s","citations":[{"input":"0"}]}),
        ];
        let start = text.find("café").unwrap();
        let end = start + "café🙂".len();
        let target = StatementTarget {
            target: EvidenceSpan {
                unit: "g0/request/i2/text".into(),
                start,
                end,
            },
            reason: None,
        };
        let mut projection = json!({"units":units});
        let mut r = recipe();
        let witness = prepare(&target, &mut projection, &mut r).unwrap();
        assert_eq!(witness["target"]["text"], "café🙂");
        assert_eq!(
            witness["target"]["governing_context"]["text"],
            "Keep café🙂 because it is legible. "
        );
        assert!(!r.questions.contains_key("reason_link"));
        assert_eq!(projection["units"][0]["text"], text);
        for (start, end) in [(end, end), (start + 4, end), (0, text.len() + 1)] {
            let mut bad = target.clone();
            bad.target.start = start;
            bad.target.end = end;
            assert!(prepare(&bad, &mut projection, &mut recipe()).is_err());
        }
        let response = json!({"answers":{"prescription":{"choice":"instruction_or_request"},"adoption_assertion":{"choice":"proposal_or_command_only"},"reason_link":{"choice":"justification_for_target"}}});
        let value = mapped(&witness, &response).unwrap();
        assert_eq!(value["fields"]["prescription"]["assessment"], "yes");
        assert_eq!(value["fields"]["adoption_assertion"]["assessment"], "no");
        assert_eq!(value["fields"]["reason_link"]["inference_performed"], false);
    }
    #[test]
    fn missing_unknown_and_whitespace_witnesses_refuse_before_inference() {
        let units = vec![json!({"id":"g0/request/i0/text","text":"  target"})];
        for span in [
            EvidenceSpan {
                unit: "unknown".into(),
                start: 0,
                end: 1,
            },
            EvidenceSpan {
                unit: "g0/request/i0/text".into(),
                start: 0,
                end: 2,
            },
        ] {
            assert!(resolve(&span, &units).is_err());
        }
        assert!(canonical(&recipe()));
        let mut changed = recipe();
        changed.instructions.push('!');
        assert!(!canonical(&changed));
    }
}
