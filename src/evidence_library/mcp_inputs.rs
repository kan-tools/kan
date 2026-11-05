//! Advertised MCP shapes and value-free request diagnostics. Signed reader
//! objects remain opaque inputs whose real validation belongs to the Reader.
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Empty {
    /// Copy next from this tool's previous page; omit for the first page.
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Advanced {
    /// Exact documented shared API request. Prefer typed tools for common reads.
    pub query: Value,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Discover {
    /// Exact proof source id from kan_v2_catalog.
    pub source: String,
    /// Complete pin object from catalog or an earlier discovery response. Omit
    /// for a fresh snapshot; a continuation cursor requires its original pin.
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub pin: Option<Value>,
    /// Opaque next token from discovery; never invent or edit token fields.
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
    /// Requested occurrences, from 1 to 20 (default 3). The serialized output
    /// budget may return fewer; follow the returned signed next cursor.
    #[serde(default = "three")]
    #[schemars(range(min = 1, max = 20))]
    pub limit: usize,
}
fn three() -> usize {
    3
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ContentKind {
    Selected,
    Attempt,
}
fn selected() -> ContentKind {
    ContentKind::Selected
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Content {
    pub source: String,
    /// Complete signed pin returned by catalog/discovery, copied verbatim.
    #[schemars(with = "std::collections::BTreeMap<String, Value>")]
    pub pin: Value,
    /// Signed record.selection objects from discovery. Preserve their bindings.
    #[schemars(with = "Vec<std::collections::BTreeMap<String, Value>>")]
    pub selections: Vec<Value>,
    /// Selected is the ordinary bounded multi-attempt view. Attempt allows the
    /// larger budget for ONE writer/observer/attempt identity only; group by the
    /// discovery descriptions first. Neither mode claims complete capture.
    #[serde(default = "selected")]
    pub kind: ContentKind,
    /// Opaque decoded-view next cursor; copy verbatim with identical arguments.
    /// This is presentation position, not source-byte selection or a grant.
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionIdentity {
    pub writer: String,
    /// collector or gateway; this is an observer claim, not speaker identity.
    pub observer: String,
    /// kan-header or claude-code-header.
    pub scheme: String,
    pub session: String,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub source: String,
    #[schemars(with = "std::collections::BTreeMap<String, Value>")]
    pub pin: Value,
    #[schemars(with = "Vec<std::collections::BTreeMap<String, Value>>")]
    pub selections: Vec<Value>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub identity: SessionIdentity,
    pub attempts: Vec<Selection>,
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ReportReference {
    /// Existing derived report id. Bundled reports reconstruct their bounded
    /// frozen manifest as context, not live search or a provider request.
    #[schemars(length(min = 64, max = 64))]
    pub id: String,
    /// Stable input number from that report, zero-based. Show complete items
    /// whose text or tool arguments intersect this input, with exact citations.
    #[schemars(range(min = 0, max = 7))]
    pub input: usize,
    /// Optional decoded item locator returned with a structured statement.
    /// This opens its exact item inside the same frozen manifest.
    pub excerpt: Option<crate::evidence_library::proof::reports::Excerpt>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    /// Exact kan+capture://v1/occurrence URI returned by Kan. It identifies
    /// evidence, not a grant; resolution checks current access again.
    #[serde(default)]
    pub uri: String,
    /// Prefer the exact small reference_request returned by a report input.
    /// Use exactly one of uri or report; current access is rechecked.
    pub report: Option<ReportReference>,
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
}
impl Reference {
    pub fn validate_selector(&self) -> Result<(), Value> {
        match (&self.report, self.uri.is_empty()) {
            (Some(report), true) => {
                if report.id.len() != 64 || !report.id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid("arguments.report.id", "64 hexadecimal characters"));
                }
                if report.input >= 8 {
                    return Err(invalid(
                        "arguments.report.input",
                        "an input number from 0 to 7",
                    ));
                }
                if report.excerpt.as_ref().is_some_and(|e| !e.valid()) {
                    return Err(invalid(
                        "arguments.report.excerpt",
                        "a returned bounded group/direction/item/part locator",
                    ));
                }
                Ok(())
            }
            (None, false) => Ok(()),
            _ => Err(invalid(
                "arguments",
                "exactly one uri or report input reference",
            )),
        }
    }
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Help {
    /// Omit for all common read tools; otherwise choose an advertised name.
    pub tool: Option<Tool>,
    #[schemars(with = "Option<std::collections::BTreeMap<String, Value>>")]
    pub cursor: Option<Value>,
}
#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub(super) enum Tool {
    #[serde(rename = "kan_v2_record")]
    Record,
    #[serde(rename = "kan_v2_recall")]
    Recall,
    #[serde(rename = "kan_v2_extract_plan")]
    ExtractPlan,
    #[serde(rename = "kan_v2_extract")]
    Extract,
    #[serde(rename = "kan_v2_report")]
    Report,
    #[serde(rename = "kan_v2_catalog")]
    Catalog,
    #[serde(rename = "kan_v2_discover")]
    Discover,
    #[serde(rename = "kan_v2_content")]
    Content,
    #[serde(rename = "kan_v2_session")]
    Session,
    #[serde(rename = "kan_v2_reference")]
    Reference,
}
impl Tool {
    pub fn name(self) -> &'static str {
        match self {
            Self::Record => "kan_v2_record",
            Self::Recall => "kan_v2_recall",
            Self::ExtractPlan => "kan_v2_extract_plan",
            Self::Extract => "kan_v2_extract",
            Self::Report => "kan_v2_report",
            Self::Catalog => "kan_v2_catalog",
            Self::Discover => "kan_v2_discover",
            Self::Content => "kan_v2_content",
            Self::Session => "kan_v2_session",
            Self::Reference => "kan_v2_reference",
        }
    }
    pub fn schema(self) -> Value {
        match self {
            Self::Record => schema::<Record>(),
            Self::Recall => schema::<Recall>(),
            Self::ExtractPlan => schema::<ExtractPlan>(),
            Self::Extract => schema::<Extract>(),
            Self::Report => schema::<Report>(),
            Self::Catalog => schema::<Empty>(),
            Self::Discover => schema::<Discover>(),
            Self::Content => schema::<Content>(),
            Self::Session => schema::<Session>(),
            Self::Reference => schema::<Reference>(),
        }
    }
    pub fn example(self) -> Value {
        match self {
            Self::Record => {
                json!({"draft":{"source":"copy scope.id","verb":"decide","subject":"project/demo","text":"The explicitly authored decision."}})
            }
            Self::Recall => {
                json!({"source":"copy scope.id","verb":"show","subject":"project/demo"})
            }
            Self::ExtractPlan => {
                json!({"selection":{"source":"copy scope.id","from":1,"through":5,"recipe":"documentation-summary"}})
            }
            Self::Extract => {
                json!({"selection":{"source":"copy plan.selection.source","from":1,"through":5,"recipe":"documentation-summary","pin":{"request":"copy complete plan.selection.pin","reply":{}}},"preview":"copy plan.digest","nonce":"copy plan.nonce"})
            }
            Self::Report => json!({"id":"copy job.id"}),
            Self::Catalog => json!({}),
            Self::Discover => json!({"source":"copy scope.id from catalog","limit":3}),
            Self::Content => {
                json!({"source":"copy scope.id","pin":{"request":"copy complete returned pin, not this illustrative object","reply":{}},"selections":[{"body":{},"signature":"copy complete record.selection"}],"kind":"selected"})
            }
            Self::Session => {
                json!({"identity":{"writer":"copy verified writer","observer":"collector","scheme":"claude-code-header","session":"copy claimed session"},"attempts":[{"source":"copy scope.id","pin":{"request":"copy complete returned pin","reply":{}},"selections":[{"body":{},"signature":"copy complete record.selection"}]}]})
            }
            Self::Reference => json!({"report":{"id":"copy report.id","input":0}}),
        }
    }
}
pub(super) fn schema<T: JsonSchema>() -> Value {
    // JsonSchema is a static schema, never supplied evidence or configuration.
    serde_json::to_value(schemars::schema_for!(T)).expect("static JSON schema")
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub draft: super::RecordDraft,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Recall {
    pub source: String,
    /// show, status, issues or context. Defaults to show.
    #[serde(default = "show")]
    pub verb: String,
    pub subject: Option<String>,
    #[serde(default)]
    pub trust: Vec<String>,
    #[serde(default = "budget")]
    pub budget: usize,
    /// Retained report ids to append as labelled derived suggestions, after all
    /// authored rows. No inference occurs; each source is authorized again.
    #[serde(default)]
    pub derived: Vec<String>,
    #[serde(default = "derived_budget")]
    pub derived_budget: usize,
    #[schemars(with = "Option<std::collections::BTreeMap<String,Value>>")]
    pub cursor: Option<Value>,
}
fn show() -> String {
    "show".into()
}
fn budget() -> usize {
    1024
}
fn derived_budget() -> usize {
    256
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ExtractPlan {
    pub selection: super::ExtractionSelection,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Extract {
    pub selection: super::ExtractionSelection,
    pub preview: String,
    pub nonce: String,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Report {
    pub id: String,
    #[schemars(with = "Option<std::collections::BTreeMap<String,Value>>")]
    pub cursor: Option<Value>,
}
/// The parameter wrapper advertises the typed shape but defers deserialization
/// to our value-free error handler. Framework serde errors may quote bad values.
// Delegate the root schema directly. A derived transparent `with` wrapper can
// emit only a root $ref, which rmcp rejects: inputSchema must itself be an object.
// Deserialization still accepts Value so only our value-free parser reports errors.
macro_rules! input {
    ($wrapper:ident, $shape:ty) => {
        #[derive(Deserialize, Serialize)]
        #[serde(transparent)]
        pub(super) struct $wrapper(pub Value);
        impl JsonSchema for $wrapper {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                <$shape>::schema_name()
            }
            fn schema_id() -> std::borrow::Cow<'static, str> {
                <$shape>::schema_id()
            }
            fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                <$shape>::json_schema(generator)
            }
        }
    };
}
input!(EmptyInput, Empty);
input!(DiscoverInput, Discover);
input!(ContentInput, Content);
input!(SessionInput, Session);
input!(ReferenceInput, Reference);
input!(HelpInput, Help);
input!(AdvancedInput, Advanced);
input!(RecordInput, Record);
input!(RecallInput, Recall);
input!(ExtractPlanInput, ExtractPlan);
input!(ExtractInput, Extract);
input!(ReportInput, Report);

pub(super) fn parse<T: DeserializeOwned + JsonSchema>(raw: Value) -> Result<T, Value> {
    serde_json::from_value(raw.clone()).map_err(|_| {
        let schema = schema::<T>();
        let (field, expected) = mismatch(&schema, &schema, &raw, "arguments", 0)
            .unwrap_or_else(|| ("arguments".into(), "the advertised input schema".into()));
        invalid(&field, &expected)
    })
}
pub(super) fn invalid(field: &str, expected: &str) -> Value {
    json!({"error":"invalid-request","field":field,"expected":expected,
        "help":"Use kan_v2_help for schemas/examples. Copy signed pins/selections verbatim from returned results.",
        "coverage":"No successful result; do not interpret this as empty evidence."})
}
// Paths are built exclusively from static schema property names. Unknown user
// field names, values and serde error strings are deliberately never returned.
fn mismatch(
    root: &Value,
    shape: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Option<(String, String)> {
    if depth > 12 {
        return None;
    }
    if let Some(reference) = shape["$ref"].as_str().and_then(|s| s.strip_prefix('#')) {
        return mismatch(root, root.pointer(reference)?, value, path, depth + 1);
    }
    if let Some(choices) = shape["anyOf"].as_array() {
        let problems: Vec<_> = choices
            .iter()
            .map(|s| mismatch(root, s, value, path, depth + 1))
            .collect();
        return if problems.iter().any(Option::is_none) {
            None
        } else {
            Some((
                path.into(),
                "one of the advertised alternative shapes".into(),
            ))
        };
    }
    if let Some(kind) = shape["type"].as_str() {
        let valid = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true,
        };
        if !valid {
            return Some((path.into(), format!("type {kind}")));
        }
    }
    if let Some(required) = shape["required"].as_array() {
        for field in required.iter().filter_map(Value::as_str) {
            if value.get(field).is_none() {
                return Some((format!("{path}.{field}"), "required field".into()));
            }
        }
    }
    if let (Some(fields), Some(values)) = (shape["properties"].as_object(), value.as_object()) {
        if shape["additionalProperties"] == false && values.keys().any(|k| !fields.contains_key(k))
        {
            return Some((
                path.into(),
                "only the advertised field names; an unexpected field was supplied".into(),
            ));
        }
        for (field, child) in fields {
            if let Some(v) = values.get(field) {
                if let Some(problem) =
                    mismatch(root, child, v, &format!("{path}.{field}"), depth + 1)
                {
                    return Some(problem);
                }
            }
        }
    }
    if let (Some(items), Some(values)) = (shape.get("items"), value.as_array()) {
        for v in values {
            if let Some(problem) = mismatch(root, items, v, &format!("{path}[]"), depth + 1) {
                return Some(problem);
            }
        }
    }
    if let Some(allowed) = shape["enum"].as_array() {
        if !allowed.contains(value) {
            return Some((path.into(), "one of the advertised enum choices".into()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_reference_selectors_are_exclusive_bounded_and_value_free() {
        let id = "a".repeat(64);
        for raw in [
            json!({"uri":"exact returned URI"}),
            json!({"report":{"id":id,"input":7}}),
        ] {
            assert!(parse::<Reference>(raw).unwrap().validate_selector().is_ok());
        }
        for raw in [
            json!({}),
            json!({"uri":"private-secret","report":{"id":id,"input":0}}),
            json!({"report":{"id":"private-secret","input":0}}),
            json!({"report":{"id":id,"input":8}}),
            json!({"report":{"id":id,"input":0,"private-secret":"private-secret"}}),
        ] {
            let problem = match parse::<Reference>(raw) {
                Ok(args) => args.validate_selector().unwrap_err(),
                Err(problem) => problem,
            };
            assert_eq!(problem["error"], "invalid-request");
            assert!(!problem.to_string().contains("private-secret"));
        }
    }
    #[test]
    fn every_parameter_schema_passes_the_actual_mcp_root_validator() {
        fn check<T: JsonSchema + 'static>() {
            let schema = rmcp::handler::server::common::schema_for_input::<
                rmcp::handler::server::wrapper::Parameters<T>,
            >()
            .expect("advertised MCP input schema must validate at server startup");
            assert_eq!(schema["type"], "object");
        }
        check::<EmptyInput>();
        check::<DiscoverInput>();
        check::<ContentInput>();
        check::<SessionInput>();
        check::<ReferenceInput>();
        check::<HelpInput>();
        check::<AdvancedInput>();
        check::<RecordInput>();
        check::<RecallInput>();
        check::<ExtractPlanInput>();
        check::<ExtractInput>();
        check::<ReportInput>();
    }
    #[test]
    fn invalid_fields_are_actionable_without_echoing_supplied_values() {
        for raw in [
            json!({"source":42}),
            json!({"source":"ok","private-secret-field":"private-secret-value"}),
            json!({"source":"ok","limit":"private-secret-value"}),
        ] {
            let problem = parse::<Discover>(raw).err().expect("bad request");
            assert_eq!(problem["error"], "invalid-request");
            assert!(problem["field"].as_str().unwrap().starts_with("arguments"));
            assert!(!problem.to_string().contains("private-secret"));
        }
        let missing = parse::<Content>(json!({"source":"ok","selections":[]}))
            .err()
            .unwrap();
        assert_eq!(missing["field"], "arguments.pin");
        assert!(parse::<Discover>(json!({"source":"chosen","limit":10})).is_ok());
        for tool in [
            Tool::Catalog,
            Tool::Discover,
            Tool::Content,
            Tool::Session,
            Tool::Reference,
        ] {
            assert_eq!(tool.schema()["type"], "object");
            assert!(tool.example().is_object());
        }
        assert_eq!(
            schema::<DiscoverInput>()["properties"],
            schema::<Discover>()["properties"]
        );
    }
}
