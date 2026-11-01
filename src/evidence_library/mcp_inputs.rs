//! Advertised MCP shapes and value-free request diagnostics. Signed reader
//! objects remain opaque inputs whose real validation belongs to the Reader.
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Empty {}
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
    /// Bounded occurrences to inspect, from 1 to 20 (default 10).
    #[serde(default = "ten")]
    #[schemars(range(min = 1, max = 20))]
    pub limit: usize,
}
fn ten() -> usize {
    10
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
    /// Selected content is the ordinary bounded view. Attempt allows the
    /// existing larger attempt budget; neither mode claims complete capture.
    #[serde(default = "selected")]
    pub kind: ContentKind,
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
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    /// Exact kan+capture://v1/occurrence URI returned by Kan. It identifies
    /// evidence, not a grant; resolution checks current access again.
    pub uri: String,
}
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Help {
    /// Omit for all common read tools; otherwise choose an advertised name.
    pub tool: Option<Tool>,
}
#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub(super) enum Tool {
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
            Self::Catalog => "kan_v2_catalog",
            Self::Discover => "kan_v2_discover",
            Self::Content => "kan_v2_content",
            Self::Session => "kan_v2_session",
            Self::Reference => "kan_v2_reference",
        }
    }
    pub fn schema(self) -> Value {
        match self {
            Self::Catalog => schema::<Empty>(),
            Self::Discover => schema::<Discover>(),
            Self::Content => schema::<Content>(),
            Self::Session => schema::<Session>(),
            Self::Reference => schema::<Reference>(),
        }
    }
    pub fn example(self) -> Value {
        match self {
            Self::Catalog => json!({}),
            Self::Discover => json!({"source":"copy scope.id from catalog","limit":10}),
            Self::Content => {
                json!({"source":"copy scope.id","pin":{"request":"copy complete returned pin, not this illustrative object","reply":{}},"selections":[{"body":{},"signature":"copy complete record.selection"}],"kind":"selected"})
            }
            Self::Session => {
                json!({"identity":{"writer":"copy verified writer","observer":"collector","scheme":"claude-code-header","session":"copy claimed session"},"attempts":[{"source":"copy scope.id","pin":{"request":"copy complete returned pin","reply":{}},"selections":[{"body":{},"signature":"copy complete record.selection"}]}]})
            }
            Self::Reference => json!({"uri":"copy exact returned kan+capture URI"}),
        }
    }
}
pub(super) fn schema<T: JsonSchema>() -> Value {
    // JsonSchema is a static schema, never supplied evidence or configuration.
    serde_json::to_value(schemars::schema_for!(T)).expect("static JSON schema")
}

/// The parameter wrapper advertises the typed shape but defers deserialization
/// to our value-free error handler. Framework serde errors may quote bad values.
// schemars' `with` is a Rust type string, so keep these explicit rather than
// constructing its attribute through macro stringification.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct EmptyInput(#[schemars(with = "Empty")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct DiscoverInput(#[schemars(with = "Discover")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct ContentInput(#[schemars(with = "Content")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct SessionInput(#[schemars(with = "Session")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct ReferenceInput(#[schemars(with = "Reference")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct HelpInput(#[schemars(with = "Help")] pub Value);
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub(super) struct AdvancedInput(#[schemars(with = "Advanced")] pub Value);

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
