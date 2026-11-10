//! Stateless, agent-sized presentation over already authenticated shared reads.
//! Cursors bind presentation/query identity; they never grant source access.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(in crate::evidence_library) const LIMIT: usize = 12 * 1024;
const TEXT_CHUNK: usize = 2048;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::evidence_library) enum Error {
    Cursor,
    Limited,
    Corrupt,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: String,
    row: usize,
    offset: usize,
}
fn size(value: &Value) -> Result<usize, Error> {
    serde_json::to_vec(value)
        .map(|v| v.len())
        .map_err(|_| Error::Corrupt)
}
fn digest(value: &Value) -> Result<String, Error> {
    Ok(crate::evidence_service::hex(&Sha256::digest(
        serde_json::to_vec(value).map_err(|_| Error::Corrupt)?,
    )))
}
fn position(cursor: Option<Value>, binding: &str, rows: usize) -> Result<(usize, usize), Error> {
    match cursor {
        None => Ok((0, 0)),
        Some(value) => {
            let c: Cursor = serde_json::from_value(value).map_err(|_| Error::Cursor)?;
            if c.binding != binding || c.row >= rows {
                return Err(Error::Cursor);
            }
            Ok((c.row, c.offset))
        }
    }
}
fn next(binding: &str, row: usize, offset: usize, total: usize) -> Value {
    if row == total {
        Value::Null
    } else {
        json!(Cursor {
            binding: binding.into(),
            row,
            offset
        })
    }
}
// Fresh pins/nonces may change between catalog/reference calls, but the list of
// visible source identities/capabilities and decoded content must remain bound.
fn stable(value: &Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(k, _)| !matches!(k.as_str(), "pin" | "pin_wire" | "selection"))
                .map(|(k, v)| (k.clone(), stable(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(stable).collect()),
        v => v.clone(),
    }
}
/// Catalog/help lists keep every visible entry, with an explicit continuation.
/// A changed visible roster invalidates the old cursor instead of skipping rows.
pub(in crate::evidence_library) fn list(
    mut value: Value,
    field: &str,
    query: &Value,
    cursor: Option<Value>,
) -> Result<Value, Error> {
    let binding = digest(&json!({"query":query,"view":stable(&value)}))?;
    let rows = value
        .as_object_mut()
        .and_then(|v| v.remove(field))
        .and_then(|v| v.as_array().cloned())
        .ok_or(Error::Corrupt)?;
    let (start, offset) = position(cursor, &binding, rows.len())?;
    if offset != 0 {
        return Err(Error::Cursor);
    }
    value[field] = json!([]);
    value["presentation_coverage"] = json!("This page only. Follow next with unchanged tool arguments; upstream coverage is not complete capture.");
    let mut index = start;
    while index < rows.len() {
        value[field]
            .as_array_mut()
            .ok_or(Error::Corrupt)?
            .push(rows[index].clone());
        value["next"] = next(&binding, index + 1, 0, rows.len());
        if size(&value)? > LIMIT {
            value[field].as_array_mut().ok_or(Error::Corrupt)?.pop();
            if index == start {
                return Err(Error::Limited);
            }
            break;
        }
        index += 1;
    }
    value["next"] = next(&binding, index, 0, rows.len());
    if size(&value)? > LIMIT {
        return Err(Error::Limited);
    }
    Ok(value)
}
enum Attribution<'a> {
    Item {
        content: &'a Value,
        stream: &'a Value,
        item: &'a Value,
        source: &'a str,
        tool: bool,
    },
    Occurrence {
        record: &'a Value,
        source: &'a str,
    },
}
struct Row<'a> {
    value: Value,
    text: Option<std::borrow::Cow<'a, str>>,
    attribution: Option<Attribution<'a>>,
}
fn fields(value: &Value, omitted: &[&str]) -> Result<Value, Error> {
    Ok(Value::Object(
        value
            .as_object()
            .ok_or(Error::Corrupt)?
            .iter()
            .filter(|(k, _)| !omitted.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ))
}
fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, Error> {
    v[key].as_array().ok_or(Error::Corrupt)
}
fn citations(
    content: &Value,
    stream: &Value,
    item: &Value,
    source: &str,
    tool: bool,
    report: Option<&str>,
    reference: &mut impl FnMut(&str, Value) -> Result<String, Error>,
) -> Result<Value, Error> {
    let set = if tool {
        &item["tool"]["citation_set"]
    } else {
        &item["citation_set"]
    }
    .as_str()
    .and_then(|n| n.parse::<usize>().ok())
    .ok_or(Error::Corrupt)?;
    let mut out = Vec::new();
    for cite in array(stream, "citation_sets")?
        .get(set)
        .and_then(Value::as_array)
        .ok_or(Error::Corrupt)?
    {
        let index = cite["input"]
            .as_str()
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or(Error::Corrupt)?;
        let record = array(content, "occurrences")?
            .get(index)
            .ok_or(Error::Corrupt)?["record"]
            .clone();
        let mut value = json!({"source":source,"uri":reference(source,record)?,"bytes":cite["bytes"],"coarse":item["coarse"]});
        if let Some(id) = report {
            value["reference_request"] = json!({"report":{"id":id,"input":index}});
        }
        out.push(value);
        // Expand only the next visible item's citation set, never all repeated
        // sets across the entire interpreted transcript.
        if serde_json::to_vec(&out).map_err(|_| Error::Corrupt)?.len() > LIMIT {
            return Err(Error::Limited);
        }
    }
    Ok(json!(out))
}
// Keep whole items, original item indices and citation sets after reconstruction.
// State rows are emitted separately and are never filtered by this focus.
fn report_item_touches(
    stream: &Value,
    item: &Value,
    input: usize,
    count: usize,
) -> Result<bool, Error> {
    let sets = array(stream, "citation_sets")?;
    let touches = |id: &Value| -> Result<bool, Error> {
        let n = id
            .as_str()
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or(Error::Corrupt)?;
        let set = sets
            .get(n)
            .and_then(Value::as_array)
            .ok_or(Error::Corrupt)?;
        let mut found = false;
        for cite in set {
            let n = cite["input"]
                .as_str()
                .and_then(|v| v.parse::<usize>().ok())
                .ok_or(Error::Corrupt)?;
            if n >= count {
                return Err(Error::Corrupt);
            }
            found |= n == input;
        }
        Ok(found)
    };
    let text = item["text"].is_string();
    let tool = item["tool"]["json"].is_string();
    Ok((!text && !tool)
        || (text && touches(&item["citation_set"])?)
        || (tool && touches(&item["tool"]["citation_set"])?))
}
fn report_readable_inputs(content: &Value) -> Result<Vec<usize>, Error> {
    let mut counts = vec![0; array(content, "occurrences")?.len()];
    if counts.len() > 8 {
        return Err(Error::Corrupt);
    }
    for group in array(content, "groups")? {
        for direction in ["request", "response"] {
            let stream = &group[direction];
            for item in array(stream, "items")? {
                if !item["text"].is_string() && !item["tool"]["json"].is_string() {
                    continue;
                }
                let count = counts.len();
                for (input, value) in counts.iter_mut().enumerate() {
                    if report_item_touches(stream, item, input, count)? {
                        *value += 1;
                    }
                }
            }
        }
    }
    Ok(counts)
}
fn compact_citations(page: &mut Value) -> Result<(), Error> {
    let mut dictionary = page["citation_dictionary"]
        .as_object()
        .cloned()
        .ok_or(Error::Corrupt)?;
    for entry in page["entries"].as_array_mut().ok_or(Error::Corrupt)? {
        let Some(values) = entry
            .as_object_mut()
            .ok_or(Error::Corrupt)?
            .remove("citations")
        else {
            continue;
        };
        let mut refs = Vec::new();
        for cite in values.as_array().ok_or(Error::Corrupt)? {
            let id = match dictionary
                .iter()
                .find(|(_, v)| *v == cite)
                .map(|(k, _)| k.clone())
            {
                Some(id) => id,
                None => {
                    let id = format!("c{}", dictionary.len());
                    dictionary.insert(id.clone(), cite.clone());
                    id
                }
            };
            refs.push(id);
        }
        entry["citation_refs"] = json!(refs);
    }
    page["citation_dictionary"] = json!(dictionary);
    Ok(())
}
fn content_rows<'a>(
    content: &'a Value,
    source: &'a str,
    selection: usize,
    focus: Option<usize>,
    excerpt: Option<&crate::evidence_library::proof::reports::Excerpt>,
    rows: &mut Vec<Row<'a>>,
    hash: &mut Sha256,
) -> Result<(), Error> {
    if let Some(input) = focus {
        if input >= array(content, "occurrences")?.len() {
            return Err(Error::Corrupt);
        }
    }
    // Bind citation lineage once, without expanding a reused set for each item.
    hash.update(serde_json::to_vec(&stable(&content["occurrences"])).map_err(|_| Error::Corrupt)?);
    for group in array(content, "groups")? {
        for direction in ["request", "response"] {
            hash.update(
                serde_json::to_vec(&group[direction]["citation_sets"])
                    .map_err(|_| Error::Corrupt)?,
            );
        }
    }
    // Non-capture/unavailable observations have no group; never hide them.
    for observation in array(content, "observations")? {
        if observation["kind"] != "capture" {
            let index = observation["input"]
                .as_str()
                .and_then(|n| n.parse::<usize>().ok())
                .ok_or(Error::Corrupt)?;
            let record = &array(content, "occurrences")?
                .get(index)
                .ok_or(Error::Corrupt)?["record"];
            rows.push(Row { value:json!({"type":"observation","source":source,"selection":selection,"observation":observation}),text:None, attribution:Some(Attribution::Occurrence{record,source}) });
        }
    }
    for (group_index, group) in array(content, "groups")?.iter().enumerate() {
        let context = json!({"source":source,"selection":selection,"group":group_index,"writer":group["writer"],"observer":group["observer"],"attempt":group["attempt"]});
        let state = fields(group, &["request", "response", "ordinals", "metadata"])?;
        rows.push(Row { value:json!({"type":"group-state","context":context,"state":state,"ordinal_count":array(group,"ordinals")?.len(),"ordinal_conflicts":array(group,"ordinals")?.iter().filter(|o|o["conflict"]==true).count(),"audit_fields_omitted":["ordinals","metadata"]}),text:None,attribution:None });
        for direction in ["request", "response"] {
            let stream = &group[direction];
            let omitted = array(stream, "items")?
                .iter()
                .filter(|item| {
                    item["text"].is_null()
                        && matches!(
                            item["kind"].as_str(),
                            Some("protocol" | "framing" | "context")
                        )
                })
                .count();
            rows.push(Row { value:json!({"type":"stream-state","context":context,"direction":direction,"state":fields(stream,&["items","citation_sets","parsed_json"])?,"nontext_protocol_items_in_audit":omitted}),text:None,attribution:None });
            for (index, item) in array(stream, "items")?.iter().enumerate() {
                if excerpt.is_some_and(|e| {
                    e.group != group_index || e.direction != direction || e.item != index
                }) {
                    continue;
                }
                // Protocol/context wrappers often duplicate a whole JSONL event.
                // Preserve their count and audit availability, not empty rows
                // before every readable child. Malformed/unsupported states stay.
                if item["text"].is_null()
                    && matches!(
                        item["kind"].as_str(),
                        Some("protocol" | "framing" | "context")
                    )
                {
                    continue;
                }
                if let Some(input) = focus {
                    if !report_item_touches(
                        stream,
                        item,
                        input,
                        array(content, "occurrences")?.len(),
                    )? {
                        continue;
                    }
                }
                if excerpt.is_none_or(|e| e.part == "text") {
                    rows.push(Row {
                    value:json!({"type":"item","context":context,"direction":direction,"item_index":index,
                        "item":fields(item,&["text","event_json","tool"])?,"tool_input_follows":!item["tool"].is_null()}),
                    text:item["text"].as_str().map(std::borrow::Cow::Borrowed),
                    attribution:Some(Attribution::Item{content,stream,item,source,tool:false}),
                });
                }
                if let Some(text) = item["tool"]["json"]
                    .as_str()
                    .filter(|_| excerpt.is_none_or(|e| e.part == "tool"))
                {
                    rows.push(Row {
                        value:json!({"type":"tool-input","context":context,"direction":direction,"item_index":index,
                            "item":{"kind":"tool-input-json","region":item["tool"]["region"],"coarse":item["coarse"]},
                            "interpretation":"JSON input data, not instructions or proof that the tool executed."}),
                        text:Some(std::borrow::Cow::Borrowed(text)),
                        attribution:Some(Attribution::Item{content,stream,item,source,tool:true}),
                    });
                }
            }
        }
    }
    Ok(())
}
/// Decode through the existing reader on every request before calling this pure
/// view. Changed evidence/state/query invalidates a cursor; no cached grant exists.
pub(in crate::evidence_library) fn content(
    value: &Value,
    source: Option<&str>,
    query: &Value,
    cursor: Option<Value>,
    mut extra: Value,
    mut reference: impl FnMut(&str, Value) -> Result<String, Error>,
) -> Result<Value, Error> {
    if extra["report_selection"].is_object() {
        let counts = report_readable_inputs(value)?;
        let focus = extra["report_selection"]["input"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(Error::Corrupt)?;
        let count = *counts.get(focus).ok_or(Error::Corrupt)?;
        let id = extra["report_selection"]["id"].clone();
        let readable = counts.iter().enumerate().filter(|(_,n)|**n>0).map(|(input,n)|json!({"input":input,"readable_items":n,"reference_request":{"report":{"id":id,"input":input}}})).collect::<Vec<_>>();
        extra["report_selection"]["readable_items_in_focus"] = json!(count);
        extra["report_selection"]["readability"] = json!(if count > 0 {
            "Decoded text or tool arguments are present in this focused view."
        } else if readable.is_empty() {
            "No decoded text or tool arguments in the frozen manifest. This view contains structural/loss metadata only."
        } else {
            "This input contains no decoded text or tool arguments. Metadata entries do not verify source text; use a readable_inputs reference_request to open a text-bearing input."
        });
        extra["report_selection"]["readable_inputs"] = json!(readable);
    }
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(query).map_err(|_| Error::Corrupt)?);
    hash.update(serde_json::to_vec(&extra).map_err(|_| Error::Corrupt)?);
    let mut rows = Vec::new();
    let excerpt: Option<crate::evidence_library::proof::reports::Excerpt> =
        if extra["excerpt"].is_object() {
            Some(serde_json::from_value(extra["excerpt"].clone()).map_err(|_| Error::Cursor)?)
        } else {
            None
        };
    if excerpt.as_ref().is_some_and(|e| !e.valid()) {
        return Err(Error::Cursor);
    }
    let focus = if extra["report_selection"].is_object() {
        Some(
            extra["report_selection"]["input"]
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(Error::Corrupt)?,
        )
    } else {
        None
    };
    if let Some(source) = source {
        content_rows(
            value,
            source,
            0,
            focus,
            excerpt.as_ref(),
            &mut rows,
            &mut hash,
        )?;
    } else {
        for (index, attempt) in array(value, "attempts")?.iter().enumerate() {
            let source = attempt["source"].as_str().ok_or(Error::Corrupt)?;
            rows.push(Row { value:json!({"type":"session-attempt","selection":index,"source":source,"membership":attempt["membership"],"links":attempt["links"]}),text:None,attribution:None });
            content_rows(
                &attempt["content"],
                source,
                index,
                focus,
                excerpt.as_ref(),
                &mut rows,
                &mut hash,
            )?;
        }
    }
    if excerpt.is_some() && !rows.iter().any(|r| r.text.is_some()) {
        return Err(Error::Cursor);
    }
    // Semantic disclosure: useful decoded text/tool data precedes structural
    // diagnostics. Stable sorting keeps original indices and every loss row;
    // full selected evidence inspection remains available in the advanced API.
    rows.sort_by_key(|r| r.text.is_none());
    for row in &rows {
        let metadata = serde_json::to_vec(&row.value).map_err(|_| Error::Corrupt)?;
        hash.update(metadata.len().to_be_bytes());
        hash.update(metadata);
        match row.text.as_deref() {
            Some(text) => {
                hash.update([1]);
                hash.update(text.len().to_be_bytes());
                hash.update(text.as_bytes());
            }
            None => hash.update([0]),
        }
    }
    let binding = crate::evidence_service::hex(&hash.finalize());
    let (mut index, mut offset) = position(cursor, &binding, rows.len())?;
    let mut page = json!({"version":"kan-mcp-content-page/2","entries":[],"citation_dictionary":{},"next":null,
        "coverage":value["coverage"],"identity":value.get("identity"),"reference":extra.get("reference"),"uri":extra.get("uri"),"origin_evaluation":extra.get("origin_evaluation"),
        "presentation":"Text first. Each entry's citation_refs resolves in THIS page's citation_dictionary, retaining original URI, exact enclosing range and coarse flag. event_json, parsed_json and raw frame metadata remain in the advanced shared audit API. Attribution is enclosing, not exact JSON tokens.",
        "complete_selection_view":false,"view_id":binding,"disclosure":"excerpts-first; diagnostics follow; full original evidence remains available through the shared audit API"});
    if extra["report_selection"].is_object() {
        page["report_selection"] = extra["report_selection"].clone();
    }
    while index < rows.len() {
        let row = &rows[index];
        let text = row.text.as_deref().unwrap_or("");
        if offset > text.len()
            || !text.is_char_boundary(offset)
            || (row.text.is_none() && offset != 0)
        {
            return Err(Error::Cursor);
        }
        let mut materialized = row.value.clone();
        if extra["report_selection"].is_object() && materialized["type"] == "item" {
            materialized["content_state"] = json!(if row.text.is_some() {
                "decoded-text"
            } else {
                "metadata-only; no decoded body on this item"
            });
        }
        let attribution = match &row.attribution {
            Some(Attribution::Item {
                content,
                stream,
                item,
                source,
                tool,
            }) => citations(
                content,
                stream,
                item,
                source,
                *tool,
                extra["report_selection"]["id"].as_str(),
                &mut reference,
            )
            .map(|v| {
                materialized["citations"] = v;
            }),
            Some(Attribution::Occurrence { record, source }) => {
                reference(source, (**record).clone()).map(|v| {
                    materialized["uri"] = json!(v);
                })
            }
            None => Ok(()),
        };
        if let Err(e) = attribution {
            if e == Error::Limited && !page["entries"].as_array().ok_or(Error::Corrupt)?.is_empty()
            {
                page["next"] = next(&binding, index, offset, rows.len());
                page["complete_selection_view"] = json!(false);
                if size(&page)? > LIMIT {
                    return Err(Error::Limited);
                }
                return Ok(page);
            }
            return Err(e);
        }
        let mut end = (offset + TEXT_CHUNK).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        loop {
            if offset < text.len() && end == offset {
                return Err(Error::Limited);
            }
            let mut entry = materialized.clone();
            if row.text.is_some() {
                entry["item"]["text"] = json!(&text[offset..end]);
                entry["text_fragment"] = json!({"continued":offset>0,"final":end==text.len()});
            }
            let (following, at) = if end == text.len() {
                (index + 1, 0)
            } else {
                (index, end)
            };
            let before = page.clone();
            page["entries"]
                .as_array_mut()
                .ok_or(Error::Corrupt)?
                .push(entry);
            compact_citations(&mut page)?;
            page["next"] = next(&binding, following, at, rows.len());
            page["complete_selection_view"] = json!(following == rows.len());
            if size(&page)? + 256 <= LIMIT {
                index = following;
                offset = at;
                break;
            }
            page = before;
            if !page["entries"].as_array().ok_or(Error::Corrupt)?.is_empty() {
                page["next"] = next(&binding, index, offset, rows.len());
                page["complete_selection_view"] = json!(false);
                if size(&page)? > LIMIT {
                    return Err(Error::Limited);
                }
                return Ok(page);
            }
            if end == offset {
                return Err(Error::Limited);
            }
            let mut smaller = offset + (end - offset) / 2;
            while !text.is_char_boundary(smaller) {
                smaller -= 1;
            }
            end = smaller;
        }
    }
    page["next"] = Value::Null;
    page["complete_selection_view"] = json!(true);
    if size(&page)? > LIMIT {
        return Err(Error::Limited);
    }
    Ok(page)
}

#[cfg(test)]
fn first_citation<'a>(page: &'a Value, entry: &Value) -> &'a Value {
    &page["citation_dictionary"][entry["citation_refs"][0].as_str().unwrap()]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excerpt_first_page_deduplicates_witnesses_and_preserves_frozen_item_and_view_identity() {
        let text = "observable é🙂 text ".repeat(2000);
        let raw = fixture(&text);
        let original = raw.clone();
        let query = json!({"report":{"id":"a".repeat(64),"input":0,"excerpt":{"group":0,"direction":"request","item":0,"part":"text"}}});
        let extra = json!({"origin_evaluation":{"id":"a".repeat(64),"version":"kan-report-evaluation/1"},"report_selection":{"id":"a".repeat(64),"input":0,"inputs_count":1},"excerpt":query["report"]["excerpt"]});
        let mut cursor = None;
        let mut joined = String::new();
        let mut view = None;
        let mut pages = 0;
        loop {
            let page = content(
                &raw,
                Some("source"),
                &query,
                cursor,
                extra.clone(),
                |_, _| Ok(format!("kan+capture://{}", "u".repeat(1200))),
            )
            .unwrap();
            assert_eq!(page["origin_evaluation"], extra["origin_evaluation"]);
            assert!(size(&page).unwrap() <= LIMIT);
            if pages == 0 {
                assert_eq!(page["entries"][0]["type"], "item");
                assert!(page["entries"][0]["item"]["text"].is_string());
            }
            assert!(page["citation_dictionary"].as_object().unwrap().len() <= 1);
            if let Some(id) = &view {
                assert_eq!(&page["view_id"], id);
            } else {
                view = Some(page["view_id"].clone());
            }
            for row in page["entries"].as_array().unwrap() {
                if let Some(t) = row["item"]["text"].as_str() {
                    assert_eq!(row["item_index"], 0);
                    assert!(row.get("citations").is_none());
                    assert_eq!(first_citation(&page, row)["bytes"], json!(["0", "200000"]));
                    joined.push_str(t);
                }
            }
            pages += 1;
            assert!(pages < 100);
            if page["next"].is_null() {
                break;
            }
            cursor = Some(page["next"].clone());
        }
        assert_eq!(joined, text);
        assert_eq!(raw, original);
        let mut bad = extra;
        bad["excerpt"]["item"] = json!(99);
        assert_eq!(
            content(&raw, Some("source"), &query, None, bad, |_, _| Ok(
                "uri".into()
            ))
            .unwrap_err(),
            Error::Cursor
        );
    }
    #[test]
    fn report_focus_preserves_original_item_indices_tool_citations_and_loss_states() {
        let text = "é🙂 report tool arguments ".repeat(2000);
        let mut raw = fixture("unrelated prefix");
        raw["occurrences"] = json!([{"record":{"sequence":"1"}},{"record":{"sequence":"2"}},{"record":{"sequence":"3"}}]);
        raw["groups"][0]["request"]["citation_sets"] =
            json!([[{"input":"0","bytes":["0","50"]}],[{"input":"2","bytes":["50","90000"]}]]);
        raw["groups"][0]["request"]["items"].as_array_mut().unwrap().push(json!({"kind":"tool-use","role":"assistant","text":"Write","coarse":true,"citation_set":"0","tool":{"json":text,"region":["50","90000"],"citation_set":"1"}}));
        let original = raw.clone();
        let query = json!({"report":{"id":"r","input":2}});
        let extra = json!({"report_selection":{"id":"r","input":2,"inputs_count":3,"coverage":"frozen manifest context; focused enclosing items only"}});
        let mut cursor = None;
        let mut first_cursor = None;
        let mut joined = String::new();
        let mut loss_seen = false;
        let mut pages = 0;
        loop {
            let page = content(
                &raw,
                Some("source"),
                &query,
                cursor,
                extra.clone(),
                |_, record| Ok(format!("source-{}", record["sequence"].as_str().unwrap())),
            )
            .unwrap();
            assert!(size(&page).unwrap() <= LIMIT);
            assert_eq!(
                page["report_selection"]["id"],
                extra["report_selection"]["id"]
            );
            assert_eq!(page["report_selection"]["input"], 2);
            assert_eq!(page["report_selection"]["readable_items_in_focus"], 1);
            for entry in page["entries"].as_array().unwrap() {
                assert_ne!(entry["item"]["text"], "unrelated prefix");
                if entry["type"] == "stream-state" && entry["direction"] == "response" {
                    loss_seen = true;
                    assert_eq!(entry["state"]["state"], "unavailable");
                }
                if entry["type"] == "tool-input" {
                    assert_eq!(entry["item_index"], 1);
                    assert_eq!(first_citation(&page, entry)["uri"], "source-3");
                    joined.push_str(entry["item"]["text"].as_str().unwrap());
                }
                if entry["type"] == "item" {
                    assert_eq!(entry["item_index"], 1);
                    assert_eq!(first_citation(&page, entry)["uri"], "source-1");
                }
            }
            pages += 1;
            assert!(pages < 100);
            cursor = page.get("next").filter(|v| !v.is_null()).cloned();
            if first_cursor.is_none() {
                first_cursor = cursor.clone();
            }
            if cursor.is_none() {
                assert_eq!(page["complete_selection_view"], true);
                break;
            }
        }
        assert!(loss_seen && pages > 1);
        assert_eq!(joined, text);
        assert_eq!(raw, original);
        let mut changed = extra;
        changed["report_selection"]["input"] = json!(0);
        assert_eq!(
            content(
                &raw,
                Some("source"),
                &query,
                first_cursor,
                changed,
                |_, _| Ok("uri".into())
            )
            .unwrap_err(),
            Error::Cursor
        );
    }
    #[test]
    fn metadata_only_report_focus_explains_absence_and_routes_to_readable_input() {
        let mut raw = fixture("A source statement é🙂");
        raw["occurrences"] = json!([{"record":{"sequence":"1"}},{"record":{"sequence":"2"}}]);
        raw["groups"][0]["request"]["items"].as_array_mut().unwrap().push(json!({"kind":"text","role":"user","text":null,"tool":null,"citation_set":"0","coarse":true}));
        let original = raw.clone();
        let query = json!({"report":{"id":"report","input":1}});
        let extra = json!({"report_selection":{"id":"report","input":1,"inputs_count":2}});
        let page = content(&raw, Some("source"), &query, None, extra, |_, _| {
            Ok("exact-source-uri".into())
        })
        .unwrap();
        assert!(size(&page).unwrap() <= LIMIT);
        assert_eq!(page["report_selection"]["readable_items_in_focus"], 0);
        assert!(page["report_selection"]["readability"]
            .as_str()
            .unwrap()
            .contains("no decoded text"));
        let hop = page["report_selection"]["readable_inputs"][0]["reference_request"].clone();
        assert_eq!(hop, json!({"report":{"id":"report","input":0}}));
        let metadata = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["type"] == "item")
            .unwrap();
        assert_eq!(
            metadata["content_state"],
            "metadata-only; no decoded body on this item"
        );
        assert_eq!(first_citation(&page, metadata)["reference_request"], hop);
        assert_eq!(first_citation(&page, metadata)["uri"], "exact-source-uri");
        let readable = content(
            &raw,
            Some("source"),
            &hop,
            None,
            json!({"report_selection":{"id":"report","input":0,"inputs_count":2}}),
            |_, _| Ok("exact-source-uri".into()),
        )
        .unwrap();
        assert_eq!(readable["report_selection"]["readable_items_in_focus"], 1);
        assert!(readable["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["item"]["text"] == "A source statement é🙂"));
        assert_eq!(raw, original);
        for item in raw["groups"][0]["request"]["items"].as_array_mut().unwrap() {
            item["text"] = Value::Null;
        }
        let empty = content(
            &raw,
            Some("source"),
            &query,
            None,
            json!({"report_selection":{"id":"report","input":1,"inputs_count":2}}),
            |_, _| Ok("uri".into()),
        )
        .unwrap();
        assert_eq!(empty["report_selection"]["readable_inputs"], json!([]));
        assert!(empty["report_selection"]["readability"]
            .as_str()
            .unwrap()
            .contains("No decoded text"));
    }
    fn fixture(text: &str) -> Value {
        json!({"coverage":"explicit selection only, not complete capture","observations":[{"kind":"capture","input":"0"}],"occurrences":[{"record":{"sequence":"1"}}],
        "groups":[{"writer":"writer","observer":"collector","attempt":"attempt","ordinals":[],"ordinal_gaps":[],"missing_start":false,"terminal":"claimed-completed","metadata":[],
        "request":{"state":"interpreted","items":[{"kind":"text","role":"assistant","text":text,"coarse":true,"citation_set":"0","event_json":text,"tool":null}],"citation_sets":[[{"input":"0","bytes":["0","200000"]}]],"parsed_json":text},
        "response":{"state":"unavailable","issues":[{"kind":"gap","bytes":["1","2"]}],"items":[],"citation_sets":[],"parsed_json":null}}]})
    }
    #[test]
    fn unicode_pages_reassemble_text_and_preserve_citations_without_raw_duplicates() {
        let text = "é🙂漢字\"\\\n".repeat(20000);
        let raw = fixture(&text);
        let original = raw.clone();
        let query = json!({"source":"selected","pin":"exact"});
        let mut cursor = None;
        let mut joined = String::new();
        let mut pages = 0;
        loop {
            let page = content(
                &raw,
                Some("selected"),
                &query,
                cursor,
                Value::Null,
                |_, _| Ok("kan+capture://test-citation".into()),
            )
            .unwrap();
            assert!(size(&page).unwrap() <= LIMIT);
            assert!(!page.to_string().contains("event_json\":"));
            for entry in page["entries"].as_array().unwrap() {
                if let Some(text) = entry["item"]["text"].as_str() {
                    joined.push_str(text);
                    assert_eq!(
                        first_citation(&page, entry)["uri"],
                        "kan+capture://test-citation"
                    );
                    assert_eq!(
                        first_citation(&page, entry)["bytes"],
                        json!(["0", "200000"])
                    );
                }
            }
            pages += 1;
            assert!(pages < 1000);
            cursor = page.get("next").filter(|v| !v.is_null()).cloned();
            if cursor.is_none() {
                assert_eq!(page["complete_selection_view"], true);
                break;
            }
        }
        assert_eq!(joined, text);
        assert_eq!(raw, original);
        assert!(pages > 1);
    }
    #[test]
    fn changed_query_or_content_rejects_cursor_and_unavailable_state_is_visible() {
        let raw = fixture(&"x".repeat(30000));
        let query = json!({"source":"chosen"});
        let page = content(&raw, Some("chosen"), &query, None, Value::Null, |_, _| {
            Ok("uri".into())
        })
        .unwrap();
        let cursor = page["next"].clone();
        assert_eq!(
            content(
                &raw,
                Some("chosen"),
                &json!({"source":"other"}),
                Some(cursor.clone()),
                Value::Null,
                |_, _| Ok("uri".into())
            ),
            Err(Error::Cursor)
        );
        assert_eq!(
            content(
                &fixture("changed"),
                Some("chosen"),
                &query,
                Some(cursor),
                Value::Null,
                |_, _| Ok("uri".into())
            ),
            Err(Error::Cursor)
        );
        let missing = json!({"coverage":"explicit only","observations":[{"kind":"unavailable","input":"0","reason":"KeyUnavailable"}],"occurrences":[{"record":{"sequence":"1"}}],"groups":[]});
        let page = content(
            &missing,
            Some("chosen"),
            &query,
            None,
            Value::Null,
            |_, _| Ok("uri".into()),
        )
        .unwrap();
        assert_eq!(page["entries"][0]["observation"]["kind"], "unavailable");
    }
    #[test]
    fn catalog_pagination_preserves_entries_and_invalidates_changed_roster() {
        let rows: Vec<_> = (0..16)
            .map(|i| json!({"id":i,"pin":"x".repeat(3000)}))
            .collect();
        let value = json!({"scopes":rows,"coverage":"complete"});
        let page = list(value.clone(), "scopes", &json!({}), None).unwrap();
        assert!(size(&page).unwrap() <= LIMIT);
        let cursor = page["next"].clone();
        assert!(!cursor.is_null());
        let mut changed = value.clone();
        changed["scopes"][0]["id"] = json!(99);
        assert_eq!(
            list(changed, "scopes", &json!({}), Some(cursor.clone())),
            Err(Error::Cursor)
        );
        let rest = list(value, "scopes", &json!({}), Some(cursor)).unwrap();
        assert!(rest["scopes"][0]["id"].as_u64().unwrap() > 0);
    }
    #[test]
    fn citations_expand_only_for_the_visible_page_and_oversized_units_refuse() {
        let mut raw = fixture("small text");
        let item = raw["groups"][0]["request"]["items"][0].clone();
        raw["groups"][0]["request"]["items"] = json!(vec![item; 300]);
        let mut expanded = 0;
        let page = content(
            &raw,
            Some("source"),
            &json!({}),
            None,
            Value::Null,
            |_, _| {
                expanded += 1;
                Ok("x".repeat(8500))
            },
        )
        .unwrap();
        let visible = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["type"] == "item")
            .count();
        assert!(
            expanded <= visible + 1,
            "expand only visible items plus the next candidate, never all 300 items"
        );
        assert_eq!(page["citation_dictionary"].as_object().unwrap().len(), 1);
        assert_eq!(page["citation_dictionary"]["c0"]["uri"], "x".repeat(8500));
        assert!(!page["next"].is_null());
        assert!(size(&page).unwrap() <= LIMIT);
        let small = fixture("🙂");
        assert_eq!(
            content(
                &small,
                Some("source"),
                &json!({}),
                None,
                Value::Null,
                |_, _| Ok("x".repeat(LIMIT + 1))
            ),
            Err(Error::Limited)
        );
    }
}

#[cfg(test)]
mod tool_input_tests {
    use super::*;
    #[test]
    fn decision_bearing_tool_input_is_bounded_reassembled_and_uses_its_own_citation_set() {
        let text=serde_json::to_string(&json!({"file_path":"DECISION.md","content":"Explicit decision é🙂漢字\n".repeat(12000)})).unwrap();
        let value = json!({"coverage":"selected only","occurrences":[{"record":{"sequence":"1"}},{"record":{"sequence":"2"}}],"observations":[],"groups":[{
            "writer":"w","observer":"collector","attempt":"a","ordinals":[],"metadata":[],
            "request":{"state":"interpreted","items":[{"kind":"tool-use","role":"assistant","text":"Write","coarse":true,"citation_set":"0","tool":{"json":text,"region":["0","999999"],"citation_set":"1"}}],"citation_sets":[[{"input":"0","bytes":["0","4"]}],[{"input":"1","bytes":["2","999999"]}]]},
            "response":{"state":"unavailable","items":[],"citation_sets":[]}}]});
        let mut cursor = None;
        let mut joined = String::new();
        let mut count = 0;
        loop {
            let page = content(
                &value,
                Some("s"),
                &json!({"uri":"stable-reference"}),
                cursor,
                Value::Null,
                |_, r| Ok(format!("uri-{}", r["sequence"].as_str().unwrap())),
            )
            .unwrap();
            assert!(size(&page).unwrap() <= LIMIT);
            for row in page["entries"].as_array().unwrap() {
                if row["type"] == "tool-input" {
                    joined.push_str(row["item"]["text"].as_str().unwrap());
                    assert_eq!(first_citation(&page, row)["uri"], "uri-2");
                    assert_eq!(first_citation(&page, row)["bytes"], json!(["2", "999999"]));
                }
            }
            count += 1;
            assert!(count < 500);
            cursor = page.get("next").filter(|v| !v.is_null()).cloned();
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(joined, text);
        assert!(count > 1);
    }
}
