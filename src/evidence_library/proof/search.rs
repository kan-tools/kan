//! Bounded, reproducible search over encrypted, reader-signed index pages.
use crate::{
    evidence_content::ContentError,
    evidence_reader::proof::{Occurrence, Pin, Reader, Source, Token},
    evidence_reconstruction::{self, Decoded},
    evidence_service::Failure,
    evidence_workspace::Workspace,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub source: String,
    pub pin: Pin,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub text: String,
    pub writer: Option<String>,
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_to: Option<String>,
}
impl Filter {
    pub fn validate(&self) -> Result<(), Failure> {
        if self
            .annotation_subject
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 256)
            || self
                .annotation_tag
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 64)
            || self.text.len() > 256
            || self.writer.as_ref().is_some_and(|s| s.len() > 256)
            || self.kind.as_ref().is_some_and(|s| s.len() > 64)
        {
            return Err(Failure::Invalid);
        }
        if self
            .observer
            .as_ref()
            .is_some_and(|s| !matches!(s.as_str(), "collector" | "gateway"))
            || self.attempt.as_ref().is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(Failure::Invalid);
        }
        let from = self.attested_from.as_deref().map(time).transpose()?;
        let to = self.attested_to.as_deref().map(time).transpose()?;
        if from.zip(to).is_some_and(|(a, b)| a > b) {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
}
fn time(s: &str) -> Result<u64, Failure> {
    let n = s.parse::<u64>().map_err(|_| Failure::Invalid)?;
    if n.to_string() != s {
        return Err(Failure::Invalid);
    }
    Ok(n)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Span {
    offset: usize,
    text: String,
    enclosing_end: Option<usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    record: Occurrence,
    writer: Option<String>,
    kind: String,
    observer: Option<String>,
    attempt: Option<String>,
    spans: Vec<Span>,
    unsearchable_bytes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    version: u8,
    documents: Vec<Document>,
    next: Option<Token>,
    indexed_at: u64,
}
fn doc(source: Source) -> Document {
    let (record, writer, plaintext, kind) = match source {
        Source::Available {
            record,
            writer,
            plaintext,
            ..
        } => (record, Some(writer), Some(plaintext), "opaque"),
        Source::KeyUnavailable { record, writer, .. } => {
            (record, Some(writer), None, "key-unavailable")
        }
        Source::Missing { record } => (record, None, None, "missing"),
        Source::Corrupt { record } => (record, None, None, "corrupt"),
    };
    let mut d = Document {
        record,
        writer,
        kind: kind.into(),
        observer: None,
        attempt: None,
        spans: Vec::new(),
        unsearchable_bytes: 0,
    };
    if let Some(bytes) = plaintext {
        let mut add = |offset: usize, b: &[u8]| {
            if let Ok(text) = std::str::from_utf8(b) {
                d.spans.push(Span {
                    offset,
                    text: text.into(),
                    enclosing_end: None,
                });
                if let Ok(value) = serde_json::from_slice::<Value>(b) {
                    let mut strings = Vec::new();
                    let mut visited = 0;
                    json_strings(&value, &mut strings, &mut visited);
                    for text in strings {
                        d.spans.push(Span {
                            offset,
                            text,
                            enclosing_end: Some(offset + b.len()),
                        });
                    }
                }
            } else {
                d.unsearchable_bytes += b.len();
            }
        };
        match evidence_reconstruction::decode(&bytes) {
            Ok(Decoded::Capture(frame)) => {
                d.kind = "capture".into();
                d.observer = serde_json::to_value(frame.header.observer)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned));
                d.attempt = Some(frame.header.attempt.clone());
                add(frame.header_span.start, &bytes[frame.header_span]);
                add(frame.body_span.start, frame.body);
            }
            Ok(Decoded::Unsupported(_)) => {
                d.kind = "unsupported".into();
                add(0, &bytes);
            }
            Err(_) => {
                d.kind = "malformed".into();
                add(0, &bytes);
            }
            _ => {
                if bytes.starts_with(b"KANI") {
                    match crate::evidence_restore::decode_frame(&bytes) {
                        Ok((_, offset)) => {
                            d.kind = "import".into();
                            add(9, &bytes[9..offset]);
                            add(offset, &bytes[offset..]);
                        }
                        Err(_) => {
                            d.kind = "malformed".into();
                            add(0, &bytes);
                        }
                    }
                } else {
                    add(0, &bytes)
                }
            }
        }
    }
    d
}
fn json_strings(value: &Value, strings: &mut Vec<String>, visited: &mut usize) {
    if *visited >= 8192 || strings.len() >= 2048 {
        return;
    }
    *visited += 1;
    match value {
        Value::String(s) => strings.push(s.clone()),
        Value::Array(items) => {
            for v in items {
                json_strings(v, strings, visited);
            }
        }
        Value::Object(items) => {
            for v in items.values() {
                json_strings(v, strings, visited);
            }
        }
        _ => (),
    }
}

fn key(target: &Target, cursor: Option<&Token>) -> Result<String, Failure> {
    serde_json::to_string(&("raw-text/3", target, cursor)).map_err(|_| Failure::Invalid)
}
fn load(
    workspace: &Workspace,
    target: &Target,
    cursor: Option<&Token>,
) -> Result<Option<Page>, Failure> {
    workspace
        .get("search-page", &key(target, cursor)?)?
        .map(|v| serde_json::from_value::<Page>(v).map_err(|_| Failure::Corrupt))
        .transpose()
}
fn status(page: &Page) -> Value {
    let mut facets = BTreeMap::<String, usize>::new();
    let mut writers = BTreeMap::<String, usize>::new();
    let mut observers = BTreeMap::<String, usize>::new();
    for d in &page.documents {
        *facets.entry(d.kind.clone()).or_default() += 1;
        if let Some(o) = &d.observer {
            *observers.entry(o.clone()).or_default() += 1;
        }
        if let Some(w) = &d.writer {
            *writers.entry(w.clone()).or_default() += 1;
        }
    }
    json!({"indexed_occurrences":page.documents.len(),"indexed_at":page.indexed_at.to_string(),"next":page.next,"facets_as_indexed":{"kind":facets,"writer":writers,"observer":observers},"unsearchable_bytes":page.documents.iter().map(|d|d.unsearchable_bytes).sum::<usize>().to_string(),"coverage":"This pinned index page only. Raw UTF-8 and up to 2,048 decoded string values in each complete JSON span are indexed. Normalized hits cite the enclosing original span. Missing/corrupt sources, binary spans, and text crossing capture chunks are not searchable. A complete scan does not prove complete capture."})
}
pub(super) async fn index(
    reader: &Reader,
    workspace: &Workspace,
    target: &Target,
    cursor: Option<&Token>,
    workers: Arc<tokio::sync::Semaphore>,
) -> Result<Value, ContentError> {
    let _permit = workers
        .try_acquire_owned()
        .map_err(|_| ContentError::Busy)?;
    tokio::time::timeout(Duration::from_secs(25), async {
        // Validate both the supplied pin and cursor even for an existing page.
        let inventory = reader.page(&target.pin, cursor, 8).await?;
        if let Some(p) = load(workspace, target, cursor)? {
            return Ok(status(&p));
        }
        let selections: Vec<_> = inventory.records.into_iter().map(|r| r.selection).collect();
        let mut documents = Vec::new();
        let mut start = 0;
        while start < selections.len() {
            let sources = reader
                .sources_prefix(&target.pin, &selections[start..])
                .await?;
            start += sources.len();
            documents.extend(sources.into_iter().map(doc));
        }
        reader.page(&target.pin, None, 1).await?;
        let page = Page {
            version: 3,
            documents,
            next: inventory.next,
            indexed_at: crate::evidence_operations::now(),
        };
        workspace.put(
            "search-page",
            &key(target, cursor)?,
            serde_json::to_value(&page).map_err(|_| Failure::Invalid)?,
        )?;
        Ok(status(&page))
    })
    .await
    .map_err(|_| ContentError::Limited)?
}
fn matching(d: &Document, filter: &Filter) -> Option<(usize, usize, String, bool, &'static str)> {
    if filter
        .writer
        .as_ref()
        .is_some_and(|w| Some(w) != d.writer.as_ref())
        || filter.kind.as_ref().is_some_and(|k| k != &d.kind)
        || filter
            .observer
            .as_ref()
            .is_some_and(|v| Some(v) != d.observer.as_ref())
        || filter
            .attempt
            .as_ref()
            .is_some_and(|v| Some(v) != d.attempt.as_ref())
        || filter.attested_from.as_ref().is_some_and(|v| {
            time(&d.record.issued_at)
                .ok()
                .zip(time(v).ok())
                .is_none_or(|(a, b)| a < b)
        })
        || filter.attested_to.as_ref().is_some_and(|v| {
            time(&d.record.issued_at)
                .ok()
                .zip(time(v).ok())
                .is_none_or(|(a, b)| a > b)
        })
    {
        return None;
    }
    let query = filter.text.to_ascii_lowercase();
    if query.is_empty() {
        return Some((
            0,
            0,
            format!(
                "{} occurrence {} · metadata filter match",
                d.kind, d.record.sequence
            ),
            true,
            "metadata-only",
        ));
    }
    for span in &d.spans {
        if let Some(at) = span.text.to_ascii_lowercase().find(&query) {
            let mut lo = at.saturating_sub(100);
            while !span.text.is_char_boundary(lo) {
                lo += 1;
            }
            let end = at + query.len();
            let mut hi = (end + 100).min(span.text.len());
            while !span.text.is_char_boundary(hi) {
                hi -= 1;
            }
            return Some((
                if span.enclosing_end.is_some() {
                    span.offset
                } else {
                    span.offset + at
                },
                span.enclosing_end.unwrap_or(span.offset + end),
                span.text[lo..hi].into(),
                span.enclosing_end.is_some(),
                if span.enclosing_end.is_some() {
                    "json-string"
                } else {
                    "raw-utf8"
                },
            ));
        }
    }
    None
}
pub(super) async fn search(
    reader: &Reader,
    workspace: &Workspace,
    target: &Target,
    cursor: Option<&Token>,
    filter: &Filter,
    workers: Arc<tokio::sync::Semaphore>,
) -> Result<Value, ContentError> {
    filter.validate()?;
    let _permit = workers
        .try_acquire_owned()
        .map_err(|_| ContentError::Busy)?;
    tokio::time::timeout(Duration::from_secs(25),async {
        reader.page(&target.pin,cursor,1).await?;
        let Some(page)=load(workspace,target,cursor)? else {return Ok(json!({"state":"not-indexed","hits":[],"next":null}));};
        if page.version!=3 || page.documents.len()>8 {return Err(Failure::Corrupt.into());}
        let mut hits=Vec::new();let mut unavailable=0;
        for d in &page.documents {if matching(d,filter).is_some() {
            let current=doc(reader.source(&target.pin,&d.record.selection).await?);
            if matches!(current.kind.as_str(),"missing"|"corrupt") {unavailable+=1;continue;}
            if let Some((start,end,snippet,coarse,interpretation))=matching(&current,filter) {hits.push(json!({"record":current.record,"writer":current.writer,"kind":current.kind,"observer":current.observer,"attempt":current.attempt,"attested_at":current.record.issued_at,"offset":start.to_string(),"end":end.to_string(),"snippet":snippet,"coarse":coarse,"interpretation":interpretation}));}
        }}
        reader.page(&target.pin,None,1).await?;
        let mut metadata_filter=filter.clone();metadata_filter.text.clear();
        let candidates:Vec<_>=page.documents.iter().filter(|d|d.kind=="capture" && matching(d,&metadata_filter).is_some()).map(|d|json!({"record":d.record,"writer":d.writer,"observer":d.observer,"attempt":d.attempt})).collect();
        let mut value=status(&page);value["attempt_members"]=json!(candidates);value["state"]=json!("indexed");value["hits"]=json!(hits);value["unavailable_matches"]=json!(unavailable);Ok(value)
    }).await.map_err(|_|ContentError::Limited)?
}

/// Search reconstructed supported messages. All output citations identify source
/// ranges in the supplied selection; normalized character offsets are not bytes.
pub(super) async fn attempt(
    reader: &Reader,
    target: &Target,
    selections: &[Token],
    filter: &Filter,
    workers: Arc<tokio::sync::Semaphore>,
) -> Result<Value, ContentError> {
    filter.validate()?;
    if filter.text.is_empty() {
        return Err(Failure::Invalid.into());
    }
    let bytes = crate::evidence_content::proof_content(
        reader,
        &target.pin,
        selections,
        crate::evidence_content::Format::AnthropicMessagesAuto,
        workers.clone(),
        true,
    )
    .await?;
    let permit = workers
        .try_acquire_owned()
        .map_err(|_| ContentError::Busy)?;
    let filter = filter.clone();
    let value = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        normalized(&bytes, &filter)
    })
    .await
    .map_err(|_| ContentError::Limited)??;
    reader.page(&target.pin, None, 1).await?;
    Ok(value)
}
fn normalized(bytes: &[u8], filter: &Filter) -> Result<Value, ContentError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Failure::Corrupt)?;
    let occurrences = value["occurrences"].as_array().ok_or(Failure::Corrupt)?;
    let mut hits = Vec::new();
    let mut streams = Vec::new();
    let mut citations = 0usize;
    let mut metadata_filter = filter.clone();
    metadata_filter.text.clear();
    let query = filter.text.to_ascii_lowercase();
    for group in value["groups"].as_array().ok_or(Failure::Corrupt)? {
        for direction in ["request", "response"] {
            let stream = &group[direction];
            streams.push(json!({"attempt":group["attempt"],"direction":direction,"state":stream["state"],"issues":stream["issues"],"terminal":group["terminal"],"ordinal_gaps":group["ordinal_gaps"]}));
            let sets = stream["citation_sets"].as_array().ok_or(Failure::Corrupt)?;
            for (ordinal, item) in stream["items"]
                .as_array()
                .ok_or(Failure::Corrupt)?
                .iter()
                .enumerate()
            {
                // Keep message/block boundaries. Unsupported fields still have raw search.
                let (text, citation_set) = if let Some(text) = item["text"].as_str() {
                    (text, &item["citation_set"])
                } else if let Some(text) = item["tool"]["json"].as_str() {
                    (text, &item["tool"]["citation_set"])
                } else {
                    continue;
                };
                let Some(at) = text.to_ascii_lowercase().find(&query) else {
                    continue;
                };
                let index = citation_set
                    .as_str()
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or(Failure::Corrupt)?;
                let source_ranges = sets
                    .get(index)
                    .and_then(Value::as_array)
                    .ok_or(Failure::Corrupt)?;
                let mut cites = Vec::new();
                let mut allowed = true;
                for cite in source_ranges {
                    let input = cite["input"]
                        .as_str()
                        .and_then(|s| s.parse::<usize>().ok())
                        .ok_or(Failure::Corrupt)?;
                    let origin = occurrences.get(input).ok_or(Failure::Corrupt)?;
                    let record: Occurrence = serde_json::from_value(origin["record"].clone())
                        .map_err(|_| Failure::Corrupt)?;
                    let document = Document {
                        record,
                        writer: origin["writer"].as_str().map(str::to_owned),
                        kind: "capture".into(),
                        observer: group["observer"].as_str().map(str::to_owned),
                        attempt: group["attempt"].as_str().map(str::to_owned),
                        spans: vec![],
                        unsearchable_bytes: 0,
                    };
                    if matching(&document, &metadata_filter).is_none() {
                        allowed = false;
                        break;
                    }
                    cites.push(json!({"record":document.record,"offset":cite["bytes"][0],"end":cite["bytes"][1]}));
                }
                if !allowed || cites.is_empty() {
                    continue;
                }
                citations += cites.len();
                if citations > 8192 || hits.len() >= 128 {
                    return Err(ContentError::Limited);
                }
                let mut lo = at.saturating_sub(100);
                while !text.is_char_boundary(lo) {
                    lo += 1;
                }
                let mut hi = (at + query.len() + 100).min(text.len());
                while !text.is_char_boundary(hi) {
                    hi -= 1;
                }
                let first = &cites[0];
                hits.push(json!({"record":first["record"],"offset":first["offset"],"end":first["end"],"snippet":&text[lo..hi],"coarse":true,"interpretation":"reconstructed-message","kind":"capture","writer":group["writer"],"observer":group["observer"],"attempt":group["attempt"],"direction":direction,"item":ordinal,"item_kind":item["kind"],"issues":item["issues"],"cites":cites}));
            }
        }
    }
    let out = json!({"version":"normalized-attempt-search/1","hits":hits,"streams":streams,"coverage":"Selected attempt only. Complete reconstructed supported message fields are searched across capture chunks. Each match retains all enclosing source ranges. Distinct messages and SSE delta items are not concatenated; incomplete streams and unsupported fields remain visible through raw search and Content."});
    if serde_json::to_vec(&out)
        .map_err(|_| Failure::Corrupt)?
        .len()
        > 4 * 1024 * 1024
    {
        return Err(ContentError::Limited);
    }
    Ok(out)
}

/// Annotation filters are a current, attributed view over evidence. They never
/// turn annotation text into raw source or relax the source reader's checks.
impl super::Readers {
    pub(super) async fn filter_search_annotations(
        &self,
        target: &Target,
        filter: &Filter,
        value: &mut Value,
    ) -> Result<(), ContentError> {
        if filter.annotation_subject.is_none() && filter.annotation_tag.is_none() {
            return Ok(());
        }
        filter.validate()?;
        let visible = self
            .annotations(
                filter.annotation_subject.clone(),
                filter.annotation_tag.clone(),
            )
            .await?;
        let records = visible["records"]
            .as_array()
            .ok_or(Failure::Corrupt)?
            .clone();
        let reader = self
            .proof
            .get(&target.source)
            .ok_or(Failure::AccessLimited)?
            .clone();
        let selected = reader.clone();
        let source = target.source.clone();
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let coordinates = tokio::task::spawn_blocking(move || -> Result<_, Failure> {
            let _permit = permit;
            let mut coordinates = std::collections::BTreeSet::new();
            for record in records {
                let draft: super::knowledge::Draft =
                    serde_json::from_value(record["draft"].clone())
                        .map_err(|_| Failure::Corrupt)?;
                for cite in draft.cites.iter().filter(|c| c.source == source) {
                    let c = selected.citation_coordinate(&cite.selection)?;
                    coordinates.insert((c.through, c.manifest, c.attestation));
                }
            }
            Ok(coordinates)
        })
        .await
        .map_err(|_| Failure::Unavailable)??;
        let matches = |record: &Value| {
            coordinates.contains(&(
                record["sequence"].as_str().unwrap_or("").to_owned(),
                record["manifest"].as_str().map(str::to_owned),
                record["attestation"].as_str().map(str::to_owned),
            ))
        };
        value["hits"]
            .as_array_mut()
            .ok_or(Failure::Corrupt)?
            .retain(|hit| {
                matches(&hit["record"])
                    || hit["cites"]
                        .as_array()
                        .is_some_and(|cites| cites.iter().any(|c| matches(&c["record"])))
            });
        // Repeat the current authorization check after resolving annotation visibility.
        reader.page(&target.pin, None, 1).await?;
        value["annotation_filter"] = json!({"subject":filter.annotation_subject,"tag":filter.annotation_tag,"coverage":visible["coverage"],"basis":"Currently authorized annotation history, including corrections and withdrawn assertions. At least one cited occurrence must match. Corpus facets and attempt reconstruction coverage are independent of this filter; saved views re-evaluate current annotations."});
        Ok(())
    }
}
