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
}
impl Filter {
    pub fn validate(&self) -> Result<(), Failure> {
        if self.text.len() > 256
            || self.text.trim().is_empty()
            || self.writer.as_ref().is_some_and(|s| s.len() > 256)
            || self.kind.as_ref().is_some_and(|s| s.len() > 64)
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Span {
    offset: usize,
    text: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    record: Occurrence,
    writer: Option<String>,
    kind: String,
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
        } => (record, Some(writer), Some(plaintext), "opaque"),
        Source::Missing { record } => (record, None, None, "missing"),
        Source::Corrupt { record } => (record, None, None, "corrupt"),
    };
    let mut d = Document {
        record,
        writer,
        kind: kind.into(),
        spans: Vec::new(),
        unsearchable_bytes: 0,
    };
    if let Some(bytes) = plaintext {
        let mut add = |offset: usize, b: &[u8]| {
            if let Ok(text) = std::str::from_utf8(b) {
                d.spans.push(Span {
                    offset,
                    text: text.into(),
                });
            } else {
                d.unsearchable_bytes += b.len();
            }
        };
        match evidence_reconstruction::decode(&bytes) {
            Ok(Decoded::Capture(frame)) => {
                d.kind = "capture".into();
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
            _ => add(0, &bytes),
        }
    }
    d
}
fn key(target: &Target, cursor: Option<&Token>) -> Result<String, Failure> {
    serde_json::to_string(&("raw-text/1", target, cursor)).map_err(|_| Failure::Invalid)
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
    for d in &page.documents {
        *facets.entry(d.kind.clone()).or_default() += 1;
        if let Some(w) = &d.writer {
            *writers.entry(w.clone()).or_default() += 1;
        }
    }
    json!({"indexed_occurrences":page.documents.len(),"indexed_at":page.indexed_at.to_string(),"next":page.next,"facets_as_indexed":{"kind":facets,"writer":writers},"unsearchable_bytes":page.documents.iter().map(|d|d.unsearchable_bytes).sum::<usize>().to_string(),"coverage":"This pinned index page only. Missing/corrupt sources, binary spans and text crossing capture chunks are not searchable. A complete scan does not prove complete capture."})
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
            version: 1,
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
fn matching(d: &Document, filter: &Filter) -> Option<(usize, usize, String)> {
    if filter
        .writer
        .as_ref()
        .is_some_and(|w| Some(w) != d.writer.as_ref())
        || filter.kind.as_ref().is_some_and(|k| k != &d.kind)
    {
        return None;
    }
    let query = filter.text.to_ascii_lowercase();
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
                span.offset + at,
                span.offset + end,
                span.text[lo..hi].into(),
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
        if page.version!=1 || page.documents.len()>8 {return Err(Failure::Corrupt.into());}
        let mut hits=Vec::new();let mut unavailable=0;
        for d in &page.documents {if matching(d,filter).is_some() {
            let current=doc(reader.source(&target.pin,&d.record.selection).await?);
            if matches!(current.kind.as_str(),"missing"|"corrupt") {unavailable+=1;continue;}
            if let Some((start,end,snippet))=matching(&current,filter) {hits.push(json!({"record":current.record,"writer":current.writer,"kind":current.kind,"offset":start.to_string(),"end":end.to_string(),"snippet":snippet}));}
        }}
        reader.page(&target.pin,None,1).await?;
        let mut value=status(&page);value["state"]=json!("indexed");value["hits"]=json!(hits);value["unavailable_matches"]=json!(unavailable);Ok(value)
    }).await.map_err(|_|ContentError::Limited)?
}
