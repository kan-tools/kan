//! Authorized, disposable Content inspection. No archive discovery or plaintext store.
use crate::{
    evidence_assembly as assembly,
    evidence_capture::{Observer, Outcome},
    evidence_interpretation as provider,
    evidence_reader::{Acquired, Pin, Reader, PAGE_LIMIT},
    evidence_service::{self as service, Failure},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const VERSION: &str = "kan-content/2";
const INPUT: usize = 8 * 1024 * 1024;
const SCAN: u64 = 64 * 1024 * 1024;
const OUTPUT: usize = 4 * 1024 * 1024;
const ITEMS: usize = 1024;
const CITATIONS: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(20);
#[derive(Clone, Copy)]
struct Presentation {
    duration: Duration,
    occurrences: usize,
    input: usize,
    output: usize,
    scan: u64,
    items: usize,
    citations: usize,
}
const SELECTED: Presentation = Presentation {
    duration: DEADLINE,
    occurrences: PAGE_LIMIT,
    input: INPUT,
    output: OUTPUT,
    scan: SCAN,
    items: ITEMS,
    citations: CITATIONS,
};
const ATTEMPT: Presentation = Presentation {
    duration: Duration::from_secs(120),
    occurrences: 1024,
    input: 40 * 1024 * 1024,
    output: 96 * 1024 * 1024,
    scan: 512 * 1024 * 1024,
    items: 4096,
    citations: 32768,
};

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    AnthropicMessagesJson,
    AnthropicMessagesSse,
}
/// Canonical decimal coordinates only: no floating point or alternate spellings.
pub fn coordinate(s: &str) -> Result<u64, Failure> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(Failure::Invalid);
    }
    s.parse().map_err(|_| Failure::Invalid)
}
pub fn pin(wire: &str) -> Result<Pin, Failure> {
    if wire.len() > 12000 {
        return Err(Failure::Invalid);
    }
    serde_json::from_str(wire).map_err(|_| Failure::Invalid)
}
pub fn pin_wire(pin: &Pin) -> Result<String, Failure> {
    serde_json::to_string(pin).map_err(|_| Failure::Invalid)
}
pub fn occurrence(row: &crate::evidence_reader::Occurrence) -> Value {
    json!({"sequence":row.sequence.to_string(),"manifest":row.manifest,"receipt":row.receipt})
}
/// All new public coordinates remain strings, including Source-return navigation.
pub fn source(value: crate::evidence_reader::Source) -> Value {
    json!({"scope":value.scope,"record":occurrence(&value.record),"writer":value.writer,
        "service_issuer":value.service_issuer,"signature":value.signature,"admission":value.admission,
        "content_trust":value.content_trust,"total_bytes":value.total_bytes.to_string(),
        "offset":value.offset.to_string(),"next":value.next.map(|v|v.to_string()),
        "bytes_hex":value.bytes_hex,"utf8":value.utf8})
}
/// Presentation outcomes are separate from evidence verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContentError {
    Read(Failure),
    Limited,
    Busy,
}
impl From<Failure> for ContentError {
    fn from(value: Failure) -> Self {
        Self::Read(value)
    }
}
impl ContentError {
    fn compatible(self) -> Failure {
        match self {
            Self::Read(f) => f,
            Self::Limited | Self::Busy => Failure::Unavailable,
        }
    }
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
impl Reader {
    /// Every selected occurrence is fully acquired or the whole operation refuses.
    /// Dropping this future cancels borrowed reads and signals the bounded worker.
    pub async fn content(
        &self,
        pin: &Pin,
        sequences: &[String],
        format: Format,
    ) -> Result<Vec<u8>, Failure> {
        self.content_detailed(pin, sequences, format)
            .await
            .map_err(ContentError::compatible)
    }
    pub(crate) async fn content_detailed(
        &self,
        pin: &Pin,
        sequences: &[String],
        format: Format,
    ) -> Result<Vec<u8>, ContentError> {
        self.content_observed(pin, sequences, format, || {}, || std::future::ready(()))
            .await
    }
    async fn content_observed<F: std::future::Future<Output = ()> + Send>(
        &self,
        pin: &Pin,
        sequences: &[String],
        format: Format,
        after_item: impl FnMut() + Send + 'static,
        mut after_acquired: impl FnMut() -> F + Send,
    ) -> Result<Vec<u8>, ContentError> {
        if sequences.is_empty() || sequences.len() > PAGE_LIMIT {
            return Err(Failure::Invalid.into());
        }
        let sequences: Vec<_> = sequences
            .iter()
            .map(|s| coordinate(s))
            .collect::<Result<_, _>>()?;
        if sequences.contains(&0)
            || sequences.iter().collect::<BTreeSet<_>>().len() != sequences.len()
        {
            return Err(Failure::Invalid.into());
        }
        // Owned by worker, not the cancelled connection. No queue of abandoned jobs.
        let permit = self
            .content_workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| ContentError::Busy)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(cancelled.clone());
        let deadline = Instant::now() + DEADLINE;
        let work = async {
            let mut acquired = Vec::new();
            let mut bytes = 0usize;
            for sequence in &sequences {
                let row = self.acquire(pin, *sequence).await?;
                after_acquired().await;
                bytes = bytes
                    .checked_add(row.plaintext.len())
                    .ok_or(ContentError::Limited)?;
                if bytes > INPUT {
                    return Err(ContentError::Limited);
                }
                acquired.push(row);
            }
            let wire = pin_wire(pin)?;
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                render(acquired, wire, format, cancelled, deadline, after_item)
            })
            .await
            .map_err(|_| ContentError::Limited)?
            .map_err(|e| {
                if e == Failure::Unavailable {
                    ContentError::Limited
                } else {
                    ContentError::Read(e)
                }
            })?;
            // A pin is not a current grant. Check again after interpretation.
            self.page(pin, sequences[0] - 1, 1).await?;
            Ok(result)
        };
        tokio::time::timeout(DEADLINE, work)
            .await
            .map_err(|_| ContentError::Limited)?
    }
}
/// The same interpreter over metadata-verified proof selections, preserving loss.
pub(crate) async fn proof_content(
    reader: &crate::evidence_reader::proof::Reader,
    pin: &crate::evidence_reader::proof::Pin,
    selections: &[crate::evidence_reader::proof::Token],
    format: Format,
    workers: Arc<tokio::sync::Semaphore>,
    attempt: bool,
) -> Result<Vec<u8>, ContentError> {
    use crate::evidence_reader::proof::Source;
    let presentation = if attempt { ATTEMPT } else { SELECTED };
    if selections.is_empty() || selections.len() > presentation.occurrences {
        return Err(Failure::Invalid.into());
    }
    let permit = workers
        .try_acquire_many_owned(if attempt { 2 } else { 1 })
        .map_err(|_| ContentError::Busy)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = Cancel(cancelled.clone());
    let deadline = Instant::now() + presentation.duration;
    let work = async {
        let mut selected = Vec::new();
        let mut bytes = 0usize;
        let mut seen = BTreeSet::new();
        let mut identity = None;
        let scope = reader.binding().owner_binding()?.scope;
        let mut offset = 0;
        while offset < selections.len() {
            let end =
                (offset + crate::evidence_proof_service::READ_BATCH_LIMIT).min(selections.len());
            let sources = reader.sources_prefix(pin, &selections[offset..end]).await?;
            offset += sources.len();
            for source in sources {
                let (record, writer, payload) = match source {
                    Source::Available {
                        record,
                        writer,
                        plaintext,
                    } => (record, Some(writer), Ok(plaintext)),
                    Source::Missing { record } => {
                        (record, None, Err(assembly::Unavailable::Missing))
                    }
                    Source::Corrupt { record } => {
                        (record, None, Err(assembly::Unavailable::Corrupt))
                    }
                };
                if !seen.insert(record.sequence.clone()) {
                    return Err(Failure::Invalid.into());
                }
                let length = payload.as_ref().ok().map(Vec::len);
                bytes = bytes
                    .checked_add(length.unwrap_or(0))
                    .ok_or(ContentError::Limited)?;
                if bytes > presentation.input {
                    return Err(ContentError::Limited);
                }
                if attempt {
                    if let Ok(bytes) = &payload {
                        let crate::evidence_reconstruction::Decoded::Capture(frame) =
                            crate::evidence_reconstruction::decode(bytes)
                                .map_err(|_| Failure::Invalid)?
                        else {
                            return Err(Failure::Invalid.into());
                        };
                        let key = (writer.clone(), frame.header.observer, frame.header.attempt);
                        if identity.as_ref().is_some_and(|previous| previous != &key) {
                            return Err(Failure::Invalid.into());
                        }
                        identity = Some(key);
                    }
                }
                let metadata = json!({"scope":reader.binding().scope,"archive":reader.binding().archive,
                "record":record,"writer":writer,"service_issuer":reader.binding().issuer,
                "total_bytes":length.map(|n|n.to_string())});
                selected.push(Selected {
                    scope,
                    writer,
                    payload,
                    metadata,
                });
            }
        }
        let wire = serde_json::to_string(pin).map_err(|_| Failure::Invalid)?;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            render_selected(
                selected,
                wire,
                format,
                cancelled,
                deadline,
                presentation,
                || {},
            )
        })
        .await
        .map_err(|_| ContentError::Limited)?
        .map_err(|e| {
            if e == Failure::Unavailable {
                ContentError::Limited
            } else {
                ContentError::Read(e)
            }
        })?;
        // Fresh service request: a historical selection token is never a grant.
        reader.page(pin, None, 1).await?;
        Ok(result)
    };
    tokio::time::timeout(presentation.duration, work)
        .await
        .map_err(|_| ContentError::Limited)?
}
struct Budget {
    presentation: Presentation,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    scan: u64,
    output: u64,
    items: usize,
    citations: usize,
}
impl Budget {
    fn check(&self) -> Result<Duration, Failure> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Failure::Unavailable);
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Failure::Unavailable)
    }
    fn limits(&self) -> Result<provider::Limits, Failure> {
        Ok(provider::Limits {
            input_bytes: self.presentation.input,
            items: self.items,
            output_bytes: self.output,
            scan_bytes: self.scan,
            citations: self.citations,
            duration: self.check()?,
            cancelled: self.cancelled.clone(),
        })
    }
    fn charge_scan(&mut self, n: u64) -> Result<(), Failure> {
        self.check()?;
        self.scan = self.scan.checked_sub(n).ok_or(Failure::Unavailable)?;
        Ok(())
    }
}
fn pair(a: impl ToString, b: impl ToString) -> Value {
    json!([a.to_string(), b.to_string()])
}
fn stream_issue(i: &assembly::StreamIssue) -> Value {
    use assembly::StreamIssue::*;
    match i {
        Gap(r) => json!({"kind":"gap","bytes":pair(r.start,r.end)}),
        OffsetOverflow { input } => json!({"kind":"offset-overflow","input":input.to_string()}),
        Overlap { input } => json!({"kind":"overlap","input":input.to_string()}),
        BeyondExtent { input } => json!({"kind":"beyond-extent","input":input.to_string()}),
        ChunkAfterEnd { input } => json!({"kind":"chunk-after-end","input":input.to_string()}),
        ConflictingExtents => json!({"kind":"conflicting-extents"}),
        OrdinalConflict => json!({"kind":"ordinal-conflict"}),
    }
}
fn item_kind(k: provider::Kind) -> &'static str {
    use provider::Kind::*;
    match k {
        Context => "context",
        System => "system",
        Text => "text",
        ToolUse => "tool-use",
        ToolResult => "tool-result",
        Thinking => "thinking",
        Attachment => "attachment",
        ToolFragment => "tool-fragment",
        Protocol => "protocol",
        Framing => "framing",
        Error => "error",
        Unsupported => "unsupported",
        Malformed => "malformed",
        Truncated => "truncated",
    }
}
fn issue_kind(i: provider::Issue) -> &'static str {
    use provider::Issue::*;
    match i {
        Shape => "shape",
        EventName => "event-name",
        Sequence => "sequence",
        BlockIndex => "block-index",
        DeltaType => "delta-type",
        ToolJson => "tool-json",
        Unknown => "unknown",
    }
}
fn map_citations(
    mapping: &provider::ValidatedMapping<'_, '_>,
    region: std::ops::Range<usize>,
    budget: &mut Budget,
) -> Result<Vec<Value>, Failure> {
    let mut limits = budget.limits()?;
    limits.items = 2 * budget.presentation.occurrences;
    let citations = mapping.map(region, limits).map_err(|e| match e {
        provider::Error::Mapping => Failure::Corrupt,
        _ => Failure::Unavailable,
    })?;
    budget.citations = budget
        .citations
        .checked_sub(citations.len())
        .ok_or(Failure::Unavailable)?;
    Ok(citations
        .into_iter()
        .map(|s| json!({"input":s.input.to_string(),"bytes":pair(s.bytes.start,s.bytes.end)}))
        .collect())
}

#[derive(Default)]
struct CitationSets {
    regions: BTreeMap<(usize, usize), usize>,
    values: Vec<Vec<Value>>,
}
impl CitationSets {
    fn reference(
        &mut self,
        mapping: &provider::ValidatedMapping<'_, '_>,
        region: std::ops::Range<usize>,
        budget: &mut Budget,
    ) -> Result<String, Failure> {
        budget.check()?;
        let key = (region.start, region.end);
        if let Some(index) = self.regions.get(&key) {
            return Ok(index.to_string());
        }
        // One immutable validated stream: identical regions have identical
        // exact source mappings. Charge and serialize each set only once.
        let citations = map_citations(mapping, region, budget)?;
        let index = self.values.len();
        self.values.push(citations);
        self.regions.insert(key, index);
        Ok(index.to_string())
    }
}

fn stream(
    stream: &assembly::Stream,
    inputs: &[assembly::Input<'_>],
    format: provider::Format,
    budget: &mut Budget,
    after_item: &mut impl FnMut(),
) -> Result<Value, Failure> {
    budget.check()?;
    let mut result = json!({"expected_bytes":stream.expected_bytes.map(|n|n.to_string()),
        "extent_claims":stream.extents.iter().map(|(i,n)|json!({"input":i.to_string(),"bytes":n.to_string()})).collect::<Vec<_>>(),
        "issues":stream.issues.iter().map(stream_issue).collect::<Vec<_>>(),
        "observed_bytes":stream.contiguous.as_ref().map(|b|b.len().to_string()),
        "state":"unavailable","items":[],"citation_sets":[],"parsed_json":null,"coherent_stop_observed":false});
    let Some(bytes) = stream.contiguous.as_deref() else {
        return Ok(result);
    };
    if !stream.issues.is_empty()
        || stream
            .expected_bytes
            .is_some_and(|n| n != bytes.len() as u64)
    {
        return Ok(result);
    }
    let document =
        provider::interpret(bytes, format, budget.limits()?).map_err(|_| Failure::Unavailable)?;
    budget.charge_scan(document.scanned_bytes)?;
    budget.output = budget
        .output
        .checked_sub(document.output_bytes)
        .ok_or(Failure::Unavailable)?;
    budget.items = budget
        .items
        .checked_sub(document.items.len())
        .ok_or(Failure::Unavailable)?;
    let mut mapping_limits = budget.limits()?;
    mapping_limits.items = 2 * budget.presentation.occurrences;
    let mapping =
        provider::validate_mapping(stream, inputs, mapping_limits).map_err(|e| match e {
            provider::Error::Mapping => Failure::Corrupt,
            _ => Failure::Unavailable,
        })?;
    budget.charge_scan(mapping.scanned_bytes)?;
    let mut items = Vec::new();
    let mut citation_sets = CitationSets::default();
    for item in document.items {
        let citation_set = citation_sets.reference(&mapping, item.region.clone(), budget)?;
        let tool = match (item.tool_input, item.tool_region) {
            (Some(json), Some(region)) => {
                let citation_set = citation_sets.reference(&mapping, region.clone(), budget)?;
                json!({"json":json,"region":pair(region.start,region.end),"citation_set":citation_set})
            }
            (None, None) => Value::Null,
            _ => return Err(Failure::Corrupt),
        };
        items.push(json!({"kind":item_kind(item.kind),"region":pair(item.region.start,item.region.end),"coarse":item.coarse,
            "role":item.role,"index":item.index.map(|n|n.to_string()),"text":item.text,"pointer":item.pointer,
            "event_json":item.event.map(|v|v.to_string()),"issues":item.issues.into_iter().map(issue_kind).collect::<Vec<_>>(),"citation_set":citation_set,"tool":tool}));
        after_item();
        budget.check()?;
    }
    result["state"] = json!("interpreted");
    result["items"] = json!(items);
    result["citation_sets"] = json!(citation_sets.values);
    result["parsed_json"] = json!(document.json.map(|v| v.to_string()));
    result["coherent_stop_observed"] = json!(document.coherent_stop_observed);
    Ok(result)
}
struct Selected {
    scope: [u8; 32],
    writer: Option<String>,
    payload: Result<Vec<u8>, assembly::Unavailable>,
    metadata: Value,
}
fn render(
    acquired: Vec<Acquired>,
    pin_wire: String,
    format: Format,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    after_item: impl FnMut(),
) -> Result<Vec<u8>, Failure> {
    let selected = acquired.into_iter().map(|a| {
        let metadata = json!({"scope":service::hex(&a.scope),"record":occurrence(&a.record),"writer":a.writer,"service_issuer":a.service_issuer,"total_bytes":a.plaintext.len().to_string()});
        Selected { scope:a.scope, writer:Some(a.writer), payload:Ok(a.plaintext), metadata }
    }).collect();
    render_selected(
        selected, pin_wire, format, cancelled, deadline, SELECTED, after_item,
    )
}
fn render_selected(
    selected: Vec<Selected>,
    pin_wire: String,
    format: Format,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    presentation: Presentation,
    mut after_item: impl FnMut(),
) -> Result<Vec<u8>, Failure> {
    let mut budget = Budget {
        presentation,
        deadline,
        cancelled,
        scan: presentation.scan,
        output: presentation.output as u64,
        items: presentation.items,
        citations: presentation.citations,
    };
    let inputs: Vec<_> = selected
        .iter()
        .map(|a| assembly::Input {
            scope: a.scope,
            writer: a.writer.as_deref().unwrap_or(""),
            payload: match &a.payload {
                Ok(bytes) => assembly::Payload::Available(bytes),
                Err(reason) => assembly::Payload::Unavailable(*reason),
            },
        })
        .collect();
    let assembled = assembly::assemble(
        &inputs,
        assembly::Limits {
            occurrences: presentation.occurrences,
            input_bytes: (presentation.input + presentation.occurrences * 1024) as u64,
            scan_bytes: budget.scan,
            assembled_bytes: presentation.input as u64,
            duration: budget.check()?,
            cancelled: budget.cancelled.clone(),
        },
    )
    .map_err(|_| Failure::Unavailable)?;
    budget.charge_scan(assembled.scanned_bytes)?;
    let observations: Vec<_> = assembled
        .observations
        .iter()
        .enumerate()
        .map(|(i, o)| {
            use assembly::Observation::*;
            let (kind, reason, ordinal) = match o {
                Capture(f) => ("capture", None, Some(f.header.ordinal.to_string())),
                Opaque => ("opaque", None, None),
                Unsupported(v) => ("unsupported", Some(format!("{v:?}")), None),
                Malformed(v) => ("malformed", Some(format!("{v:?}")), None),
                Unavailable(v) => ("unavailable", Some(format!("{v:?}")), None),
            };
            json!({"input":i.to_string(),"kind":kind,"reason":reason,"ordinal":ordinal})
        })
        .collect();
    let mut groups = Vec::new();
    for group in &assembled.groups {
        budget.check()?;
        let response_format = match format {
            Format::AnthropicMessagesJson => provider::Format::Response,
            Format::AnthropicMessagesSse => provider::Format::Sse,
        };
        let request = stream(
            &group.request,
            &inputs,
            provider::Format::Request,
            &mut budget,
            &mut after_item,
        )?;
        let response = stream(
            &group.response,
            &inputs,
            response_format,
            &mut budget,
            &mut after_item,
        )?;
        groups.push(json!({"scope":service::hex(&group.scope),"writer":group.writer,"observer":match group.observer {Observer::Collector=>"collector",Observer::Gateway=>"gateway"},
            "attempt":group.attempt,"ordinals":group.ordinals.iter().map(|o|json!({"value":o.value.to_string(),"inputs":o.inputs.iter().map(|i|i.to_string()).collect::<Vec<_>>(),"conflict":o.conflict})).collect::<Vec<_>>(),
            "ordinal_gaps":group.ordinal_gaps.iter().map(|r|pair(r.start,r.end)).collect::<Vec<_>>(),
            "missing_start":group.missing_start,"unexpected_starts":group.unexpected_starts.iter().map(|i|i.to_string()).collect::<Vec<_>>(),
            "terminal":match group.terminal {assembly::Terminal::Unknown=>"unknown",assembly::Terminal::Conflicting=>"conflicting",assembly::Terminal::Claimed(Outcome::Completed)=>"claimed-completed",assembly::Terminal::Claimed(Outcome::OutcomeUnknown)=>"claimed-unknown"},
            "events_after_terminal":group.events_after_terminal,"unconfirmed_claim":group.unconfirmed_claim,
            "request":request,"response":response}));
    }
    let occurrences: Vec<_> = selected.iter().map(|a| &a.metadata).collect();
    let value = json!({"version":VERSION,"assembly_version":assembly::VERSION,"adapter_version":provider::VERSION,
        "pin_wire":pin_wire,"occurrences":occurrences,"observations":observations,"groups":groups,
        "coverage":"explicit selection only; ordinal gaps mean no recognized capture, not absent inputs; protocol claims do not prove complete capture",
        "scan_bytes":(presentation.scan-budget.scan).to_string()});
    bounded_json(&value, presentation.output, &budget)
}
struct BoundedWriter<'a> {
    bytes: Vec<u8>,
    limit: usize,
    budget: &'a Budget,
}
impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.budget
            .check()
            .map_err(|_| io::Error::other("content cancelled or timed out"))?;
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("content output limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize, limit: usize, budget: &Budget) -> Result<Vec<u8>, Failure> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit,
        budget,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| Failure::Unavailable)?;
    budget.check()?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> Budget {
        Budget {
            presentation: SELECTED,
            deadline: Instant::now() + Duration::from_secs(5),
            cancelled: Arc::new(AtomicBool::new(false)),
            scan: SCAN,
            output: OUTPUT as u64,
            items: ITEMS,
            citations: CITATIONS,
        }
    }
    #[test]
    fn canonical_decimal_and_new_source_coordinates_preserve_full_width() {
        for value in [0, 9007199254740993, u64::MAX] {
            assert_eq!(coordinate(&value.to_string()).unwrap(), value);
        }
        for s in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            "1.0",
            "1e0",
            " 1",
            "1 ",
            "18446744073709551616",
            "９",
        ] {
            assert_eq!(coordinate(s), Err(Failure::Invalid));
        }
        let row = crate::evidence_reader::Occurrence {
            sequence: u64::MAX,
            manifest: "m".into(),
            receipt: "r".into(),
        };
        assert_eq!(occurrence(&row)["sequence"], "18446744073709551615");
    }
    #[test]
    fn serialized_byte_limit_and_cancellation_refuse_without_partial_output() {
        let b = budget();
        let v = json!("☃");
        assert_eq!(bounded_json(&v, 5, &b).unwrap(), b"\"\xe2\x98\x83\"");
        assert_eq!(bounded_json(&v, 4, &b), Err(Failure::Unavailable));
        b.cancelled.store(true, Ordering::Relaxed);
        assert_eq!(bounded_json(&v, 100, &b), Err(Failure::Unavailable));
    }
    #[test]
    fn aggregate_work_is_charged_across_interpretation_and_all_item_mappings() {
        let body =
            br#"{"type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}"#;
        let h=serde_json::to_vec(&json!({"version":2,"attempt":"1".repeat(64),"observer":"collector","ordinal":0,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"response-chunk","offset":0}})).unwrap();
        let mut raw = b"KANC2".to_vec();
        raw.extend((h.len() as u32).to_be_bytes());
        raw.extend(h);
        raw.extend(body);
        let inputs = [assembly::Input {
            scope: [1; 32],
            writer: "writer",
            payload: assembly::Payload::Available(&raw),
        }];
        let b = budget();
        let assembled = assembly::assemble(
            &inputs,
            assembly::Limits {
                occurrences: 1,
                input_bytes: 10000,
                scan_bytes: 10000,
                assembled_bytes: 10000,
                duration: b.check().unwrap(),
                cancelled: b.cancelled.clone(),
            },
        )
        .unwrap();
        let stream_data = &assembled.groups[0].response;
        // One JSON parse; source correspondence is validated once for all items.
        let exact = body.len() as u64 + (raw.len() + body.len()) as u64;
        let mut b = budget();
        b.scan = exact;
        let value = stream(
            stream_data,
            &inputs,
            provider::Format::Response,
            &mut b,
            &mut || {},
        )
        .unwrap();
        assert_eq!(value["items"].as_array().unwrap().len(), 2);
        assert_eq!(b.scan, 0);
        assert_eq!(
            stream(
                stream_data,
                &inputs,
                provider::Format::Response,
                &mut b,
                &mut || {}
            )
            .unwrap_err(),
            Failure::Unavailable
        );
        let mut b = budget();
        b.scan = exact - 1;
        assert_eq!(
            stream(
                stream_data,
                &inputs,
                provider::Format::Response,
                &mut b,
                &mut || {}
            )
            .unwrap_err(),
            Failure::Unavailable
        );
        // Independent limits must accumulate across separately interpreted streams.
        let mut b = budget();
        b.items = 3;
        stream(
            stream_data,
            &inputs,
            provider::Format::Response,
            &mut b,
            &mut || {},
        )
        .unwrap();
        assert_eq!(b.items, 1);
        assert_eq!(
            stream(
                stream_data,
                &inputs,
                provider::Format::Response,
                &mut b,
                &mut || {}
            )
            .unwrap_err(),
            Failure::Unavailable
        );
        let mut b = budget();
        b.citations = 1;
        stream(
            stream_data,
            &inputs,
            provider::Format::Response,
            &mut b,
            &mut || {},
        )
        .unwrap();
        assert_eq!(b.citations, 0);
        assert_eq!(
            stream(
                stream_data,
                &inputs,
                provider::Format::Response,
                &mut b,
                &mut || {}
            )
            .unwrap_err(),
            Failure::Unavailable
        );
        let mut b = budget();
        let expected = provider::interpret(body, provider::Format::Response, b.limits().unwrap())
            .unwrap()
            .output_bytes;
        b.output = 2 * expected - 1;
        stream(
            stream_data,
            &inputs,
            provider::Format::Response,
            &mut b,
            &mut || {},
        )
        .unwrap();
        assert_eq!(b.output, expected - 1);
        assert_eq!(
            stream(
                stream_data,
                &inputs,
                provider::Format::Response,
                &mut b,
                &mut || {}
            )
            .unwrap_err(),
            Failure::Unavailable
        );
        b.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(b.check(), Err(Failure::Unavailable));
    }
    #[test]
    fn serialized_content_cap_is_independent_of_normalized_output() {
        let body=serde_json::to_vec(&json!({"messages":(0..60).map(|_|json!({"role":"user","content":"x".repeat(34800)})).collect::<Vec<_>>()})).unwrap();
        let b = budget();
        let parsed =
            provider::interpret(&body, provider::Format::Request, b.limits().unwrap()).unwrap();
        assert!(parsed.output_bytes < OUTPUT as u64);
        assert_eq!(parsed.items.len(), 121);
        let acquired=body.chunks(65536).enumerate().map(|(n,chunk)|{
            let header=serde_json::to_vec(&json!({"version":2,"attempt":"8".repeat(64),"observer":"collector","ordinal":n,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"request-chunk","offset":n*65536}})).unwrap();
            let mut raw=b"KANC2".to_vec();raw.extend((header.len() as u32).to_be_bytes());raw.extend(header);raw.extend(chunk);
            Acquired{scope:[1;32],record:crate::evidence_reader::Occurrence{sequence:n as u64+1,manifest:"m".into(),receipt:"r".into()},writer:"synthetic-writer".into(),service_issuer:"synthetic-issuer".into(),plaintext:raw}
        }).collect();
        let mut seen = 0;
        let result = render(
            acquired,
            "opaque-pin".into(),
            Format::AnthropicMessagesJson,
            b.cancelled,
            b.deadline,
            || {
                seen += 1;
            },
        );
        assert_eq!(
            seen, 121,
            "normalization must finish before the serialization refusal"
        );
        assert!(
            matches!(result, Err(Failure::Unavailable)),
            "serialized response must refuse after normalization"
        );
    }
    #[test]
    fn dropping_request_guard_signals_the_worker() {
        let b = budget();
        let guard = Cancel(b.cancelled.clone());
        assert!(b.check().is_ok());
        drop(guard);
        assert_eq!(b.check(), Err(Failure::Unavailable));
    }
}

#[cfg(test)]
#[path = "../tests/support/content_worker_unit.rs"]
mod worker_tests;
