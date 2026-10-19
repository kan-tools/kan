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
    collections::BTreeSet,
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const VERSION: &str = "kan-content/1";
const INPUT: usize = 8 * 1024 * 1024;
const SCAN: u64 = 64 * 1024 * 1024;
const OUTPUT: usize = 4 * 1024 * 1024;
const ITEMS: usize = 1024;
const CITATIONS: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(20);

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
        if sequences.is_empty() || sequences.len() > PAGE_LIMIT {
            return Err(Failure::Invalid);
        }
        let sequences: Vec<_> = sequences
            .iter()
            .map(|s| coordinate(s))
            .collect::<Result<_, _>>()?;
        if sequences.contains(&0)
            || sequences.iter().collect::<BTreeSet<_>>().len() != sequences.len()
        {
            return Err(Failure::Invalid);
        }
        // Owned by worker, not the cancelled connection. No queue of abandoned jobs.
        let permit = self
            .content_workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(cancelled.clone());
        let deadline = Instant::now() + DEADLINE;
        let work = async {
            let mut acquired = Vec::new();
            let mut bytes = 0usize;
            for sequence in &sequences {
                let row = self.acquire(pin, *sequence).await?;
                bytes = bytes
                    .checked_add(row.plaintext.len())
                    .ok_or(Failure::Unavailable)?;
                if bytes > INPUT {
                    return Err(Failure::Unavailable);
                }
                acquired.push(row);
            }
            let wire = pin_wire(pin)?;
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                render(acquired, wire, format, cancelled, deadline)
            })
            .await
            .map_err(|_| Failure::Unavailable)??;
            // A pin is not a current grant. Check again after interpretation.
            self.page(pin, sequences[0] - 1, 1).await?;
            Ok(result)
        };
        tokio::time::timeout(DEADLINE, work)
            .await
            .map_err(|_| Failure::Unavailable)?
    }
}
struct Budget {
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
            input_bytes: INPUT,
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
    stream: &assembly::Stream,
    inputs: &[assembly::Input<'_>],
    region: std::ops::Range<usize>,
    budget: &mut Budget,
) -> Result<Vec<Value>, Failure> {
    // Full-source validation happens on every mapping. Account all passes
    // across calls, rather than resetting the request work budget per item.
    let mut charge = 0u64;
    for segment in &stream.segments {
        for (n, source) in segment.sources.iter().enumerate() {
            let assembly::Payload::Available(original) =
                inputs.get(source.input).ok_or(Failure::Corrupt)?.payload
            else {
                return Err(Failure::Corrupt);
            };
            charge = charge
                .checked_add(original.len() as u64)
                .and_then(|v| v.checked_add(source.bytes.len() as u64))
                .and_then(|v| v.checked_add(if n > 0 { original.len() as u64 } else { 0 }))
                .ok_or(Failure::Unavailable)?;
        }
    }
    let mut limits = budget.limits()?;
    limits.items = 2 * PAGE_LIMIT;
    budget.charge_scan(charge)?;
    let citations =
        provider::map_region(stream, inputs, region, limits).map_err(|_| Failure::Corrupt)?;
    budget.citations = budget
        .citations
        .checked_sub(citations.len())
        .ok_or(Failure::Unavailable)?;
    let citations: Vec<_> = citations
        .into_iter()
        .map(|s| json!({"input":s.input.to_string(),"bytes":pair(s.bytes.start,s.bytes.end)}))
        .collect();
    Ok(citations)
}
fn stream(
    stream: &assembly::Stream,
    inputs: &[assembly::Input<'_>],
    format: provider::Format,
    budget: &mut Budget,
) -> Result<Value, Failure> {
    budget.check()?;
    let mut result = json!({"expected_bytes":stream.expected_bytes.map(|n|n.to_string()),
        "extent_claims":stream.extents.iter().map(|(i,n)|json!({"input":i.to_string(),"bytes":n.to_string()})).collect::<Vec<_>>(),
        "issues":stream.issues.iter().map(stream_issue).collect::<Vec<_>>(),
        "observed_bytes":stream.contiguous.as_ref().map(|b|b.len().to_string()),
        "state":"unavailable","items":[],"parsed_json":null,"coherent_stop_observed":false});
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
    let mut items = Vec::new();
    for item in document.items {
        let citations = map_citations(stream, inputs, item.region.clone(), budget)?;
        let tool = match (item.tool_input, item.tool_region) {
            (Some(json), Some(region)) => {
                let citations = map_citations(stream, inputs, region.clone(), budget)?;
                json!({"json":json,"region":pair(region.start,region.end),"citations":citations})
            }
            (None, None) => Value::Null,
            _ => return Err(Failure::Corrupt),
        };
        items.push(json!({"kind":item_kind(item.kind),"region":pair(item.region.start,item.region.end),"coarse":item.coarse,
            "role":item.role,"index":item.index.map(|n|n.to_string()),"text":item.text,"pointer":item.pointer,
            "event_json":item.event.map(|v|v.to_string()),"issues":item.issues.into_iter().map(issue_kind).collect::<Vec<_>>(),"citations":citations,"tool":tool}));
    }
    result["state"] = json!("interpreted");
    result["items"] = json!(items);
    result["parsed_json"] = json!(document.json.map(|v| v.to_string()));
    result["coherent_stop_observed"] = json!(document.coherent_stop_observed);
    Ok(result)
}
fn render(
    acquired: Vec<Acquired>,
    pin_wire: String,
    format: Format,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    let mut budget = Budget {
        deadline,
        cancelled,
        scan: SCAN,
        output: OUTPUT as u64,
        items: ITEMS,
        citations: CITATIONS,
    };
    let inputs: Vec<_> = acquired
        .iter()
        .map(|a| assembly::Input {
            scope: a.scope,
            writer: &a.writer,
            payload: assembly::Payload::Available(&a.plaintext),
        })
        .collect();
    let assembled = assembly::assemble(
        &inputs,
        assembly::Limits {
            occurrences: PAGE_LIMIT,
            input_bytes: (INPUT + PAGE_LIMIT * 1024) as u64,
            scan_bytes: budget.scan,
            assembled_bytes: INPUT as u64,
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
        )?;
        let response = stream(&group.response, &inputs, response_format, &mut budget)?;
        groups.push(json!({"scope":service::hex(&group.scope),"writer":group.writer,"observer":match group.observer {Observer::Collector=>"collector",Observer::Gateway=>"gateway"},
            "attempt":group.attempt,"ordinals":group.ordinals.iter().map(|o|json!({"value":o.value.to_string(),"inputs":o.inputs.iter().map(|i|i.to_string()).collect::<Vec<_>>(),"conflict":o.conflict})).collect::<Vec<_>>(),
            "ordinal_gaps":group.ordinal_gaps.iter().map(|r|pair(r.start,r.end)).collect::<Vec<_>>(),
            "missing_start":group.missing_start,"unexpected_starts":group.unexpected_starts.iter().map(|i|i.to_string()).collect::<Vec<_>>(),
            "terminal":match group.terminal {assembly::Terminal::Unknown=>"unknown",assembly::Terminal::Conflicting=>"conflicting",assembly::Terminal::Claimed(Outcome::Completed)=>"claimed-completed",assembly::Terminal::Claimed(Outcome::OutcomeUnknown)=>"claimed-unknown"},
            "events_after_terminal":group.events_after_terminal,"unconfirmed_claim":group.unconfirmed_claim,
            "request":request,"response":response}));
    }
    let occurrences: Vec<_> = acquired.iter().map(|a|json!({"scope":service::hex(&a.scope),"record":occurrence(&a.record),"writer":a.writer,"service_issuer":a.service_issuer,"total_bytes":a.plaintext.len().to_string()})).collect();
    let value = json!({"version":VERSION,"assembly_version":assembly::VERSION,"adapter_version":provider::VERSION,
        "pin_wire":pin_wire,"occurrences":occurrences,"observations":observations,"groups":groups,
        "coverage":"explicit selection only; ordinal gaps mean no recognized capture, not absent inputs; protocol claims do not prove complete capture",
        "scan_bytes":(SCAN-budget.scan).to_string()});
    bounded_json(&value, OUTPUT, &budget)
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
        // One JSON parse; root and text each validate the original frame and body.
        let exact = body.len() as u64 + 2 * (raw.len() + body.len()) as u64;
        let mut b = budget();
        b.scan = exact;
        let value = stream(stream_data, &inputs, provider::Format::Response, &mut b).unwrap();
        assert_eq!(value["items"].as_array().unwrap().len(), 2);
        assert_eq!(b.scan, 0);
        assert_eq!(
            stream(stream_data, &inputs, provider::Format::Response, &mut b).unwrap_err(),
            Failure::Unavailable
        );
        let mut b = budget();
        b.scan = exact - 1;
        assert_eq!(
            stream(stream_data, &inputs, provider::Format::Response, &mut b).unwrap_err(),
            Failure::Unavailable
        );
        b.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(b.check(), Err(Failure::Unavailable));
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
