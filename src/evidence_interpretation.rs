//! Versioned, disposable provider interpretation of an explicitly selected body.
//! Provider roles and protocol outcomes are claims. No network, execution, grant
//! validation, persistence or capture-completeness certificate is provided.
use crate::{
    evidence_assembly::{Input, Payload, SourceSpan, Stream},
    evidence_capture::Event,
    evidence_reconstruction::{self as decode, Decoded, Unique},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const VERSION: &str = "kan-anthropic-messages/1";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Request,
    Response,
    Sse,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Context,
    System,
    Text,
    ToolUse,
    ToolResult,
    Thinking,
    Attachment,
    ToolFragment,
    Protocol,
    Error,
    Unsupported,
    Malformed,
    Truncated,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    Shape,
    EventName,
    Sequence,
    BlockIndex,
    DeltaType,
    ToolJson,
    Unknown,
}
#[derive(Debug)]
pub struct Item {
    pub kind: Kind,
    /// Enclosing assembled-body bytes, exclusive end. Semantic attribution is
    /// coarse: this is never claimed to be the exact JSON string token range.
    pub region: Range<usize>,
    pub coarse: bool,
    pub role: Option<String>,
    pub index: Option<u64>,
    pub text: Option<String>,
    /// Location in Document.json for non-streamed input; JSON pointer escaping
    /// is unnecessary because this adapter generates only fixed keys/indices.
    pub pointer: Option<String>,
    /// Complete event JSON, including fields this adapter does not interpret.
    pub event: Option<Value>,
    pub issues: Vec<Issue>,
}
#[derive(Debug)]
pub struct Document {
    pub format: Format,
    pub json: Option<Value>,
    pub items: Vec<Item>,
    /// A coherent protocol stop was observed, not complete traffic capture.
    /// False for request/JSON response: those have no SSE stop observation.
    pub coherent_stop_observed: bool,
    pub scanned_bytes: u64,
    pub output_bytes: u64,
}
#[derive(Clone)]
pub struct Limits {
    pub input_bytes: usize,
    pub items: usize,
    /// Cumulative encoded JSON and copied text/data bytes, not exact RSS.
    pub output_bytes: u64,
    /// SSE line acquisition, JSON parsing and source decode/comparison bytes.
    /// This is accounting for those passes, not every CPU instruction.
    pub scan_bytes: u64,
    pub citations: usize,
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("provider interpretation budget exhausted: {0}")]
    Limit(&'static str),
    #[error("provider interpretation cancelled")]
    Cancelled,
    #[error("invalid source mapping")]
    Mapping,
}
type Result<T> = std::result::Result<T, Error>;
struct Work {
    limits: Limits,
    deadline: Instant,
    scan: u64,
    output: u64,
    items: usize,
}
impl Work {
    fn new(limits: Limits) -> Result<Self> {
        if limits.duration.is_zero() || limits.duration > Duration::from_secs(3600) {
            return Err(Error::Limit("duration"));
        }
        let deadline = Instant::now()
            .checked_add(limits.duration)
            .ok_or(Error::Limit("duration"))?;
        let w = Self {
            limits,
            deadline,
            scan: 0,
            output: 0,
            items: 0,
        };
        w.check()?;
        Ok(w)
    }
    fn check(&self) -> Result<()> {
        if self.limits.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Limit("duration"));
        }
        Ok(())
    }
    fn scan(&mut self, n: usize) -> Result<()> {
        self.check()?;
        self.scan = self
            .scan
            .checked_add(n as u64)
            .ok_or(Error::Limit("scan bytes"))?;
        if self.scan > self.limits.scan_bytes {
            return Err(Error::Limit("scan bytes"));
        }
        Ok(())
    }
    fn output(&mut self, n: usize) -> Result<()> {
        self.check()?;
        self.output = self
            .output
            .checked_add(n as u64)
            .ok_or(Error::Limit("output bytes"))?;
        if self.output > self.limits.output_bytes {
            return Err(Error::Limit("output bytes"));
        }
        Ok(())
    }
    fn item(&mut self) -> Result<()> {
        self.check()?;
        self.items = self.items.checked_add(1).ok_or(Error::Limit("items"))?;
        if self.items > self.limits.items {
            return Err(Error::Limit("items"));
        }
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<String> {
        self.output(s.len())?;
        Ok(s.into())
    }
}
fn item(kind: Kind, region: Range<usize>) -> Item {
    Item {
        kind,
        region,
        coarse: true,
        role: None,
        index: None,
        text: None,
        pointer: None,
        event: None,
        issues: vec![],
    }
}
fn push(out: &mut Vec<Item>, value: Item, w: &mut Work) -> Result<()> {
    w.item()?;
    out.push(value);
    Ok(())
}
fn strict(bytes: &[u8], w: &mut Work) -> Result<Option<Value>> {
    // Input bounds precede allocation, serde's recursion limit remains enabled.
    w.scan(bytes.len())?;
    w.output(bytes.len())?;
    let parsed = serde_json::from_slice::<Unique>(bytes).ok().map(|u| u.0);
    w.check()?;
    Ok(parsed)
}
fn block(
    value: &Value,
    pointer: String,
    role: Option<&str>,
    region: Range<usize>,
    out: &mut Vec<Item>,
    w: &mut Work,
) -> Result<()> {
    let (kind, text) = if let Some(s) = value.as_str() {
        (Kind::Text, Some(s))
    } else {
        match value.get("type").and_then(Value::as_str) {
            Some("text") => (Kind::Text, value.get("text").and_then(Value::as_str)),
            Some("thinking") => (
                Kind::Thinking,
                value.get("thinking").and_then(Value::as_str),
            ),
            Some("redacted_thinking") => (Kind::Thinking, None),
            Some("tool_use" | "server_tool_use") => {
                (Kind::ToolUse, value.get("name").and_then(Value::as_str))
            }
            Some("tool_result") => (
                Kind::ToolResult,
                value.get("content").and_then(Value::as_str),
            ),
            Some("image" | "document") => (Kind::Attachment, None),
            Some(_) => (Kind::Unsupported, None),
            None => (Kind::Malformed, None),
        }
    };
    let mut i = item(kind, region);
    i.pointer = Some(w.string(&pointer)?);
    i.role = role.map(|s| w.string(s)).transpose()?;
    i.text = text.map(|s| w.string(s)).transpose()?;
    if matches!(kind, Kind::Text | Kind::ToolUse) && text.is_none() {
        i.kind = Kind::Malformed;
        i.issues.push(Issue::Shape);
    }
    if kind == Kind::Unsupported {
        i.issues.push(Issue::Unknown);
    }
    push(out, i, w)
}
fn content(
    value: &Value,
    pointer: &str,
    role: Option<&str>,
    region: Range<usize>,
    out: &mut Vec<Item>,
    w: &mut Work,
) -> Result<()> {
    if let Some(values) = value.as_array() {
        for (n, v) in values.iter().enumerate() {
            w.check()?;
            block(v, format!("{pointer}/{n}"), role, region.clone(), out, w)?;
        }
    } else {
        block(value, pointer.into(), role, region, out, w)?;
    }
    Ok(())
}
fn json_body(bytes: &[u8], format: Format, doc: &mut Document, w: &mut Work) -> Result<()> {
    let Some(value) = strict(bytes, w)? else {
        return push(&mut doc.items, item(Kind::Malformed, 0..bytes.len()), w);
    };
    let region = 0..bytes.len();
    if !value.is_object() {
        push(&mut doc.items, item(Kind::Malformed, region), w)?;
        doc.json = Some(value);
        return Ok(());
    }
    // Always expose the root, preserving unknown fields and empty contents.
    let mut root = item(Kind::Protocol, region.clone());
    root.pointer = Some(String::new());
    push(&mut doc.items, root, w)?;
    if format == Format::Request {
        if let Some(system) = value.get("system") {
            let mut i = item(Kind::System, region.clone());
            i.pointer = Some(w.string("/system")?);
            push(&mut doc.items, i, w)?;
            content(
                system,
                "/system",
                Some("system"),
                region.clone(),
                &mut doc.items,
                w,
            )?;
        }
        if let Some(messages) = value.get("messages").and_then(Value::as_array) {
            for (n, message) in messages.iter().enumerate() {
                w.check()?;
                let role = message.get("role").and_then(Value::as_str);
                let mut i = item(Kind::Context, region.clone());
                i.pointer = Some(w.string(&format!("/messages/{n}"))?);
                i.role = role.map(|s| w.string(s)).transpose()?;
                if !matches!(role, Some("user" | "assistant")) {
                    i.issues.push(Issue::Shape);
                }
                push(&mut doc.items, i, w)?;
                if let Some(c) = message.get("content") {
                    content(
                        c,
                        &format!("/messages/{n}/content"),
                        role,
                        region.clone(),
                        &mut doc.items,
                        w,
                    )?;
                } else {
                    push(&mut doc.items, item(Kind::Malformed, region.clone()), w)?;
                }
            }
        } else {
            push(&mut doc.items, item(Kind::Malformed, region.clone()), w)?;
        }
    } else if value.get("type").and_then(Value::as_str) == Some("error") {
        let mut i = item(Kind::Error, region.clone());
        i.pointer = Some(w.string("/error")?);
        push(&mut doc.items, i, w)?;
    } else if value.get("type").and_then(Value::as_str) == Some("message") {
        let role = value.get("role").and_then(Value::as_str);
        if let Some(c) = value.get("content") {
            content(c, "/content", role, region, &mut doc.items, w)?;
        } else {
            push(&mut doc.items, item(Kind::Malformed, region), w)?;
        }
    } else {
        push(&mut doc.items, item(Kind::Unsupported, region), w)?;
    }
    doc.json = Some(value);
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Text,
    Thinking,
    Tool,
    Unknown,
}
struct ActiveBlock {
    kind: BlockKind,
    stopped: bool,
    fragments: String,
    fragmented: bool,
}
#[derive(Default)]
struct State {
    started: bool,
    stopped: bool,
    delta: bool,
    invalid: bool,
    open_blocks: usize,
    blocks: BTreeMap<u64, ActiveBlock>,
}
fn event(
    value: Value,
    name: Option<&str>,
    region: Range<usize>,
    state: &mut State,
    w: &mut Work,
) -> Result<Item> {
    let mut i = item(Kind::Protocol, region);
    let typ = value.get("type").and_then(Value::as_str);
    if typ.is_none() || name.is_some_and(|n| Some(n) != typ) {
        i.issues.push(Issue::EventName);
    }
    let index = value.get("index").and_then(Value::as_u64);
    i.index = index;
    if state.stopped {
        i.issues.push(Issue::Sequence);
    }
    match typ {
        Some("message_start") => {
            if state.started {
                i.issues.push(Issue::Sequence);
            }
            state.started = true;
            let m = value.get("message");
            if m.and_then(|m| m.get("type")).and_then(Value::as_str) != Some("message")
                || m.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant")
                || !m
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                i.issues.push(Issue::Shape);
            }
        }
        Some("content_block_start") => {
            if !state.started || state.delta {
                i.issues.push(Issue::Sequence);
            }
            if let Some(index) = index {
                if let std::collections::btree_map::Entry::Vacant(entry) = state.blocks.entry(index)
                {
                    let b = value.get("content_block");
                    let kind = match b.and_then(|b| b.get("type")).and_then(Value::as_str) {
                        Some("text") => {
                            i.kind = Kind::Text;
                            BlockKind::Text
                        }
                        Some("thinking" | "redacted_thinking") => {
                            i.kind = Kind::Thinking;
                            BlockKind::Thinking
                        }
                        Some("tool_use" | "server_tool_use") => {
                            i.kind = Kind::ToolUse;
                            BlockKind::Tool
                        }
                        _ => {
                            i.kind = Kind::Unsupported;
                            i.issues.push(Issue::Unknown);
                            BlockKind::Unknown
                        }
                    };
                    let key = match kind {
                        BlockKind::Text => "text",
                        BlockKind::Thinking => "thinking",
                        BlockKind::Tool => "name",
                        BlockKind::Unknown => "",
                    };
                    i.text = b
                        .and_then(|b| b.get(key))
                        .and_then(Value::as_str)
                        .map(|s| w.string(s))
                        .transpose()?;
                    if matches!(kind, BlockKind::Text | BlockKind::Tool) && i.text.is_none() {
                        i.issues.push(Issue::Shape);
                    }
                    if kind == BlockKind::Tool
                        && !b.and_then(|b| b.get("input")).is_some_and(Value::is_object)
                    {
                        i.issues.push(Issue::ToolJson);
                    }
                    state.open_blocks = state
                        .open_blocks
                        .checked_add(1)
                        .ok_or(Error::Limit("items"))?;
                    entry.insert(ActiveBlock {
                        kind,
                        stopped: false,
                        fragments: String::new(),
                        fragmented: false,
                    });
                } else {
                    i.issues.push(Issue::BlockIndex);
                }
            } else {
                i.issues.push(Issue::BlockIndex);
            }
        }
        Some("content_block_delta") => {
            if !state.started || state.delta {
                i.issues.push(Issue::Sequence);
            }
            let delta = value.get("delta");
            let (kind, key, want) = match delta.and_then(|d| d.get("type")).and_then(Value::as_str)
            {
                Some("text_delta") => (Kind::Text, "text", BlockKind::Text),
                Some("thinking_delta") => (Kind::Thinking, "thinking", BlockKind::Thinking),
                Some("signature_delta") => (Kind::Protocol, "signature", BlockKind::Thinking),
                Some("input_json_delta") => (Kind::ToolFragment, "partial_json", BlockKind::Tool),
                _ => (Kind::Unsupported, "", BlockKind::Unknown),
            };
            i.kind = kind;
            let text = delta.and_then(|d| d.get(key)).and_then(Value::as_str);
            i.text = text.map(|s| w.string(s)).transpose()?;
            if want == BlockKind::Unknown {
                if delta
                    .and_then(|d| d.get("type"))
                    .and_then(Value::as_str)
                    .is_none()
                {
                    i.kind = Kind::Malformed;
                    i.issues.push(Issue::Shape);
                } else {
                    i.issues.push(Issue::Unknown);
                }
            } else if text.is_none() {
                i.issues.push(Issue::Shape);
            }
            if let Some(b) = index.and_then(|n| state.blocks.get_mut(&n)) {
                if b.stopped {
                    i.issues.push(Issue::Sequence);
                }
                if b.kind != want {
                    i.issues.push(Issue::DeltaType);
                }
                if want == BlockKind::Tool && b.kind == want && !b.stopped {
                    if let Some(s) = text {
                        w.output(s.len())?;
                        b.fragments.push_str(s);
                        b.fragmented = true;
                    }
                }
            } else {
                i.issues.push(Issue::BlockIndex);
            }
        }
        Some("content_block_stop") => {
            if !state.started || state.delta {
                i.issues.push(Issue::Sequence);
            }
            if let Some(b) = index.and_then(|n| state.blocks.get_mut(&n)) {
                if b.stopped {
                    i.issues.push(Issue::Sequence);
                } else {
                    b.stopped = true;
                    state.open_blocks -= 1;
                    if b.fragmented
                        && !strict(b.fragments.as_bytes(), w)?.is_some_and(|v| v.is_object())
                    {
                        i.issues.push(Issue::ToolJson);
                    }
                }
            } else {
                i.issues.push(Issue::BlockIndex);
            }
        }
        Some("message_delta") => {
            if !value.get("delta").is_some_and(Value::is_object) {
                i.issues.push(Issue::Shape);
            }
            if !state.started || state.open_blocks != 0 {
                i.issues.push(Issue::Sequence);
            }
            state.delta = true;
        }
        Some("message_stop") => {
            if !state.started || !state.delta || state.open_blocks != 0 {
                i.issues.push(Issue::Sequence);
            }
            state.stopped = true;
        }
        Some("ping") => {}
        Some("error") => {
            i.kind = Kind::Error;
            state.invalid = true;
        }
        _ => {
            if typ.is_none() {
                i.kind = Kind::Malformed;
                i.issues.push(Issue::Shape);
            } else {
                i.kind = Kind::Unsupported;
                i.issues.push(Issue::Unknown);
            }
        }
    }
    if !i.issues.is_empty() {
        state.invalid = true;
    }
    i.event = Some(value);
    Ok(i)
}
fn sse(
    bytes: &[u8],
    doc: &mut Document,
    w: &mut Work,
    after_item: &mut impl FnMut(),
) -> Result<()> {
    if bytes.is_empty() {
        push(&mut doc.items, item(Kind::Truncated, 0..0), w)?;
        return Ok(());
    }
    let mut state = State::default();
    let mut start = 0;
    let mut pos = 0;
    let mut data = Vec::new();
    let mut name: Option<String> = None;
    let mut has_data = false;
    while pos < bytes.len() {
        w.check()?;
        let line_start = pos;
        while pos < bytes.len() && !matches!(bytes[pos], b'\r' | b'\n') {
            pos += 1;
            if pos.is_multiple_of(65536) {
                w.check()?;
            }
        }
        if pos == bytes.len() {
            w.scan(pos - line_start)?;
            break;
        }
        let line = &bytes[line_start..pos];
        if bytes[pos] == b'\r' && bytes.get(pos + 1) == Some(&b'\n') {
            pos += 2;
        } else {
            pos += 1;
        }
        w.scan(pos - line_start)?;
        if line.is_empty() {
            let mut i = if has_data {
                if data.last() == Some(&b'\n') {
                    data.pop();
                }
                match strict(&data, w)? {
                    Some(v) => event(v, name.as_deref(), start..pos, &mut state, w)?,
                    None => {
                        state.invalid = true;
                        item(Kind::Malformed, start..pos)
                    }
                }
            } else {
                item(Kind::Protocol, start..pos)
            };
            // Invalid UTF-8 in event names is never silently repaired.
            if name.as_deref() == Some("\0invalid-utf8") {
                i.issues.push(Issue::EventName);
                state.invalid = true;
            }
            push(&mut doc.items, i, w)?;
            after_item();
            start = pos;
            data.clear();
            name = None;
            has_data = false;
        } else if !line.starts_with(b":") {
            let (field, mut value) = match line.iter().position(|&b| b == b':') {
                Some(n) => (&line[..n], &line[n + 1..]),
                None => (line, &[][..]),
            };
            if value.first() == Some(&b' ') {
                value = &value[1..];
            }
            match field {
                b"data" => {
                    w.output(value.len() + 1)?;
                    data.extend_from_slice(value);
                    data.push(b'\n');
                    has_data = true;
                }
                b"event" => {
                    name = Some(w.string(std::str::from_utf8(value).unwrap_or("\0invalid-utf8"))?);
                }
                _ => {}
            }
        }
    }
    if start < bytes.len() {
        push(&mut doc.items, item(Kind::Truncated, start..bytes.len()), w)?;
        state.invalid = true;
        after_item();
    }
    doc.coherent_stop_observed = state.stopped && !state.invalid;
    Ok(())
}
pub fn interpret(bytes: &[u8], format: Format, limits: Limits) -> Result<Document> {
    interpret_observed(bytes, format, limits, || {})
}
fn interpret_observed(
    bytes: &[u8],
    format: Format,
    limits: Limits,
    mut after_item: impl FnMut(),
) -> Result<Document> {
    let mut w = Work::new(limits)?;
    if bytes.len() > w.limits.input_bytes {
        return Err(Error::Limit("input bytes"));
    }
    let mut doc = Document {
        format,
        json: None,
        items: vec![],
        coherent_stop_observed: false,
        scanned_bytes: 0,
        output_bytes: 0,
    };
    if format == Format::Sse {
        sse(bytes, &mut doc, &mut w, &mut after_item)?;
    } else {
        json_body(bytes, format, &mut doc, &mut w)?;
        after_item();
    }
    w.check()?;
    doc.scanned_bytes = w.scan;
    doc.output_bytes = w.output;
    Ok(doc)
}
/// Map one enclosing region to exact original input spans. Validate the full
/// contiguous stream and every duplicate source before returning any citations.
/// This checks byte correspondence only, never a signature or access grant.
pub fn map_region(
    stream: &Stream,
    inputs: &[Input<'_>],
    region: Range<usize>,
    limits: Limits,
) -> Result<Vec<SourceSpan>> {
    let mut w = Work::new(limits)?;
    let bytes = stream.contiguous.as_deref().ok_or(Error::Mapping)?;
    if bytes.len() > w.limits.input_bytes {
        return Err(Error::Limit("input bytes"));
    }
    if !stream.issues.is_empty()
        || stream
            .expected_bytes
            .is_some_and(|n| n != bytes.len() as u64)
        || region.start > region.end
        || region.end > bytes.len()
    {
        return Err(Error::Mapping);
    }
    let mut next = 0usize;
    let mut out = vec![];
    let mut group = None;
    for s in &stream.segments {
        w.item()?;
        if s.offset != next as u64 || s.sources.is_empty() {
            return Err(Error::Mapping);
        }
        let end = next.checked_add(s.length).ok_or(Error::Mapping)?;
        let piece = bytes.get(next..end).ok_or(Error::Mapping)?;
        let mut first_raw = None;
        for source in &s.sources {
            w.item()?;
            let original = match inputs.get(source.input).map(|i| i.payload) {
                Some(Payload::Available(b)) => b,
                _ => return Err(Error::Mapping),
            };
            w.scan(original.len())?;
            let frame = match decode::decode(original) {
                Ok(Decoded::Capture(f)) => f,
                _ => return Err(Error::Mapping),
            };
            if frame.body_span != source.bytes {
                return Err(Error::Mapping);
            }
            let (direction, offset) = match frame.header.event {
                Event::RequestChunk { offset } => (0, offset),
                Event::ResponseChunk { offset } => (1, offset),
                _ => return Err(Error::Mapping),
            };
            if offset != s.offset {
                return Err(Error::Mapping);
            }
            let input = &inputs[source.input];
            let identity = (
                input.scope,
                input.writer,
                frame.header.observer,
                frame.header.attempt,
                direction,
            );
            if let Some(expected) = &group {
                if expected != &identity {
                    return Err(Error::Mapping);
                }
            } else {
                group = Some(identity);
            }
            if let Some(expected) = first_raw {
                w.scan(original.len())?;
                if expected != original {
                    return Err(Error::Mapping);
                }
            } else {
                first_raw = Some(original);
            }
            let raw = original.get(source.bytes.clone()).ok_or(Error::Mapping)?;
            w.scan(raw.len())?;
            if raw != piece {
                return Err(Error::Mapping);
            }
            let a = next.max(region.start);
            let b = end.min(region.end);
            if a < b || (region.is_empty() && next <= a && a <= end && a == region.start) {
                if out.len() >= w.limits.citations {
                    return Err(Error::Limit("citations"));
                }
                out.push(SourceSpan {
                    input: source.input,
                    bytes: (source.bytes.start + a - next)..(source.bytes.start + b - next),
                });
            }
        }
        next = end;
    }
    if next != bytes.len() {
        return Err(Error::Mapping);
    }
    w.check()?;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_after_first_event_refuses_remaining_output() {
        let c = Arc::new(AtomicBool::new(false));
        let limits = Limits {
            input_bytes: 1000,
            items: 100,
            output_bytes: 1000,
            scan_bytes: 1000,
            citations: 100,
            duration: Duration::from_secs(1),
            cancelled: c.clone(),
        };
        let mut seen = 0;
        let result = interpret_observed(
            b"data: {\"type\":\"ping\"}\n\ndata: {\"type\":\"ping\"}\n\n",
            Format::Sse,
            limits,
            || {
                seen += 1;
                c.store(true, Ordering::Relaxed);
            },
        );
        assert_eq!(result.unwrap_err(), Error::Cancelled);
        assert_eq!(seen, 1);
    }
}
