#![cfg(feature = "v2-crypto")]
use kan::{evidence_assembly as a, evidence_capture::CHUNK, evidence_interpretation as p};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
fn limits() -> p::Limits {
    p::Limits {
        input_bytes: 1024 * 1024,
        items: 10000,
        output_bytes: 16 * 1024 * 1024,
        scan_bytes: 16 * 1024 * 1024,
        citations: 10000,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn parse(bytes: &[u8], f: p::Format) -> p::Document {
    p::interpret(bytes, f, limits()).unwrap()
}
fn events(values: &[Value]) -> Vec<u8> {
    let mut out = vec![];
    for v in values {
        out.extend(format!("event: {}\ndata: {}\n\n", v["type"].as_str().unwrap(), v).as_bytes());
    }
    out
}
fn start() -> Value {
    json!({"type":"message_start","message":{"type":"message","role":"assistant","content":[]}})
}
fn delta() -> Value {
    json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}})
}
fn stop() -> Value {
    json!({"type":"message_stop"})
}
fn text_stream() -> Vec<Value> {
    vec![
        start(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"é \"hi\""}}),
        json!({"type":"content_block_stop","index":0}),
        delta(),
        stop(),
    ]
}
#[test]
fn request_history_and_unknown_fields_remain_source_linked() {
    let raw=br#"{"system":"You are helpful","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"t","name":"read","input":{"path":"secret"}},{"type":"thinking","thinking":"maybe"},{"type":"future","extension":true}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"done"},{"type":"image","source":{"type":"url","url":"https://invalid.example/private"}}]}],"future_root":{"v":1}}"#;
    let d = parse(raw, p::Format::Request);
    assert_eq!(
        d.items
            .iter()
            .filter(|i| i.kind == p::Kind::Context)
            .count(),
        3
    );
    for k in [
        p::Kind::System,
        p::Kind::Text,
        p::Kind::ToolUse,
        p::Kind::ToolResult,
        p::Kind::Thinking,
        p::Kind::Attachment,
        p::Kind::Unsupported,
    ] {
        assert!(d.items.iter().any(|i| i.kind == k), "missing {k:?}");
    }
    assert_eq!(d.json.as_ref().unwrap()["future_root"]["v"], 1);
    for i in &d.items {
        assert_eq!(i.region, 0..raw.len());
        assert!(i.coarse);
        if let Some(ptr) = &i.pointer {
            assert!(d.json.as_ref().unwrap().pointer(ptr).is_some());
        }
    }
    assert!(!d.coherent_stop_observed);
}
#[test]
fn duplicate_keys_aliases_depth_and_truncation_are_visible() {
    for raw in [&b"{\"messages\":[],\"messag\\u0065s\":[]}"[..],b"{\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"a\",\"text\":\"b\"}}]}",b"{\"messages\":[",b"\xff"] {
        let d=parse(raw,p::Format::Request);assert_eq!(d.items.len(),1);assert_eq!(d.items[0].kind,p::Kind::Malformed);assert!(d.json.is_none());assert_eq!(d.items[0].region,0..raw.len());
    }
    let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert_eq!(
        parse(deep.as_bytes(), p::Format::Response).items[0].kind,
        p::Kind::Malformed
    );
}
#[test]
fn response_json_and_provider_errors_never_claim_stream_completeness() {
    let d=parse(br#"{"type":"message","role":"assistant","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn"}"#,p::Format::Response);
    assert_eq!(d.items[1].text.as_deref(), Some("hello"));
    assert!(!d.coherent_stop_observed);
    let e = parse(
        br#"{"type":"error","error":{"type":"overloaded_error","message":"no"}}"#,
        p::Format::Response,
    );
    assert!(e.items.iter().any(|i| i.kind == p::Kind::Error));
    assert!(parse(
        br#"{"type":"next_version","opaque":1}"#,
        p::Format::Response
    )
    .items
    .iter()
    .any(|i| i.kind == p::Kind::Unsupported));
}
#[test]
fn newline_forms_multiline_comments_and_raw_unknown_fields_survive() {
    let raw = events(&text_stream());
    for newline in ["\n", "\r\n", "\r"] {
        let body = String::from_utf8(raw.clone())
            .unwrap()
            .replace('\n', newline);
        let d = parse(body.as_bytes(), p::Format::Sse);
        assert!(d.coherent_stop_observed);
        assert_eq!(d.items.len(), 6);
        assert_eq!(d.items[2].text.as_deref(), Some("é \"hi\""));
        let mut previous = 0;
        for i in &d.items {
            assert_eq!(i.region.start, previous);
            assert!(i.region.end <= body.len());
            previous = i.region.end;
            assert!(i.event.is_some());
        }
        assert_eq!(previous, body.len());
    }
    let d = parse(
        b": comment\nid: unused\nevent: ping\ndata: {\"type\":\ndata: \"ping\",\"extra\":1}\n\n",
        p::Format::Sse,
    );
    assert_eq!(d.items.len(), 1);
    assert_eq!(d.items[0].event.as_ref().unwrap()["extra"], 1);
    assert!(d.items[0].issues.is_empty());
}
#[test]
fn malformed_unknown_error_and_trailing_event_are_visible() {
    for (bytes, kind) in [
        (
            b"event: ping\ndata: not json\n\n".as_slice(),
            p::Kind::Malformed,
        ),
        (
            b"event: future\ndata: {\"type\":\"future\"}\n\n",
            p::Kind::Unsupported,
        ),
        (
            b"data: {\"type\":\"error\",\"error\":{}}\n\n",
            p::Kind::Error,
        ),
        (b"data: {\"type\":\"ping\"}\n", p::Kind::Truncated),
    ] {
        let d = parse(bytes, p::Format::Sse);
        assert_eq!(d.items[0].kind, kind);
        assert_eq!(d.items[0].region, 0..bytes.len());
        assert!(!d.coherent_stop_observed);
    }
    let mut bytes = events(&text_stream());
    bytes.extend(b"data: ");
    let d = parse(&bytes, p::Format::Sse);
    assert_eq!(d.items.last().unwrap().kind, p::Kind::Truncated);
    assert!(!d.coherent_stop_observed);
    let bad = parse(
        b"event: message_stop\ndata: {\"type\":\"ping\"}\n\n",
        p::Format::Sse,
    );
    assert!(bad.items[0].issues.contains(&p::Issue::EventName));
}
#[test]
fn block_sequence_conflicts_and_sparse_indices_never_complete() {
    let valid = text_stream();
    let mut cases = vec![];
    let mut missing = valid.clone();
    missing.remove(0);
    cases.push(missing);
    let mut duplicate = valid.clone();
    duplicate.insert(2, valid[1].clone());
    cases.push(duplicate);
    let mut missing_stop = valid.clone();
    missing_stop.remove(3);
    cases.push(missing_stop);
    let mut wrong_index = valid.clone();
    wrong_index[2]["index"] = json!(u64::MAX);
    cases.push(wrong_index);
    let mut wrong_delta = valid.clone();
    wrong_delta[2]["delta"] = json!({"type":"thinking_delta","thinking":"hmm"});
    cases.push(wrong_delta);
    let mut after_stop = valid.clone();
    after_stop.push(json!({"type":"ping"}));
    cases.push(after_stop);
    for c in cases {
        let d = parse(&events(&c), p::Format::Sse);
        assert!(!d.coherent_stop_observed);
        assert!(d.items.iter().any(|i| !i.issues.is_empty()));
    }
    let mut sparse = valid;
    sparse[1]["index"] = json!(u64::MAX);
    sparse[2]["index"] = json!(u64::MAX);
    sparse[3]["index"] = json!(u64::MAX);
    let d = parse(&events(&sparse), p::Format::Sse);
    assert_eq!(d.items[1].index, Some(u64::MAX));
    assert!(d.coherent_stop_observed);
}
#[test]
fn tool_fragments_are_not_repaired_or_replaced_by_empty_initial_input() {
    for (fragments, valid) in [
        (vec!["{\"x\":", "1}"], true),
        (vec!["{\"x\":"], false),
        (vec!["[]"], false),
        (vec!["{\"x\":1,\"x\":2}"], false),
    ] {
        let mut values = vec![
            start(),
            json!({"type":"content_block_start","index":7,"content_block":{"type":"tool_use","id":"call","name":"run","input":{}}}),
        ];
        for s in &fragments {
            values.push(json!({"type":"content_block_delta","index":7,"delta":{"type":"input_json_delta","partial_json":s}}));
        }
        values.extend([
            json!({"type":"content_block_stop","index":7}),
            delta(),
            stop(),
        ]);
        let d = parse(&events(&values), p::Format::Sse);
        assert_eq!(d.coherent_stop_observed, valid);
        assert_eq!(
            d.items
                .iter()
                .filter(|i| i.kind == p::Kind::ToolFragment)
                .map(|i| i.text.as_deref().unwrap())
                .collect::<Vec<_>>(),
            fragments
        );
        assert_eq!(
            d.items
                .iter()
                .any(|i| i.issues.contains(&p::Issue::ToolJson)),
            !valid
        );
    }
}
fn wire(n: u64, offset: usize, body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= CHUNK);
    let h=serde_json::to_vec(&json!({"version":2,"attempt":"a".repeat(64),"observer":"collector","ordinal":n,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"response-chunk","offset":offset}})).unwrap();
    let mut v = b"KANC2".to_vec();
    v.extend((h.len() as u32).to_be_bytes());
    v.extend(h);
    v.extend(body);
    v
}
fn inputs(raw: &[Vec<u8>]) -> Vec<a::Input<'_>> {
    raw.iter()
        .map(|b| a::Input {
            scope: [1; 32],
            writer: "w",
            payload: a::Payload::Available(b),
        })
        .collect()
}
fn assembled<'a>(inputs: &[a::Input<'a>]) -> a::Assembly<'a> {
    a::assemble(
        inputs,
        a::Limits {
            occurrences: 100,
            input_bytes: 1024 * 1024,
            scan_bytes: 16 * 1024 * 1024,
            assembled_bytes: 1024 * 1024,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap()
}
#[test]
fn every_capture_split_preserves_sse_text_and_exact_duplicate_source_spans() {
    let bytes = events(&text_stream());
    for split in 1..bytes.len() {
        let left = wire(0, 0, &bytes[..split]);
        let right = wire(1, split, &bytes[split..]);
        let raw = vec![left.clone(), right, left];
        let selected = inputs(&raw);
        let assembly = assembled(&selected);
        let stream = &assembly.groups[0].response;
        let d = parse(stream.contiguous.as_ref().unwrap(), p::Format::Sse);
        assert!(d.coherent_stop_observed);
        for i in &d.items {
            let spans = p::map_region(stream, &selected, i.region.clone(), limits()).unwrap();
            let mut primary: Vec<u8> = vec![];
            for span in &spans {
                assert!(span.bytes.start <= span.bytes.end);
                if span.input != 2 {
                    primary.extend(&raw[span.input][span.bytes.clone()]);
                }
            }
            assert_eq!(primary, bytes[i.region.clone()]);
            let left_spans: Vec<_> = spans
                .iter()
                .filter(|s| s.input == 0)
                .map(|s| s.bytes.clone())
                .collect();
            let duplicates: Vec<_> = spans
                .iter()
                .filter(|s| s.input == 2)
                .map(|s| s.bytes.clone())
                .collect();
            assert_eq!(left_spans, duplicates);
        }
    }
}
#[test]
fn mapping_refuses_gaps_overlaps_forged_source_bytes_and_ranges() {
    let raw = vec![wire(0, 0, b"abc"), wire(1, 3, b"def")];
    let selected = inputs(&raw);
    for mode in 0..6 {
        let mut a = assembled(&selected);
        let s = &mut a.groups[0].response;
        match mode {
            0 => s.segments[1].offset = 2,
            1 => s.segments[1].offset = 4,
            2 => s.segments[0].sources[0].bytes.start = 0,
            3 => s.segments[0].sources[0].input = 99,
            4 => s.segments[0].sources.clear(),
            _ => s.contiguous.as_mut().unwrap()[0] = b'X',
        };
        assert_eq!(
            p::map_region(s, &selected, 0..6, limits()).unwrap_err(),
            p::Error::Mapping
        );
    }
    let a = assembled(&selected);
    let s = &a.groups[0].response;
    assert_eq!(
        p::map_region(s, &selected, 0..7, limits()).unwrap_err(),
        p::Error::Mapping
    );
    assert_eq!(
        p::map_region(s, &selected, std::ops::Range { start: 5, end: 2 }, limits()).unwrap_err(),
        p::Error::Mapping
    );
    let mut l = limits();
    l.citations = 1;
    assert_eq!(
        p::map_region(s, &selected, 0..6, l).unwrap_err(),
        p::Error::Limit("citations")
    );
}
#[test]
fn exact_budgets_and_cancellation_return_no_partial_document() {
    let bytes = events(&text_stream());
    let d = parse(&bytes, p::Format::Sse);
    let mut l = limits();
    l.input_bytes = bytes.len();
    l.items = d.items.len();
    l.output_bytes = d.output_bytes;
    l.scan_bytes = d.scanned_bytes;
    assert!(p::interpret(&bytes, p::Format::Sse, l.clone()).is_ok());
    for (which, expected) in [
        (0, "input bytes"),
        (1, "items"),
        (2, "output bytes"),
        (3, "scan bytes"),
    ] {
        let mut b = l.clone();
        match which {
            0 => b.input_bytes -= 1,
            1 => b.items -= 1,
            2 => b.output_bytes -= 1,
            _ => b.scan_bytes -= 1,
        };
        assert_eq!(
            p::interpret(&bytes, p::Format::Sse, b).unwrap_err(),
            p::Error::Limit(expected)
        );
    }
    let b = l.clone();
    b.cancelled.store(true, Ordering::Relaxed);
    assert_eq!(
        p::interpret(&bytes, p::Format::Sse, b).unwrap_err(),
        p::Error::Cancelled
    );
    let mut b = limits();
    b.duration = Duration::ZERO;
    assert_eq!(
        p::interpret(&bytes, p::Format::Sse, b).unwrap_err(),
        p::Error::Limit("duration")
    );
}

#[test]
fn mapping_refuses_foreign_group_unavailable_source_and_forged_extent() {
    let raw = vec![wire(0, 0, b"abc"), wire(1, 3, b"def")];
    let selected = inputs(&raw);
    let assembly = assembled(&selected);
    let stream = &assembly.groups[0].response;
    for mode in 0..3 {
        let mut changed = inputs(&raw);
        match mode {
            0 => changed[1].scope = [2; 32],
            1 => changed[1].writer = "foreign",
            _ => changed[1].payload = a::Payload::Unavailable(a::Unavailable::Missing),
        }
        assert_eq!(
            p::map_region(stream, &changed, 0..6, limits()).unwrap_err(),
            p::Error::Mapping
        );
    }
    let mut a = assembled(&selected);
    a.groups[0].response.expected_bytes = Some(7);
    assert_eq!(
        p::map_region(&a.groups[0].response, &selected, 0..6, limits()).unwrap_err(),
        p::Error::Mapping
    );
}
#[test]
fn empty_sse_and_malformed_message_delta_are_explicit() {
    assert_eq!(parse(b"", p::Format::Sse).items[0].kind, p::Kind::Truncated);
    let mut values = text_stream();
    values[4] = json!({"type":"message_delta"});
    let d = parse(&events(&values), p::Format::Sse);
    assert!(!d.coherent_stop_observed);
    assert!(d.items[4].issues.contains(&p::Issue::Shape));
}

#[test]
fn missing_event_and_delta_types_are_malformed_not_future_extensions() {
    for value in [
        json!({}),
        json!({"type":7}),
        json!({"type":"content_block_delta","index":0,"delta":null}),
    ] {
        let raw = format!("data: {value}\n\n");
        let d = parse(raw.as_bytes(), p::Format::Sse);
        assert_eq!(d.items[0].kind, p::Kind::Malformed);
        assert!(!d.coherent_stop_observed);
    }
}

#[test]
fn harness_jsonl_keeps_tools_compaction_unknowns_and_original_line_ranges() {
    let lines = [
        "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"hello\"},{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"read\",\"input\":{\"path\":\"a\"}}]}}\n",
        "{\"type\":\"summary\",\"summary\":\"compacted\",\"parentUuid\":\"branch-parent\"}\n",
        "{\"type\":\"future\",\"extension\":true}\n",
        "{\"type\":\"user\",\"type\":\"assistant\"}\n",
    ];
    let raw = lines.concat();
    let doc = parse(raw.as_bytes(), p::Format::HarnessJsonl);
    assert!(doc.items.iter().any(|i| i.kind == p::Kind::ToolUse));
    assert!(doc.items.iter().any(|i| i.text.as_deref() == Some("hello")));
    let summary = doc
        .items
        .iter()
        .find(|i| i.kind == p::Kind::Context)
        .unwrap();
    assert_eq!(
        summary.region,
        lines[0].len()..lines[0].len() + lines[1].len()
    );
    assert_eq!(
        summary.event.as_ref().unwrap()["parentUuid"],
        "branch-parent"
    );
    assert!(doc
        .items
        .iter()
        .any(|i| i.kind == p::Kind::Protocol && i.event.as_ref().unwrap()["extension"] == true));
    assert_eq!(doc.items.last().unwrap().kind, p::Kind::Malformed);
    assert!(doc.items.iter().all(|i| i.pointer.is_none()));
    assert!(!doc.coherent_stop_observed);
}
