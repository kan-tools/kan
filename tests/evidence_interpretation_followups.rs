#![cfg(feature = "v2-crypto")]
use kan::{evidence_assembly as a, evidence_interpretation as p};
use serde_json::{json, Value};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn limits() -> p::Limits {
    p::Limits {
        input_bytes: 1 << 20,
        items: 1000,
        output_bytes: 1 << 20,
        scan_bytes: 8 << 20,
        citations: 1000,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn events(values: &[Value]) -> Vec<u8> {
    values
        .iter()
        .map(|v| format!("data: {v}\n\n"))
        .collect::<String>()
        .into_bytes()
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
fn frame(ordinal: u64, offset: u64, body: &[u8]) -> Vec<u8> {
    let h=serde_json::to_vec(&json!({"version":2,"attempt":"1".repeat(64),"observer":"collector","ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"response-chunk","offset":offset}})).unwrap();
    let mut out = b"KANC2".to_vec();
    out.extend((h.len() as u32).to_be_bytes());
    out.extend(h);
    out.extend(body);
    out
}
#[test]
fn absolute_output_accounting_covers_json_strings_and_sse_data() {
    let request = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
    // Input parse plus independently enumerated Context/block pointer, role and text copies.
    let expected = (request.len()
        + "/messages/0".len()
        + "user".len()
        + "/messages/0/content".len()
        + "user".len()
        + "hi".len()) as u64;
    let mut l = limits();
    l.output_bytes = expected;
    let d = p::interpret(request, p::Format::Request, l.clone()).unwrap();
    assert_eq!(d.output_bytes, expected);
    l.output_bytes -= 1;
    assert_eq!(
        p::interpret(request, p::Format::Request, l).unwrap_err(),
        p::Error::Limit("output bytes")
    );
    let data = br#"{"type":"ping"}"#;
    let raw = events(&[json!({"type":"ping"})]);
    let expected = (data.len() + 1 + data.len()) as u64;
    let mut l = limits();
    l.output_bytes = expected;
    assert_eq!(
        p::interpret(&raw, p::Format::Sse, l.clone())
            .unwrap()
            .output_bytes,
        expected
    );
    l.output_bytes -= 1;
    assert_eq!(
        p::interpret(&raw, p::Format::Sse, l).unwrap_err(),
        p::Error::Limit("output bytes")
    );
}
#[test]
fn empty_chunks_at_covered_offsets_preserve_mapping_and_boundary_lineage() {
    for raw in [
        vec![frame(0, 0, b"abcdef"), frame(1, 3, b""), frame(2, 6, b"gh")],
        vec![frame(0, 0, b"abcdefgh"), frame(1, 0, b"")],
    ] {
        let inputs: Vec<_> = raw
            .iter()
            .map(|r| a::Input {
                scope: [1; 32],
                writer: "writer",
                payload: a::Payload::Available(r),
            })
            .collect();
        let ab = a::assemble(
            &inputs,
            a::Limits {
                occurrences: 10,
                input_bytes: 10000,
                scan_bytes: 10000,
                assembled_bytes: 10000,
                duration: Duration::from_secs(10),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )
        .unwrap();
        let stream = &ab.groups[0].response;
        assert!(stream.issues.is_empty());
        assert_eq!(stream.contiguous.as_deref(), Some(&b"abcdefgh"[..]));
        let mapped = p::map_region(stream, &inputs, 0..8, limits())
            .expect("valid empty covered chunk must map");
        let joined: Vec<_> = mapped
            .iter()
            .flat_map(|s| raw[s.input][s.bytes.clone()].iter().copied())
            .collect();
        assert_eq!(joined, b"abcdefgh");
        let point = stream
            .segments
            .iter()
            .find(|s| s.length == 0)
            .unwrap()
            .offset as usize;
        let mapped = p::map_region(stream, &inputs, point..point, limits()).unwrap();
        assert_eq!(mapped.len(), 2);
        assert!(mapped.iter().all(|s| s.bytes.is_empty()));
        assert!(mapped.iter().any(|s| s.input == 1));
    }
    let raw = [
        frame(0, 0, b"abc"),
        frame(1, 3, b"def"),
        frame(0, 0, b"abc"),
    ];
    let inputs: Vec<_> = raw
        .iter()
        .map(|r| a::Input {
            scope: [1; 32],
            writer: "writer",
            payload: a::Payload::Available(r),
        })
        .collect();
    let ab = a::assemble(
        &inputs,
        a::Limits {
            occurrences: 10,
            input_bytes: 10000,
            scan_bytes: 10000,
            assembled_bytes: 10000,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap();
    let mapped = p::map_region(&ab.groups[0].response, &inputs, 3..3, limits()).unwrap();
    assert_eq!(
        mapped.iter().map(|s| s.input).collect::<Vec<_>>(),
        vec![0, 2, 1]
    );
    assert!(mapped.iter().all(|s| s.bytes.is_empty()));
}
#[test]
fn nested_tool_results_render_and_malformed_unknown_shapes_have_reasons() {
    let raw=br#"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"NESTED-RESULT"},{"type":"image","source":{"type":"url","url":"https://untrusted.invalid"}}]}]}]}"#;
    let d = p::interpret(raw, p::Format::Request, limits()).unwrap();
    assert!(d
        .items
        .iter()
        .any(|i| i.text.as_deref() == Some("NESTED-RESULT")
            && i.pointer.as_deref() == Some("/messages/0/content/0/content/0")));
    for (raw, f) in [
        (br#"{"type":"future_root"}"#.as_slice(), p::Format::Response),
        (
            br#"{"messages":[{"role":"user"}]}"#.as_slice(),
            p::Format::Request,
        ),
        (b"broken".as_slice(), p::Format::Response),
    ] {
        let d = p::interpret(raw, f, limits()).unwrap();
        assert!(d
            .items
            .iter()
            .filter(|i| matches!(i.kind, p::Kind::Malformed | p::Kind::Unsupported))
            .all(|i| !i.issues.is_empty()));
    }
    let d = p::interpret(
        br#"{"type":"message","role":"user","content":"x"}"#,
        p::Format::Response,
        limits(),
    )
    .unwrap();
    assert!(d.items[0].issues.contains(&p::Issue::Shape));
}
#[test]
fn citations_delta_is_not_a_contradiction_and_unknown_types_do_not_guess_block_kind() {
    let mut v = vec![
        start(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"evidence","document_index":0}}}),
        json!({"type":"content_block_stop","index":0}),
        delta(),
        stop(),
    ];
    let d = p::interpret(&events(&v), p::Format::Sse, limits()).unwrap();
    assert!(d.coherent_stop_observed);
    assert!(d.items[2].issues.is_empty());
    v[2]["delta"] = json!({"type":"future_delta","value":"retained"});
    let d = p::interpret(&events(&v), p::Format::Sse, limits()).unwrap();
    assert_eq!(d.items[2].kind, p::Kind::Unsupported);
    assert_eq!(d.items[2].issues, vec![p::Issue::Unknown]);
    assert!(!d.coherent_stop_observed);
}
#[test]
fn bom_and_undispatched_framing_keep_source_regions_and_unknown_fields_visible() {
    let raw = events(&[start(), delta(), stop()]);
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend(&raw);
    let d = p::interpret(&bom, p::Format::Sse, limits()).unwrap();
    assert!(d.coherent_stop_observed);
    assert_eq!(d.items[0].region.start, 0);
    assert_eq!(d.items.last().unwrap().region.end, bom.len());
    let mut raw = raw.clone();
    raw.extend(b"event: message_start\n\n");
    let d = p::interpret(&raw, p::Format::Sse, limits()).unwrap();
    let last = d.items.last().unwrap();
    assert_eq!(format!("{:?}", last.kind), "Framing");
    assert_eq!(last.text.as_deref(), Some("Undispatched SSE framing"));
    assert!(d.coherent_stop_observed);
    raw.extend(b"dta: not a known SSE field\n\n");
    let d = p::interpret(&raw, p::Format::Sse, limits()).unwrap();
    assert_eq!(d.items.last().unwrap().issues, vec![p::Issue::Unknown]);
    assert!(!d.coherent_stop_observed);
}
#[test]
fn sequence_issue_is_attached_to_the_block_start_that_follows_message_delta() {
    let v = [
        start(),
        delta(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_stop","index":0}),
        stop(),
    ];
    let d = p::interpret(&events(&v), p::Format::Sse, limits()).unwrap();
    assert!(d.items[2].issues.contains(&p::Issue::Sequence));
}

#[test]
fn malformed_error_and_tool_result_shapes_have_resolving_pointers_and_reasons() {
    for bytes in [
        br#"{"type":"error"}"#.as_slice(),
        br#"{"type":"error","error":7}"#.as_slice(),
    ] {
        let d = p::interpret(bytes, p::Format::Response, limits()).unwrap();
        let i = d.items.iter().find(|i| i.kind == p::Kind::Error).unwrap();
        assert!(i.issues.contains(&p::Issue::Shape));
        assert!(d
            .json
            .as_ref()
            .unwrap()
            .pointer(i.pointer.as_ref().unwrap())
            .is_some());
    }
    for value in [
        json!(null),
        json!({"type":"text","text":"kept in raw JSON"}),
        json!(7),
    ] {
        let bytes=serde_json::to_vec(&json!({"messages":[{"role":"user","content":[{"type":"tool_result","content":value}]}]})).unwrap();
        let d = p::interpret(&bytes, p::Format::Request, limits()).unwrap();
        let item = d
            .items
            .iter()
            .find(|i| i.kind == p::Kind::ToolResult)
            .unwrap();
        assert!(item.issues.contains(&p::Issue::Shape));
        assert_eq!(
            d.json
                .as_ref()
                .unwrap()
                .pointer("/messages/0/content/0/content"),
            Some(&value)
        );
    }
}
#[test]
fn unknown_sse_field_reason_is_local_to_its_event() {
    let raw = b"future-field: value\ndata: {\"type\":\"ping\"}\n\ndata: {\"type\":\"ping\"}\n\n";
    let d = p::interpret(raw, p::Format::Sse, limits()).unwrap();
    assert_eq!(d.items.len(), 2);
    assert_eq!(d.items[0].issues, vec![p::Issue::Unknown]);
    assert!(d.items[1].issues.is_empty());
    assert!(!d.coherent_stop_observed);
}

#[test]
fn citations_and_unknown_deltas_do_not_promote_an_empty_json_key_to_text() {
    for delta in [
        json!({"type":"citations_delta","citation":{},"":"untyped text"}),
        json!({"type":"future_delta","":"untyped text"}),
    ] {
        let raw = events(&[
            start(),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":delta}),
        ]);
        let doc = p::interpret(&raw, p::Format::Sse, limits()).unwrap();
        let item = &doc.items[2];
        assert_eq!(item.text, None);
        assert_eq!(item.event.as_ref().unwrap()["delta"][""], "untyped text");
    }
}

#[test]
fn absent_tool_result_content_is_valid_but_explicit_invalid_content_is_not() {
    for is_error in [false, true] {
        let bytes = serde_json::to_vec(&json!({"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"synthetic","is_error":is_error}]}]})).unwrap();
        let d = p::interpret(&bytes, p::Format::Request, limits()).unwrap();
        let item = d
            .items
            .iter()
            .find(|i| i.kind == p::Kind::ToolResult)
            .unwrap();
        assert!(!item.issues.contains(&p::Issue::Shape));
        assert!(d
            .json
            .as_ref()
            .unwrap()
            .pointer(item.pointer.as_ref().unwrap())
            .is_some());
    }
}
