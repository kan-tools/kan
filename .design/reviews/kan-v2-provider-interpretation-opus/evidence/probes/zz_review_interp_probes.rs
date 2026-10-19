#![cfg(feature = "v2-crypto")]
// Independent reviewer probes for src/evidence_interpretation.rs (frozen 0d04848).
// Authored from the design doc and protocol reading, not from the author's fixtures.
// Naming: pass_* = expected-correct behaviour asserted (a failure is a finding);
//         char_* = characterisation, prints observed behaviour and asserts what was observed
//                  so that a change is visible (the REPORT judges whether it is acceptable).
use kan::{evidence_assembly as a, evidence_interpretation as p};
use serde_json::{json, Value};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

fn lim() -> p::Limits {
    p::Limits {
        input_bytes: 8 * 1024 * 1024,
        items: 1_000_000,
        output_bytes: 256 * 1024 * 1024,
        scan_bytes: 256 * 1024 * 1024,
        citations: 100_000,
        duration: Duration::from_secs(60),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn parse(b: &[u8], f: p::Format) -> p::Document {
    p::interpret(b, f, lim()).unwrap()
}
// Independent SSE writer: no "event:" helper sharing with author; variable framing.
fn sse(events: &[Value], nl: &str, with_names: bool) -> Vec<u8> {
    let mut s = String::new();
    for e in events {
        if with_names {
            s += &format!("event: {}{nl}", e["type"].as_str().unwrap());
        }
        s += &format!("data:{}{nl}{nl}", e);
    }
    s.into_bytes()
}
fn ms() -> Value {
    json!({"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[],"model":"x","usage":{"input_tokens":1}}})
}
fn md() -> Value {
    json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}})
}
fn mstop() -> Value {
    json!({"type":"message_stop"})
}
fn tool_stream(fragments: &[&str]) -> Vec<Value> {
    let mut v = vec![
        ms(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"noargs","input":{}}}),
    ];
    for f in fragments {
        v.push(json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":f}}));
    }
    v.extend([json!({"type":"content_block_stop","index":0}), md(), mstop()]);
    v
}
fn text_stream() -> Vec<Value> {
    vec![
        ms(),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"a"}}),
        json!({"type":"content_block_stop","index":0}),
        md(),
        mstop(),
    ]
}
fn tiles(d: &p::Document, len: usize) {
    let mut prev = 0;
    for i in &d.items {
        assert_eq!(i.region.start, prev, "regions must tile");
        assert!(i.region.end >= i.region.start && i.region.end <= len);
        prev = i.region.end;
    }
    assert_eq!(prev, len, "regions must cover the whole body");
}

// ---------------- JSON: strictness, depth, numbers ----------------
#[test]
fn pass_j1_nested_escaped_duplicate_alias_refuses_whole_body() {
    let raw = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"a","t\u0065xt":"b"}]}]}"#;
    let d = parse(raw, p::Format::Request);
    assert_eq!(d.items.len(), 1);
    assert_eq!(d.items[0].kind, p::Kind::Malformed);
    assert!(d.json.is_none());
}
#[test]
fn pass_j2_depth_limit_holds_despite_unbounded_depth_feature_and_does_not_overflow() {
    // serde_json is built with feature "unbounded_depth"; the limit must still apply.
    for n in [100_000usize, 1_000_000] {
        let deep = "[".repeat(n);
        let d = parse(deep.as_bytes(), p::Format::Response);
        assert_eq!(d.items[0].kind, p::Kind::Malformed);
        let sse_deep = format!("data: {}\n\n", "{\"a\":".repeat(n / 5));
        let d = parse(sse_deep.as_bytes(), p::Format::Sse);
        assert_eq!(d.items[0].kind, p::Kind::Malformed);
    }
    // Boundary: 127 nested arrays inside a root object parse; 200 do not.
    let ok = format!("{{\"type\":\"message\",\"content\":[],\"x\":{}0{}}}", "[".repeat(126), "]".repeat(126));
    assert_eq!(parse(ok.as_bytes(), p::Format::Response).items[0].kind, p::Kind::Protocol);
}
#[test]
fn char_j3_numeric_fidelity_of_retained_json() {
    // Integers beyond u64/i64 become f64 in the retained Value; exponent overflow
    // makes the WHOLE body Malformed. Raw bytes remain reachable only via region.
    let raw = br#"{"type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"n":123456789012345678901234567890,"m":1.0,"z":-0}}"#;
    let d = parse(raw, p::Format::Response);
    let n = d.json.as_ref().unwrap()["usage"]["n"].to_string();
    let m = d.json.as_ref().unwrap()["usage"]["m"].to_string();
    let z = d.json.as_ref().unwrap()["usage"]["z"].to_string();
    println!("J3 big integer retained as {n}; 1.0 as {m}; -0 as {z}");
    assert_ne!(n, "123456789012345678901234567890", "lossy: observed");
    let over = br#"{"type":"message","role":"assistant","content":[{"type":"text","text":"readable"}],"usage":{"n":1e400}}"#;
    let d = parse(over, p::Format::Response);
    println!("J3 1e400 body -> items {:?}", d.items.iter().map(|i| i.kind).collect::<Vec<_>>());
    assert_eq!(d.items.len(), 1);
    assert_eq!(d.items[0].kind, p::Kind::Malformed);
}
#[test]
fn pass_j4_pointers_resolve_and_request_history_is_context_not_observation() {
    let raw = br#"{"model":"x","system":[{"type":"text","text":"S"}],"messages":[{"role":"user","content":"q1"},{"role":"assistant","content":"a1"},{"role":"user","content":"q2"},{"role":"assistant","content":"a1"}]}"#;
    let d = parse(raw, p::Format::Request);
    assert_eq!(d.format, p::Format::Request);
    let ctx = d.items.iter().filter(|i| i.kind == p::Kind::Context).count();
    assert_eq!(ctx, 4, "every message is Context, repeated history not coalesced or dropped");
    for i in &d.items {
        if let Some(ptr) = &i.pointer {
            assert!(d.json.as_ref().unwrap().pointer(ptr).is_some(), "{ptr}");
        }
        assert!(i.coarse);
        assert_eq!(i.region, 0..raw.len());
    }
    assert!(!d.coherent_stop_observed);
}
#[test]
fn char_j5_nested_tool_result_content_is_not_rendered() {
    let raw = br#"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"NESTED-RESULT"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}]}]}]}"#;
    let d = parse(raw, p::Format::Request);
    let tr: Vec<_> = d.items.iter().filter(|i| i.kind == p::Kind::ToolResult).collect();
    println!("J5 tool_result items: {:?}", tr.iter().map(|i| (&i.text, &i.issues)).collect::<Vec<_>>());
    assert!(d.items.iter().all(|i| i.text.as_deref() != Some("NESTED-RESULT")), "observed: nested text not surfaced");
    assert!(tr[0].issues.is_empty(), "observed: no issue tells the reader content was not interpreted");
}
#[test]
fn char_j6_issue_labelling_consistency() {
    let d = parse(br#"{"type":"future_root","x":1}"#, p::Format::Response);
    let u = d.items.iter().find(|i| i.kind == p::Kind::Unsupported).unwrap();
    println!("J6 unknown root type issues={:?}", u.issues);
    let d = parse(br#"{"type":"message","role":"user","content":"x"}"#, p::Format::Response);
    println!("J6 response role=user items={:?}", d.items.iter().map(|i| (i.kind, &i.role, &i.issues)).collect::<Vec<_>>());
    let d = parse(br#"{"messages":[{"role":"user"}]}"#, p::Format::Request);
    println!("J6 message without content items={:?}", d.items.iter().map(|i| (i.kind, &i.pointer, &i.issues)).collect::<Vec<_>>());
}
#[test]
fn pass_j7_hostile_strings_are_inert_data() {
    let raw = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"<script>alert(1)</script>\u0000\u202e"},{"type":"document","source":{"type":"url","url":"javascript:alert(1)"}}]}]}"#;
    let d = parse(raw, p::Format::Request);
    assert!(d.items.iter().any(|i| i.text.as_deref() == Some("<script>alert(1)</script>\u{0}\u{202e}")));
    let att = d.items.iter().find(|i| i.kind == p::Kind::Attachment).unwrap();
    assert!(att.text.is_none(), "attachment URL is not promoted to text/link");
}

// ---------------- SSE framing and state ----------------
#[test]
fn pass_s1_independent_writer_all_newlines_no_names() {
    for nl in ["\n", "\r\n", "\r"] {
        for names in [true, false] {
            let b = sse(&text_stream(), nl, names);
            let d = parse(&b, p::Format::Sse);
            assert!(d.coherent_stop_observed, "nl={nl:?} names={names}");
            tiles(&d, b.len());
        }
    }
    // Mixed newline forms inside one stream; CR immediately followed by CRLF.
    let b = b"event: ping\rdata: {\"type\":\"ping\"}\r\n\ndata: {\"type\":\"ping\"}\r\r\n".to_vec();
    let d = parse(&b, p::Format::Sse);
    assert_eq!(d.items.len(), 2);
    assert!(d.items.iter().all(|i| i.issues.is_empty()));
    tiles(&d, b.len());
}
#[test]
fn char_s2_bom_and_unknown_field_lines() {
    // WHATWG strips a leading BOM. Here a BOM before "data:" makes the field name unknown.
    let mut b = "\u{feff}".as_bytes().to_vec();
    b.extend(sse(&text_stream(), "\n", false));
    let d = parse(&b, p::Format::Sse);
    println!("S2 BOM: first={:?} issues={:?} coherent={}", d.items[0].kind, d.items[0].issues, d.coherent_stop_observed);
    assert!(!d.coherent_stop_observed);
    // A misspelled field silently drops its value; the dataless block carries no issue.
    let mut b = sse(&text_stream(), "\n", true);
    b.extend(b"dta: {\"type\":\"message_start\"}\n\n");
    let d = parse(&b, p::Format::Sse);
    let last = d.items.last().unwrap();
    println!("S2 garbage-after-stop: kind={:?} issues={:?} event={:?} coherent={}", last.kind, last.issues, last.event, d.coherent_stop_observed);
}
#[test]
fn char_s3_dataless_named_block_after_stop() {
    let mut b = sse(&text_stream(), "\n", true);
    b.extend(b"event: message_start\n\n");
    let d = parse(&b, p::Format::Sse);
    let last = d.items.last().unwrap();
    println!("S3 dataless 'event: message_start' after stop: kind={:?} issues={:?} coherent={}", last.kind, last.issues, d.coherent_stop_observed);
}
#[test]
fn pass_s4_lifecycle_contradictions_never_cohere() {
    let v = text_stream();
    let mut cases: Vec<(&str, Vec<Value>)> = vec![];
    let mut c = v.clone();
    c.insert(5, json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}));
    cases.push(("block-start-after-message_delta", c));
    let mut c = v.clone();
    c.insert(4, json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"late"}}));
    cases.push(("delta-after-block-stop", c));
    let mut c = v.clone();
    c.remove(4);
    cases.push(("stop-without-message_delta", c));
    let mut c = v.clone();
    c.insert(4, json!({"type":"content_block_stop","index":0}));
    cases.push(("double-block-stop", c));
    let mut c = v.clone();
    c.insert(1, ms());
    cases.push(("double-message_start", c));
    let mut c = v.clone();
    c.insert(3, json!({"type":"error","error":{"type":"overloaded_error"}}));
    cases.push(("error-mid-stream", c));
    let mut c = v.clone();
    c[2]["index"] = json!(-1);
    cases.push(("negative-index", c));
    let mut c = v.clone();
    c[2]["index"] = json!("0");
    cases.push(("string-index", c));
    let mut c = v.clone();
    c[1]["index"] = json!(1.5);
    cases.push(("float-index", c));
    let mut c = v.clone();
    c[3]["index"] = json!(9);
    cases.push(("stop-unknown-index", c));
    let mut c = v.clone();
    c.push(mstop());
    cases.push(("double-message_stop", c));
    let mut c = v.clone();
    c[0]["message"]["content"] = json!([{"type":"text","text":"prefilled"}]);
    cases.push(("nonempty-initial-content", c));
    for (name, c) in cases {
        let b = sse(&c, "\n", true);
        let d = parse(&b, p::Format::Sse);
        assert!(!d.coherent_stop_observed, "{name} cohered");
        assert!(d.items.iter().any(|i| !i.issues.is_empty() || i.kind == p::Kind::Error), "{name} no visible issue");
        tiles(&d, b.len());
    }
}
#[test]
fn char_s5_known_protocol_extensions() {
    // citations_delta is a documented Anthropic text-block delta. It is not
    // interpreted by this adapter version; observe whether it is labelled a
    // contradiction (DeltaType) rather than only Unknown.
    let mut v = text_stream();
    v.insert(3, json!({"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"a"}}}));
    let d = parse(&sse(&v, "\n", true), p::Format::Sse);
    println!("S5 citations_delta issues={:?} kind={:?}", d.items[3].issues, d.items[3].kind);
    // A no-argument tool streams only empty partial_json (fine-grained tool streaming
    // may also). Observe whether "" is flagged invalid tool JSON.
    let d = parse(&sse(&tool_stream(&[""]), "\n", true), p::Format::Sse);
    println!("S5 empty-fragment tool: coherent={} toolJson={}", d.coherent_stop_observed, d.items.iter().any(|i| i.issues.contains(&p::Issue::ToolJson)));
    let d = parse(&sse(&tool_stream(&["", "{\"a\":", "\"\\u00e9\"}"]), "\n", true), p::Format::Sse);
    assert!(d.coherent_stop_observed, "leading empty fragment then valid object must cohere");
    let d = parse(&sse(&tool_stream(&[]), "\n", true), p::Format::Sse);
    println!("S5 no-delta tool (input {{}} placeholder only): coherent={}", d.coherent_stop_observed);
}
#[test]
fn pass_s6_tool_fragment_strictness() {
    for (frags, ok) in [
        (vec!["{\"a\":1}", " "], true),
        (vec!["{\"a\":1}{"], false),
        (vec!["{\"a\":1,\"\\u0061\":2}"], false),
        (vec!["{\"a\":", "1e400}"], false),
        (vec!["\"str\""], false),
        (vec!["null"], false),
    ] {
        let d = parse(&sse(&tool_stream(&frags), "\n", true), p::Format::Sse);
        assert_eq!(d.coherent_stop_observed, ok, "{frags:?}");
    }
}
#[test]
fn pass_s7_invalid_utf8_and_sentinel_names() {
    let mut b = b"event: \xff\xfe\ndata: {\"type\":\"ping\"}\n\n".to_vec();
    let d = parse(&b, p::Format::Sse);
    assert!(d.items[0].issues.contains(&p::Issue::EventName));
    b = b"data: {\"type\":\"ping\",\"x\":\"\xff\"}\n\n".to_vec();
    let d = parse(&b, p::Format::Sse);
    assert_eq!(d.items[0].kind, p::Kind::Malformed);
}
// Deterministic fuzz: random SSE token soup. Properties: no panic, tiling,
// coherent => no item issue, no Malformed/Truncated/Unsupported/Error, and last
// data-bearing item is message_stop.
#[test]
fn pass_s8_fuzz_tiling_and_coherence_implies_clean() {
    let tokens: Vec<Vec<u8>> = [
        "data: ", "data:", "event: ", "event: ping", ":c", "\n", "\r", "\r\n", "\n\n", "{", "}", "\"type\":", "\"message_start\"", "\"ping\"",
        "\"message_stop\"", "\"message_delta\"", "\"content_block_start\"", "\"index\":0", ",", "\"delta\":{}", "id: 1", "x", "é",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let mut seed = 0x9e3779b97f4a7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let full = sse(&text_stream(), "\n", true);
    for round in 0..20000 {
        let mut b = vec![];
        if round % 2 == 0 {
            // mutate a valid stream: delete/duplicate/insert a token at a random spot
            b = full.clone();
            let at = (next() as usize) % (b.len() + 1);
            match next() % 3 {
                0 => {
                    let end = (at + 1 + (next() as usize % 8)).min(b.len());
                    b.drain(at.min(end)..end);
                }
                1 => {
                    let t = &tokens[(next() as usize) % tokens.len()];
                    b.splice(at..at, t.iter().copied());
                }
                _ => b.truncate(at),
            }
        } else {
            for _ in 0..(next() % 40) {
                b.extend(&tokens[(next() as usize) % tokens.len()]);
            }
        }
        let d = p::interpret(&b, p::Format::Sse, lim()).unwrap();
        tiles(&d, b.len());
        if d.coherent_stop_observed {
            for i in &d.items {
                assert!(i.issues.is_empty(), "coherent with issue: {:?}", String::from_utf8_lossy(&b));
                assert!(!matches!(i.kind, p::Kind::Malformed | p::Kind::Truncated | p::Kind::Unsupported | p::Kind::Error));
            }
            let last = d.items.iter().rev().find(|i| i.event.is_some()).unwrap();
            assert_eq!(last.event.as_ref().unwrap()["type"], "message_stop");
        }
    }
}
#[test]
fn pass_j8_fuzz_request_json_no_panic_and_pointers_resolve() {
    let base = br#"{"system":"s","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"tool_result","content":"r"}]},{"role":"assistant","content":"b"}]}"#.to_vec();
    let mut seed = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..20000 {
        let mut b = base.clone();
        let at = (next() as usize) % b.len();
        let ch = b"{}[],:\"a01\\ "[(next() as usize) % 12];
        match next() % 2 {
            0 => b[at] = ch,
            _ => b.insert(at, ch),
        }
        for f in [p::Format::Request, p::Format::Response] {
            let d = p::interpret(&b, f, lim()).unwrap();
            assert!(!d.items.is_empty());
            for i in &d.items {
                assert_eq!(i.region, 0..b.len());
                if let (Some(ptr), Some(j)) = (&i.pointer, &d.json) {
                    assert!(j.pointer(ptr).is_some(), "{ptr}");
                }
            }
        }
    }
}

// ---------------- Budgets ----------------
#[test]
fn pass_b1_exact_edges_for_request_format() {
    let raw = br#"{"system":"s","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"thinking","thinking":"t"}]}]}"#;
    let d = parse(raw, p::Format::Request);
    let mut l = lim();
    l.input_bytes = raw.len();
    l.items = d.items.len();
    l.output_bytes = d.output_bytes;
    l.scan_bytes = d.scanned_bytes;
    let ok = p::interpret(raw, p::Format::Request, l.clone()).unwrap();
    assert_eq!(ok.items.len(), d.items.len());
    for (w, e) in [(0, "input bytes"), (1, "items"), (2, "output bytes"), (3, "scan bytes")] {
        let mut b = l.clone();
        match w {
            0 => b.input_bytes -= 1,
            1 => b.items -= 1,
            2 => b.output_bytes -= 1,
            _ => b.scan_bytes -= 1,
        }
        assert_eq!(p::interpret(raw, p::Format::Request, b).unwrap_err(), p::Error::Limit(e));
    }
    // Absolute accounting: request scan = body length (one strict parse).
    assert_eq!(d.scanned_bytes, raw.len() as u64);
}
#[test]
fn pass_b2_duration_bounds() {
    let mut l = lim();
    l.duration = Duration::from_secs(3601);
    assert_eq!(p::interpret(b"", p::Format::Sse, l).unwrap_err(), p::Error::Limit("duration"));
    let mut l = lim();
    l.duration = Duration::from_nanos(1);
    // A 1ns deadline must not produce a success for non-trivial work.
    let big = sse(&text_stream(), "\n", true).repeat(2000);
    let mut l2 = l.clone();
    l2.input_bytes = big.len();
    assert!(p::interpret(&big, p::Format::Sse, l2).is_err());
}

// ---------------- map_region ----------------
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn frame(ordinal: u64, elapsed: u64, event: Value, body: &[u8]) -> Vec<u8> {
    let h = serde_json::to_vec(&json!({"version":2,"attempt":A,"observer":"collector","ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":elapsed,"unconfirmed_before":0,"event":event})).unwrap();
    let mut v = b"KANC2".to_vec();
    v.extend((h.len() as u32).to_be_bytes());
    v.extend(h);
    v.extend(body);
    v
}
fn rc(n: u64, off: u64, body: &[u8]) -> Vec<u8> {
    frame(n, 0, json!({"type":"response-chunk","offset":off}), body)
}
fn qc(n: u64, off: u64, body: &[u8]) -> Vec<u8> {
    frame(n, 0, json!({"type":"request-chunk","offset":off}), body)
}
fn ins(raw: &[Vec<u8>]) -> Vec<a::Input<'_>> {
    raw.iter()
        .map(|b| a::Input { scope: [7; 32], writer: "w", payload: a::Payload::Available(b) })
        .collect()
}
fn asm<'a>(i: &[a::Input<'a>]) -> a::Assembly<'a> {
    a::assemble(
        i,
        a::Limits {
            occurrences: 1000,
            input_bytes: 8 << 20,
            scan_bytes: 64 << 20,
            assembled_bytes: 8 << 20,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap()
}
#[test]
fn pass_m1_multibyte_escaped_sse_spans_across_three_chunks_and_triplicates() {
    let body = sse(&vec![ms(), json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}), json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"é😀\"\\\u{2028}"}}), json!({"type":"content_block_stop","index":0}), md(), mstop()], "\r\n", false);
    let n = body.len();
    for (x, y) in [(1, 2), (n / 3, 2 * n / 3), (n - 2, n - 1)] {
        let c0 = rc(0, 0, &body[..x]);
        let c1 = rc(1, x as u64, &body[x..y]);
        let c2 = rc(2, y as u64, &body[y..]);
        let raw = vec![c2.clone(), c0.clone(), c1.clone(), c0.clone(), c2.clone(), c2];
        let i = ins(&raw);
        let ab = asm(&i);
        let s = &ab.groups[0].response;
        assert!(s.issues.is_empty());
        let d = parse(s.contiguous.as_ref().unwrap(), p::Format::Sse);
        assert!(d.coherent_stop_observed);
        assert_eq!(d.items[2].text.as_deref(), Some("é😀\"\\\u{2028}"));
        for it in &d.items {
            let spans = p::map_region(s, &i, it.region.clone(), lim()).unwrap();
            // Concatenate primary (first-listed) source per segment; check every
            // duplicate covers the identical bytes.
            let mut by_seg: Vec<Vec<u8>> = vec![];
            let mut prim: Vec<u8> = vec![];
            for sp in &spans {
                let bytes = raw[sp.input][sp.bytes.clone()].to_vec();
                by_seg.push(bytes);
            }
            let mut k = 0;
            for seg in &s.segments {
                let a0 = (seg.offset as usize).max(it.region.start);
                let b0 = (seg.offset as usize + seg.length).min(it.region.end);
                if a0 < b0 {
                    let first = &by_seg[k];
                    for j in 0..seg.sources.len() {
                        assert_eq!(&by_seg[k + j], first);
                    }
                    prim.extend(first);
                    k += seg.sources.len();
                }
            }
            assert_eq!(k, spans.len(), "no extra/missing citations");
            assert_eq!(prim, &body[it.region.clone()]);
        }
    }
}
fn base_stream() -> (Vec<Vec<u8>>, Vec<u8>) {
    (vec![rc(0, 0, b"abc"), rc(1, 3, b"def")], b"abcdef".to_vec())
}
#[test]
fn pass_m2_forged_duplicate_with_different_frame_refuses() {
    // Same attempt/offset/body, different ordinal+elapsed: never an exact duplicate.
    let (mut raw, _) = base_stream();
    raw.push(frame(9, 5, json!({"type":"response-chunk","offset":0}), b"abc"));
    let i = ins(&raw);
    let mut ab = asm(&ins(&raw[..2]));
    let s = &mut ab.groups[0].response;
    s.segments[0].sources.push(a::SourceSpan { input: 2, bytes: raw[2].len() - 3..raw[2].len() });
    assert_eq!(p::map_region(s, &i, 0..6, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn pass_m3_forged_cross_direction_segment_refuses() {
    let (mut raw, _) = base_stream();
    raw[1] = qc(1, 3, b"def");
    let i = ins(&raw);
    let ok_raw = base_stream().0;
    let mut ab = asm(&ins(&ok_raw));
    let s = &mut ab.groups[0].response;
    s.segments[1].sources[0].bytes = raw[1].len() - 3..raw[1].len();
    assert_eq!(p::map_region(s, &i, 0..6, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn pass_m4_forged_frame_offset_refuses() {
    let raw = vec![rc(0, 0, b"abc"), rc(1, 100, b"def")];
    let i = ins(&raw);
    let ok_raw = base_stream().0;
    let mut ab = asm(&ins(&ok_raw));
    let s = &mut ab.groups[0].response;
    s.segments[1].sources[0].bytes = raw[1].len() - 3..raw[1].len();
    assert_eq!(p::map_region(s, &i, 0..6, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn pass_m5_forged_span_into_header_bytes_refuses() {
    // Body "aaa": the header's attempt string also contains "aaa". A span that
    // points into the header has identical bytes but is not the frame body.
    let raw = vec![rc(0, 0, b"aaa")];
    let i = ins(&raw);
    let mut ab = asm(&i);
    let s = &mut ab.groups[0].response;
    let pos = raw[0].windows(3).position(|w| w == b"aaa").unwrap();
    assert!(pos + 3 < raw[0].len() - 3);
    s.segments[0].sources[0].bytes = pos..pos + 3;
    assert_eq!(p::map_region(s, &i, 0..3, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn pass_m6_forged_trailing_contiguous_bytes_refuse() {
    let (raw, _) = base_stream();
    let i = ins(&raw);
    let mut ab = asm(&i);
    let s = &mut ab.groups[0].response;
    s.contiguous.as_mut().unwrap().push(b'Z');
    assert_eq!(p::map_region(s, &i, 6..7, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn pass_m7_citation_and_work_edges_and_empty_regions() {
    let (raw, _) = base_stream();
    let mut raw = raw;
    raw.push(raw[0].clone());
    let i = ins(&raw);
    let ab = asm(&i);
    let s = &ab.groups[0].response;
    // 0..6 cites seg0 twice (dup) + seg1 once = 3
    let mut l = lim();
    l.citations = 3;
    assert_eq!(p::map_region(s, &i, 0..6, l.clone()).unwrap().len(), 3);
    l.citations = 2;
    assert_eq!(p::map_region(s, &i, 0..6, l).unwrap_err(), p::Error::Limit("citations"));
    // Empty region at a segment boundary: observe what is cited.
    let e = p::map_region(s, &i, 3..3, lim()).unwrap();
    println!("M7 empty region 3..3 cites {e:?}");
    let e = p::map_region(s, &i, 6..6, lim()).unwrap();
    println!("M7 empty region 6..6 cites {e:?}");
    // Unrelated stream issue blocks all mapping.
    let mut ab2 = asm(&i);
    ab2.groups[0].response.issues.push(a::StreamIssue::OrdinalConflict);
    assert_eq!(p::map_region(&ab2.groups[0].response, &i, 0..1, lim()).unwrap_err(), p::Error::Mapping);
}
#[test]
fn char_m8_valid_assembly_with_empty_chunk_cannot_be_mapped() {
    // Recorder::record explicitly allows an empty chunk; assembly accepts an
    // empty frame at a covered offset without an Overlap issue.
    let raw = vec![rc(0, 0, b"abcdef"), rc(1, 3, b""), rc(2, 6, b"gh")];
    let i = ins(&raw);
    let ab = asm(&i);
    let s = &ab.groups[0].response;
    println!("M8 issues={:?} contiguous={:?} segs={:?}", s.issues, s.contiguous.as_deref().map(String::from_utf8_lossy), s.segments.iter().map(|g| (g.offset, g.length)).collect::<Vec<_>>());
    assert!(s.issues.is_empty());
    assert_eq!(s.contiguous.as_deref(), Some(&b"abcdefgh"[..]));
    let r = p::map_region(s, &i, 0..8, lim());
    println!("M8 map_region(0..8) = {r:?}");
    // Also: empty chunk at offset 0 listed after the nonempty one at offset 0.
    let raw = vec![rc(0, 0, b"abc"), rc(1, 0, b"")];
    let i = ins(&raw);
    let ab = asm(&i);
    let s = &ab.groups[0].response;
    println!("M8b issues={:?} contiguous={:?} map={:?}", s.issues, s.contiguous, p::map_region(s, &i, 0..3, lim()));
}
#[test]
fn char_m9_empty_request_body_and_request_end_only() {
    let raw = vec![frame(0, 0, json!({"type":"request-end","bytes":0}), b"")];
    let i = ins(&raw);
    let ab = asm(&i);
    let s = &ab.groups[0].request;
    let d = parse(s.contiguous.as_ref().unwrap(), p::Format::Request);
    let spans = p::map_region(s, &i, d.items[0].region.clone(), lim()).unwrap();
    println!("M9 empty request: items={:?} spans={spans:?}", d.items.iter().map(|x| (x.kind, x.region.clone())).collect::<Vec<_>>());
}
