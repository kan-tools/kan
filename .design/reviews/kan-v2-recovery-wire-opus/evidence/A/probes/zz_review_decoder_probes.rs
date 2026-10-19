#![cfg(feature = "v2-crypto")]
//! Reviewer probes for c04ee13 (temporary; copied into tests/ only while run).
use kan::evidence_reconstruction::{decode, Decoded, Error, Unsupported, MAX_FRAME, MAX_HEADER};
use kan::evidence_capture::CHUNK;
use serde_json::{json, Value};

const ATTEMPT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn wire(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = b"KANC2".to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(body);
    bytes
}
fn base(event: Value) -> Value {
    json!({"version":2,"attempt":ATTEMPT,"observer":"gateway","ordinal":7,
           "observed_at_unix_micros":null,"elapsed_micros":1,"unconfirmed_before":0,"event":event})
}
fn events() -> Vec<Value> {
    vec![
        json!({"type":"started","method":"POST","route":"/"}),
        json!({"type":"request-chunk","offset":0}),
        json!({"type":"request-end","bytes":0}),
        json!({"type":"forwarding-intent"}),
        json!({"type":"transport-link","exchange":"01".repeat(32)}),
        json!({"type":"http-metadata-chunk","direction":"request","offset":0,"total":0}),
        json!({"type":"http-metadata","direction":"response","headers":[["a","b"]],"omitted":["c"]}),
        json!({"type":"response-head","status":200}),
        json!({"type":"response-chunk","offset":0}),
        json!({"type":"terminal","outcome":"completed"}),
    ]
}
fn label(r: &Result<Decoded<'_>, Error>) -> String {
    match r {
        Ok(Decoded::Opaque) => "Opaque".into(),
        Ok(Decoded::Unsupported(u)) => format!("Unsupported({u:?})"),
        Ok(Decoded::Capture(_)) => "Capture".into(),
        Err(e) => format!("Err({e:?})"),
    }
}

/// PA1: no accepted recognized frame may silently narrow its JSON projection.
/// Property: for every Capture, to_value(header) == the parsed header value.
#[test]
fn review_pa1_capture_projection_is_lossless_over_mutation_corpus() {
    let mut out = String::new();
    let mut captures = 0;
    let mut violations = Vec::new();
    let replacements = [
        json!(null), json!(0), json!(-1), json!(1.0), json!(1e0), json!("x"), json!(true),
        json!([]), json!({}), json!(18446744073709551615u64), json!([["a","b","c"]]), json!([["a"]]),
        json!({"0":"a","1":"b"}),
    ];
    for event in events() {
        let mut corpus: Vec<(String, Value)> = vec![("base".into(), base(event.clone()))];
        let header = base(event.clone());
        for key in header.as_object().unwrap().keys() {
            let mut v = header.clone();
            v.as_object_mut().unwrap().remove(key);
            corpus.push((format!("drop-top-{key}"), v));
            for (i, r) in replacements.iter().enumerate() {
                if key == "event" { continue; }
                let mut v = header.clone();
                v[key] = r.clone();
                corpus.push((format!("set-top-{key}-{i}"), v));
            }
        }
        for key in event.as_object().unwrap().keys() {
            if key == "type" { continue; }
            let mut v = header.clone();
            v["event"].as_object_mut().unwrap().remove(key);
            corpus.push((format!("drop-event-{key}"), v));
            for (i, r) in replacements.iter().enumerate() {
                let mut v = header.clone();
                v["event"][key] = r.clone();
                corpus.push((format!("set-event-{key}-{i}"), v));
            }
        }
        for (i, extra) in [json!(1), json!(null), json!({"a":[1]})].iter().enumerate() {
            let mut v = header.clone();
            v["extra"] = extra.clone();
            corpus.push((format!("extra-top-{i}"), v));
            let mut v = header.clone();
            v["event"]["extra"] = extra.clone();
            corpus.push((format!("extra-event-{i}"), v));
        }
        let kind = event["type"].as_str().unwrap().to_string();
        for (name, v) in corpus {
            let text = serde_json::to_vec(&v).unwrap();
            let bytes = wire(&text, b"");
            let r = decode(&bytes);
            let l = label(&r);
            if let Ok(Decoded::Capture(frame)) = &r {
                captures += 1;
                let projected = serde_json::to_value(&frame.header).unwrap();
                if projected != v {
                    violations.push(format!("{kind}/{name}: parsed={v} projected={projected}"));
                }
            }
            out.push_str(&format!("{kind}\t{name}\t{l}\n"));
        }
    }
    out.push_str(&format!("captures={captures} violations={}\n", violations.len()));
    for v in &violations { out.push_str(&format!("VIOLATION {v}\n")); }
    if let Ok(path) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{path}/pa1-corpus.tsv"), &out).unwrap();
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// PA2: timestamp absent vs null vs values; unknown variants keep precedence.
#[test]
fn review_pa2_timestamp_distinction_and_unsupported_precedence() {
    let mut out = String::new();
    let cases: Vec<(&str, Value, &str)> = vec![
        ("null", json!(null), "Capture"),
        ("zero", json!(0), "Capture"),
        ("u64max", json!(18446744073709551615u64), "Capture"),
        ("negative", json!(-1), "Err(Header)"),
        ("float", json!(1.5), "Err(Header)"),
        ("string", json!("0"), "Err(Header)"),
    ];
    for (name, ts, expected) in cases {
        let mut v = base(json!({"type":"request-end","bytes":3}));
        v["observed_at_unix_micros"] = ts;
        let l = label(&decode(&wire(&serde_json::to_vec(&v).unwrap(), b"")));
        out.push_str(&format!("{name}\t{l}\n"));
        assert_eq!(l, expected, "{name}");
    }
    // Over-u64 literal is written textually since serde_json Value cannot hold it.
    let big = br#"{"version":2,"attempt":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","observer":"gateway","ordinal":7,"observed_at_unix_micros":18446744073709551616,"elapsed_micros":1,"unconfirmed_before":0,"event":{"type":"forwarding-intent"}}"#;
    let l = label(&decode(&wire(big, b"")));
    out.push_str(&format!("over-u64\t{l}\n"));
    assert_eq!(l, "Err(Header)");
    // Absent timestamp in each unknown classification remains Unsupported, as designed.
    for (name, mutate, expected) in [
        ("version", json!({"version":3}), "Unsupported(Version)"),
        ("observer", json!({"observer":"future"}), "Unsupported(Observer)"),
        ("event", json!({"event":{"type":"future","x":1}}), "Unsupported(Event)"),
        ("outcome", json!({"event":{"type":"terminal","outcome":"future"}}), "Unsupported(Outcome)"),
    ] {
        let mut v = base(json!({"type":"forwarding-intent"}));
        v.as_object_mut().unwrap().remove("observed_at_unix_micros");
        for (k, val) in mutate.as_object().unwrap() { v[k] = val.clone(); }
        let l = label(&decode(&wire(&serde_json::to_vec(&v).unwrap(), b"")));
        out.push_str(&format!("absent-ts-unknown-{name}\t{l}\n"));
        assert_eq!(l, expected);
    }
    // Absent timestamp on every recognized event is malformed.
    for event in events() {
        let mut v = base(event.clone());
        v.as_object_mut().unwrap().remove("observed_at_unix_micros");
        let l = label(&decode(&wire(&serde_json::to_vec(&v).unwrap(), b"")));
        out.push_str(&format!("absent-ts-{}\t{l}\n", event["type"]));
        assert_eq!(l, "Err(Header)");
    }
    if let Ok(path) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{path}/pa2-timestamp.tsv"), &out).unwrap();
    }
}

/// PA3: forwarding-intent strictness under escape aliases and duplicates.
#[test]
fn review_pa3_forwarding_intent_aliases() {
    let mk = |event: &str| {
        format!(r#"{{"version":2,"attempt":"{ATTEMPT}","observer":"collector","ordinal":1,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{event}}}"#)
    };
    let mut out = String::new();
    for (name, event, expected) in [
        ("plain", r#"{"type":"forwarding-intent"}"#, "Capture"),
        ("escaped-type-key", r#"{"type":"forwarding-intent"}"#, "Capture"),
        ("escaped-value", r#"{"type":"forwarding-intent"}"#, "Capture"),
        ("extra-escaped-key", r#"{"type":"forwarding-intent","x":1}"#, "Err(Header)"),
        ("dup-type", r#"{"type":"forwarding-intent","type":"forwarding-intent"}"#, "Err(Header)"),
        ("empty-key", r#"{"type":"forwarding-intent","":null}"#, "Err(Header)"),
        ("whitespace", "{ \"type\" : \"forwarding-intent\" }", "Capture"),
    ] {
        let h = mk(event);
        let bytes = wire(h.as_bytes(), b"");
        let l = label(&decode(&bytes));
        out.push_str(&format!("{name}\t{l}\n"));
        assert_eq!(l, expected, "{name}");
    }
    // A forwarding intent may not carry a body either.
    let l = label(&decode(&wire(mk(r#"{"type":"forwarding-intent"}"#).as_bytes(), b"x")));
    out.push_str(&format!("body\t{l}\n"));
    assert_eq!(l, "Err(Body)");
    if let Ok(path) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{path}/pa3-forwarding.tsv"), &out).unwrap();
    }
}

/// PA4: total-size precedence and exact boundaries.
#[test]
fn review_pa4_size_precedence_and_exact_boundaries() {
    let mut out = String::new();
    let mut check = |name: &str, bytes: &[u8], expected: &str| {
        let l = label(&decode(bytes));
        out.push_str(&format!("{name}\tlen={}\t{l}\n", bytes.len()));
        assert_eq!(l, expected, "{name}");
    };
    // Exact maximum recognized frame: MAX_HEADER header (whitespace padded) + CHUNK body.
    let mut header = serde_json::to_vec(&base(json!({"type":"response-chunk","offset":5}))).unwrap();
    header.resize(MAX_HEADER, b' ');
    let max = wire(&header, &vec![0xab; CHUNK]);
    assert_eq!(max.len(), MAX_FRAME);
    check("max-recognized", &max, "Capture");
    let mut over = max.clone();
    over.push(0);
    check("max-recognized+1", &over, "Err(Limit)");
    // Header one over MAX_HEADER with small total.
    let mut h = serde_json::to_vec(&base(json!({"type":"request-end","bytes":1}))).unwrap();
    h.resize(MAX_HEADER + 1, b' ');
    check("header+1", &wire(&h, b""), "Err(Limit)");
    // Truncated KANC2 envelope whose declared length exceeds the input, oversized total.
    let mut t = b"KANC2".to_vec();
    t.extend_from_slice(&u32::MAX.to_be_bytes());
    t.resize(MAX_FRAME + 1, 0);
    check("oversize-declared-huge", &t, "Err(Limit)");
    t.truncate(MAX_FRAME);
    check("maxsize-declared-huge", &t, "Err(Limit)");
    t.truncate(20);
    check("small-declared-huge", &t, "Err(Limit)");
    let mut t = b"KANC2".to_vec();
    t.extend_from_slice(&100u32.to_be_bytes());
    t.extend_from_slice(b"{}");
    check("small-declared-past-end", &t, "Err(Envelope)");
    check("family-prefix-only", b"KANC", "Err(Envelope)");
    let mut u = b"KANC".to_vec();
    u.resize(MAX_FRAME + 10, 0);
    check("family-nul-version-oversize", &u, "Err(Limit)");
    let mut o = b"KAN".to_vec();
    o.resize(MAX_FRAME + 10, 0);
    check("near-prefix-oversize", &o, "Opaque");
    let mut o = b"kanc2".to_vec();
    o.resize(MAX_FRAME + 10, 0);
    check("lowercase-oversize", &o, "Opaque");
    check("empty", b"", "Opaque");
    if let Ok(path) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{path}/pa4-size.tsv"), &out).unwrap();
    }
}

/// PA5: unknown future fields inside unsupported variants accept no semantics,
/// but unsupported classification still observes the family size bound.
#[test]
fn review_pa5_unsupported_is_not_shape_validation() {
    let mut v = base(json!({"type":"future","anything":{"deep":[1,2,3]}}));
    v["unknown_top"] = json!(1);
    let l = label(&decode(&wire(&serde_json::to_vec(&v).unwrap(), b"body")));
    assert_eq!(l, "Unsupported(Event)");
    let _ = Unsupported::Event;
}
