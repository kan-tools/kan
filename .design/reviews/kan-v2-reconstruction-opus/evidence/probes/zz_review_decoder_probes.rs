// Reviewer-authored hostile probes (temporary; copied into tests/ only while run).
#![cfg(feature = "v2-crypto")]
use kan::evidence_capture::{Event, Observer, Recorder, Sink, Unconfirmed, CHUNK};
use kan::evidence_reconstruction::{decode, Decoded, MAX_FRAME, MAX_HEADER};

const ATT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn wire_magic(magic: &[u8], header: &str, body: &[u8]) -> Vec<u8> {
    let mut b = magic.to_vec();
    b.extend_from_slice(&(header.len() as u32).to_be_bytes());
    b.extend_from_slice(header.as_bytes());
    b.extend_from_slice(body);
    b
}
fn wire(header: &str, body: &[u8]) -> Vec<u8> {
    wire_magic(b"KANC2", header, body)
}
fn hdr(event: &str) -> String {
    format!(r#"{{"version":2,"attempt":"{ATT}","observer":"gateway","ordinal":1,"observed_at_unix_micros":5,"elapsed_micros":6,"unconfirmed_before":0,"event":{event}}}"#)
}
fn show(label: &str, bytes: &[u8]) -> String {
    let r = match decode(bytes) {
        Ok(Decoded::Opaque) => "Opaque".to_string(),
        Ok(Decoded::Unsupported(u)) => format!("Unsupported({u:?})"),
        Ok(Decoded::Capture(f)) => format!(
            "Capture(event={:?}, header_span={:?}, body_span={:?}, observed_at={:?})",
            f.header.event, f.header_span, f.body_span, f.header.observed_at_unix_micros
        ),
        Err(e) => format!("Err({e:?})"),
    };
    println!("PROBE {label}: {r}");
    r
}

#[test]
fn review_probe_table() {
    // P1 unit-variant extra fields (serde internally-tagged unit variant).
    show("P1 forwarding-intent+extra", &wire(&hdr(r#"{"type":"forwarding-intent","smuggled":{"a":1}}"#), b""));
    // P2 struct-variant extra fields (control).
    show("P2 terminal+extra", &wire(&hdr(r#"{"type":"terminal","outcome":"completed","x":1}"#), b""));
    // P3 Option field omitted (Recorder always emits it).
    let p3 = format!(r#"{{"version":2,"attempt":"{ATT}","observer":"gateway","ordinal":1,"elapsed_micros":6,"unconfirmed_before":0,"event":{{"type":"forwarding-intent"}}}}"#);
    show("P3 observed_at omitted", &wire(&p3, b""));
    // P4 oversize unknown envelope versions (historic KANC1 and future KANC3).
    let mut big1 = b"KANC1".to_vec();
    big1.resize(MAX_FRAME + 1, 0);
    show("P4a KANC1 oversize", &big1);
    let mut big3 = b"KANC3".to_vec();
    big3.resize(MAX_FRAME + 1, 0);
    show("P4b KANC3 oversize", &big3);
    show("P4c KANC1 tiny", b"KANC1");
    // P5 oversize declared header length for unknown version (header > MAX_HEADER).
    let mut p5 = wire(&hdr(r#"{"type":"forwarding-intent"}"#).replace("\"version\":2", "\"version\":3"), b"");
    p5[5..9].copy_from_slice(&((MAX_HEADER + 1) as u32).to_be_bytes());
    show("P5 header-version3 with oversize declared length", &p5);
    // P6 escaped identifier text that decodes to valid lowercase hex.
    let esc = hdr(r#"{"type":"forwarding-intent"}"#).replacen("\"0123", "\"\\u0030123", 1);
    show("P6 escaped attempt", &wire(&esc, b""));
    // P7 escaped event type.
    show("P7 escaped type", &wire(&hdr(r#"{"type":"forwarding-intent"}"#), b""));
    // P8 nesting at the serde_json recursion limit inside unsupported variant.
    for depth in [126usize, 127, 128] {
        let ev = format!(r#"{{"type":"future","n":{}0{}}}"#, "[".repeat(depth), "]".repeat(depth));
        show(&format!("P8 unsupported nest depth {depth}"), &wire(&hdr(&ev), b""));
    }
    // P9 duplicate key nested in array of unknown event, and in HttpMetadata headers.
    show("P9 dup in unknown-event array", &wire(&hdr(r#"{"type":"future","a":[[{"k":1,"k":2}]]}"#), b""));
    // P10 version as 2e0 / 2.0 / "2" / 258 / -2
    for v in ["2e0", "\"2\"", "258", "-2", "02"] {
        show(&format!("P10 version {v}"), &wire(&hdr(r#"{"type":"forwarding-intent"}"#).replace("\"version\":2", &format!("\"version\":{v}")), b""));
    }
    // P11 unknown observer with missing event; unknown version with missing everything.
    show("P11a unknown observer no event", &wire(&format!(r#"{{"version":2,"observer":"x"}}"#), b""));
    show("P11b version3 only", &wire(r#"{"version":3}"#, b""));
    show("P11c version3 non-object event", &wire(r#"{"version":3,"event":7}"#, b""));
    // P12 observer known, kind unknown, but body attached (unknown event may carry body).
    show("P12 future event with body", &wire(&hdr(r#"{"type":"future"}"#), b"body"));
    // P13 terminal: outcome missing / outcome non-string.
    show("P13a terminal no outcome", &wire(&hdr(r#"{"type":"terminal"}"#), b""));
    show("P13b terminal outcome 1", &wire(&hdr(r#"{"type":"terminal","outcome":1}"#), b""));
    // P14 http-metadata wrong tuple arity / status overflow / negative zero ordinal.
    show("P14a header tuple arity3", &wire(&hdr(r#"{"type":"http-metadata","direction":"r","headers":[["a","b","c"]],"omitted":[]}"#), b""));
    show("P14b status 65536", &wire(&hdr(r#"{"type":"response-head","status":65536}"#), b""));
    show("P14c ordinal -0", &wire(&hdr(r#"{"type":"forwarding-intent"}"#).replace("\"ordinal\":1", "\"ordinal\":-0"), b""));
    // P15 header length exactly 0 and leading BOM.
    show("P15a empty header", &wire("", b""));
    show("P15b BOM header", &wire(&format!("\u{feff}{}", hdr(r#"{"type":"forwarding-intent"}"#)), b""));
    // P16 leading/trailing whitespace inside declared header range.
    show("P16 whitespace-wrapped header", &wire(&format!(" \n{}\t ", hdr(r#"{"type":"forwarding-intent"}"#)), b""));
    // P17 chunk event with exactly CHUNK body, and chunk with empty body.
    let f = wire(&hdr(r#"{"type":"response-chunk","offset":0}"#), &vec![7; CHUNK]);
    show("P17a chunk CHUNK body", &f);
    show("P17b chunk empty body", &wire(&hdr(r#"{"type":"response-chunk","offset":0}"#), b""));
    // P18 transport-link uppercase exchange (Recorder unhex is lowercase-only).
    show("P18 uppercase exchange", &wire(&hdr(&format!(r#"{{"type":"transport-link","exchange":"{}"}}"#, ATT.to_uppercase())), b""));
    // P19 unknown top-level field on version 2 known observer but unknown event: unsupported.
    show("P19 unknown event + extra top-level", &wire(&hdr(r#"{"type":"future"}"#).replace("\"version\":2", "\"version\":2,\"zzz\":1"), b""));
    // P20 lone low surrogate in unknown variant string.
    show("P20 lone surrogate in unsupported", &wire(&hdr(r#"{"type":"future","s":"\udc00"}"#), b""));
    // P21 KANC prefix with lowercase/other magic.
    show("P21 kanc2 lowercase", &wire_magic(b"kanc2", "{}", b""));
}

#[test]
fn review_probe_unit_variant_extra_is_strict() {
    // Assertion form of P1: a recognized frame should not silently drop fields.
    let bytes = wire(&hdr(r#"{"type":"forwarding-intent","smuggled":1}"#), b"");
    let r = decode(&bytes);
    assert!(r.is_err(), "unit variant extra field was recognized: {:?}", r.map(|d| matches!(d, Decoded::Capture(_))));
}

#[derive(Default)]
struct Memory(Vec<Vec<u8>>);
impl Sink for Memory {
    fn admit(&mut self, _: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        self.0.push(frame.to_vec());
        Ok(())
    }
}

#[test]
fn review_probe_recorder_boundary_forms_roundtrip() {
    // Production recorder boundary shapes: max route/method, unicode-heavy metadata,
    // largest permissible chunk, drop-terminal. Every recorded frame must be Capture.
    let mut memory = Memory::default();
    let mut notify = |_: &kan::evidence_capture::Health| {};
    {
        let mut r = Recorder::new(Observer::Collector, &mut memory, &mut notify).unwrap();
        r.record(Event::Started { method: "M".repeat(32), route: "é".repeat(1024) }, b"").unwrap();
        r.record(Event::RequestChunk { offset: u64::MAX }, &vec![0xff; CHUNK]).unwrap();
        r.record(Event::HttpMetadataChunk { direction: "\u{2028}\"\\".into(), offset: 0, total: u64::MAX }, &[0; 0]).unwrap();
        r.record(Event::HttpMetadata { direction: "d".into(), headers: vec![("k".repeat(1000), "\u{0}\u{1f}\u{7f}😀".repeat(1000))], omitted: vec!["x".into(); 100] }, b"").unwrap();
        // Drop emits terminal outcome-unknown.
    }
    assert!(memory.0.len() >= 5, "{}", memory.0.len());
    for (i, bytes) in memory.0.iter().enumerate() {
        let Ok(Decoded::Capture(f)) = decode(bytes) else { panic!("frame {i} not recognized: {:?}", decode(bytes).map(|d| format!("{d:?}").len())) };
        assert_eq!(f.header.ordinal, i as u64);
        assert_eq!(f.header_span.start, 9);
        assert_eq!(f.body_span.end, bytes.len());
        assert_eq!(f.body, &bytes[f.body_span.clone()]);
        let declared = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        assert_eq!(f.header_span.end, 9 + declared);
        // Header span must re-parse to identical typed JSON as the recorder wrote.
        let reparsed: serde_json::Value = serde_json::from_slice(&bytes[f.header_span.clone()]).unwrap();
        assert_eq!(reparsed["ordinal"].as_u64(), Some(i as u64));
    }
    println!("PROBE recorder frames: {}", memory.0.len());
}

#[test]
fn review_probe_max_header_allocation_shapes_complete_quickly() {
    // Worst-case-ish JSON allocations within MAX_HEADER inside an unsupported variant.
    let shapes = [
        ("many-zeros", format!("[{}0]", "0,".repeat((MAX_HEADER - 400) / 2))),
        ("many-empty-objects", format!("[{}{{}}]", "{},".repeat((MAX_HEADER - 400) / 3))),
        ("many-keys", {
            let mut s = String::from("{");
            let mut i = 0usize;
            while s.len() < MAX_HEADER - 600 { s.push_str(&format!("\"{i:x}\":0,")); i += 1; }
            s.push_str("\"end\":0}");
            s
        }),
    ];
    for (name, payload) in shapes {
        let header = hdr(&format!(r#"{{"type":"future","p":{payload}}}"#));
        assert!(header.len() <= MAX_HEADER, "{name} {}", header.len());
        let t = std::time::Instant::now();
        let r = show(&format!("ALLOC {name} len={}", header.len()), &wire(&header, b""));
        println!("PROBE ALLOC {name} elapsed={:?}", t.elapsed());
        assert!(r.starts_with("Unsupported"), "{name}: {r}");
    }
}
