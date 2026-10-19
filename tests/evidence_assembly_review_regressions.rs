#![cfg(feature = "v2-crypto")]
// Promoted design-derived probes BP06, BP09a, BP16 and BP04 from the fresh
// eb4f471 Opus review. The unchanged original probes are retained in .design.
use kan::evidence_assembly::{self as a, Input, Limits, Observation, Payload};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn frame(ordinal: u64, event: &str, body: &[u8]) -> Vec<u8> {
    let h=format!("{{\"version\":2,\"attempt\":\"{}\",\"observer\":\"collector\",\"ordinal\":{ordinal},\"observed_at_unix_micros\":null,\"elapsed_micros\":0,\"unconfirmed_before\":0,\"event\":{event}}}","1".repeat(64));
    let mut out = b"KANC2".to_vec();
    out.extend((h.len() as u32).to_be_bytes());
    out.extend(h.as_bytes());
    out.extend(body);
    out
}
fn chunk(ordinal: u64, response: bool, offset: u64, body: &[u8]) -> Vec<u8> {
    frame(
        ordinal,
        &format!(
            "{{\"type\":\"{}-chunk\",\"offset\":{offset}}}",
            if response { "response" } else { "request" }
        ),
        body,
    )
}
fn input(bytes: &[u8]) -> Input<'_> {
    Input {
        scope: [1; 32],
        writer: "w",
        payload: Payload::Available(bytes),
    }
}
fn limits() -> Limits {
    Limits {
        occurrences: 100,
        input_bytes: 1024 * 1024,
        scan_bytes: 4 * 1024 * 1024,
        assembled_bytes: 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
#[test]
fn scan_accounting_pins_decode_duplicate_comparison_and_copy() {
    let x = chunk(0, false, 0, b"abcd");
    let y = chunk(1, false, 4, b"ef");
    let z = chunk(2, true, 0, b"xyz");
    let inputs = [input(&x), input(&x), input(&x), input(&y), input(&z)];
    let decoded = 3 * x.len() + y.len() + z.len();
    let compared = 2 * x.len();
    let copied = 6 + 3;
    let expected = (decoded + compared + copied) as u64;
    let mut l = limits();
    l.scan_bytes = expected;
    let r = a::assemble(&inputs, l.clone()).unwrap();
    assert_eq!(
        r.scanned_bytes, expected,
        "absolute decode/comparison/copy accounting"
    );
    assert_eq!(r.assembled_bytes, copied as u64);
    l.scan_bytes -= 1;
    assert_eq!(
        a::assemble(&inputs, l).unwrap_err(),
        a::Error::Limit("scan bytes")
    );
}
#[test]
fn duplicate_request_end_retains_every_extent_source() {
    let c = chunk(0, false, 0, b"ab");
    let end = frame(1, r#"{"type":"request-end","bytes":2}"#, b"");
    let r = a::assemble(&[input(&c), input(&end), input(&end)], limits()).unwrap();
    assert_eq!(r.groups[0].request.extents, vec![(1, 2), (2, 2)]);
    assert_eq!(r.groups[0].request.contiguous.as_deref(), Some(&b"ab"[..]));
}
#[test]
fn stream_offset_order_can_differ_from_observer_ordinal_order() {
    let x = chunk(1, true, 2, b"cd");
    let y = chunk(2, true, 0, b"ab");
    let r = a::assemble(&[input(&x), input(&y)], limits()).unwrap();
    let s = &r.groups[0].response;
    assert_eq!(s.contiguous.as_deref(), Some(&b"abcd"[..]));
    assert!(s.issues.is_empty());
}
#[test]
fn ordinal_gaps_do_not_mean_unplaced_inputs_are_absent() {
    let s = frame(
        0,
        r#"{"type":"started","method":"POST","route":"/v1/messages"}"#,
        b"",
    );
    let unknown = frame(1, r#"{"type":"future-event","x":1}"#, b"");
    let malformed = frame(2, r#"{"type":"request-chunk","offset":"0"}"#, b"q");
    let c = chunk(3, false, 0, b"abc");
    let r = a::assemble(
        &[input(&s), input(&unknown), input(&malformed), input(&c)],
        limits(),
    )
    .unwrap();
    assert_eq!(r.observations.len(), 4);
    assert!(matches!(r.observations[1], Observation::Unsupported(_)));
    assert!(matches!(r.observations[2], Observation::Malformed(_)));
    assert_eq!(r.groups[0].ordinal_gaps, vec![1..3]);
    assert_eq!(r.groups[0].request.contiguous.as_deref(), Some(&b"abc"[..]));
}
