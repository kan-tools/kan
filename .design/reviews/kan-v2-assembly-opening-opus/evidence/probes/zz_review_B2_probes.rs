// REVIEWER TEMPORARY PROBE (scope B, supplementary). Copied into tests/ only for the run.
// Design: "Request/response offsets determine byte assembly" and ordinal orders
// observations. A chunk with a later ordinal at an earlier offset is still exact
// coverage; expectation written before running.
#![cfg(feature = "v2-crypto")]
use kan::evidence_assembly::{self as a, Input, Limits, Payload};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn f(ord: u64, kind: &str, off: u64, body: &[u8]) -> Vec<u8> {
    let h = format!("{{\"version\":2,\"attempt\":\"{}\",\"observer\":\"collector\",\"ordinal\":{ord},\"observed_at_unix_micros\":null,\"elapsed_micros\":0,\"unconfirmed_before\":0,\"event\":{{\"type\":\"{kind}\",\"offset\":{off}}}}}", "3".repeat(64));
    let mut v = b"KANC2".to_vec();
    v.extend((h.len() as u32).to_be_bytes());
    v.extend(h.as_bytes());
    v.extend(body);
    v
}
#[test]
fn bp16_out_of_ordinal_order_offsets_still_assemble_by_offset() {
    let (x, y) = (f(1, "response-chunk", 2, b"cd"), f(2, "response-chunk", 0, b"ab"));
    let l = Limits {
        occurrences: 10,
        input_bytes: 1 << 20,
        scan_bytes: 1 << 20,
        assembled_bytes: 1 << 20,
        duration: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let i = |b| Input { scope: [0; 32], writer: "w", payload: Payload::Available(b) };
    let r = a::assemble(&[i(&x), i(&y)], l).unwrap();
    let s = &r.groups[0].response;
    println!("BP16 contiguous={:?} issues={:?} order={:?}", s.contiguous, s.issues, s.segments.iter().map(|s| s.offset).collect::<Vec<_>>());
    assert_eq!(s.contiguous.as_deref(), Some(&b"abcd"[..]));
    assert!(s.issues.is_empty());
}
