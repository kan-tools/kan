#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_assembly::{
        self as a, Error, Input, Limits, Observation, Payload, StreamIssue, Terminal, Unavailable,
    },
    evidence_capture::{Observer, Outcome},
};
use serde_json::{json, Value};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

fn wire(ordinal: u64, event: Value, body: &[u8]) -> Vec<u8> {
    let h = serde_json::to_vec(
        &json!({"version":2,"attempt":"a".repeat(64),"observer":"collector",
        "ordinal":ordinal,"observed_at_unix_micros":null,"elapsed_micros":0,
        "unconfirmed_before":0,"event":event}),
    )
    .unwrap();
    let mut out = b"KANC2".to_vec();
    out.extend((h.len() as u32).to_be_bytes());
    out.extend(h);
    out.extend(body);
    out
}
fn change(bytes: &[u8], field: &str, value: Value) -> Vec<u8> {
    let n = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let mut h: Value = serde_json::from_slice(&bytes[9..9 + n]).unwrap();
    h[field] = value;
    let h = serde_json::to_vec(&h).unwrap();
    let mut out = b"KANC2".to_vec();
    out.extend((h.len() as u32).to_be_bytes());
    out.extend(h);
    out.extend(&bytes[9 + n..]);
    out
}
fn input(bytes: &[u8]) -> Input<'_> {
    Input {
        scope: [1; 32],
        writer: "verified-writer",
        payload: Payload::Available(bytes),
    }
}
fn limits() -> Limits {
    Limits {
        occurrences: 1000,
        input_bytes: 1024 * 1024,
        scan_bytes: 4 * 1024 * 1024,
        assembled_bytes: 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn started() -> Vec<u8> {
    wire(
        0,
        json!({"type":"started","method":"POST","route":"/v1/messages"}),
        b"",
    )
}
fn chunk(n: u64, offset: u64, b: &[u8]) -> Vec<u8> {
    wire(n, json!({"type":"request-chunk","offset":offset}), b)
}
fn end(n: u64, bytes: u64) -> Vec<u8> {
    wire(n, json!({"type":"request-end","bytes":bytes}), b"")
}

#[test]
fn shuffled_selection_preserves_exact_binary_spans_and_duplicate_lineage() {
    let s = started();
    let c1 = chunk(1, 0, b"\xff\xc3");
    let c2 = chunk(2, 2, b"\xa9\0");
    let e = end(3, 4);
    let inputs = [input(&c2), input(&s), input(&c1), input(&e), input(&c1)];
    let r = a::assemble(&inputs, limits()).unwrap();
    let g = &r.groups[0];
    assert_eq!(r.observations.len(), 5);
    assert_eq!(g.ordinals.len(), 4);
    assert_eq!(g.ordinals[1].inputs, vec![2, 4]);
    assert!(!g.ordinals[1].conflict);
    assert_eq!(
        g.request.contiguous.as_deref(),
        Some(&b"\xff\xc3\xa9\0"[..])
    );
    assert_eq!(g.request.expected_bytes, Some(4));
    assert!(g.ordinal_gaps.is_empty());
    assert!(!g.missing_start);
    assert_eq!(g.terminal, Terminal::Unknown);
    assert_eq!(g.request.segments[0].sources.len(), 2);
    for segment in &g.request.segments {
        for source in &segment.sources {
            let Payload::Available(bytes) = inputs[source.input].payload else {
                panic!()
            };
            let expected = &b"\xff\xc3\xa9\0"
                [segment.offset as usize..segment.offset as usize + segment.length];
            assert_eq!(&bytes[source.bytes.clone()], expected);
        }
    }
}
#[test]
fn scope_writer_observer_attempt_isolation_ignores_transport_link_claims() {
    let f = wire(
        0,
        json!({"type":"transport-link","exchange":"e".repeat(64)}),
        b"",
    );
    let gateway = change(&f, "observer", json!("gateway"));
    let other = change(&f, "attempt", json!("b".repeat(64)));
    let mut scope = input(&f);
    scope.scope = [2; 32];
    let mut writer = input(&f);
    writer.writer = "another-writer";
    let inputs = [input(&f), scope, writer, input(&gateway), input(&other)];
    let r = a::assemble(&inputs, limits()).unwrap();
    assert_eq!(r.groups.len(), 5);
    assert!(r.groups.iter().all(|g| g.ordinals.len() == 1));
    assert!(r.groups.iter().any(|g| g.observer == Observer::Gateway));
}
#[test]
fn ordinal_conflicts_keep_both_bytes_and_prevent_synthetic_rendering() {
    let x = chunk(1, 0, b"a");
    let y = chunk(1, 0, b"b");
    let e = end(2, 1);
    let r = a::assemble(&[input(&x), input(&y), input(&e)], limits()).unwrap();
    let g = &r.groups[0];
    assert!(g.ordinals[0].conflict);
    assert_eq!(g.ordinals[0].inputs, vec![0, 1]);
    assert_eq!(g.request.segments.len(), 2);
    assert!(g.request.contiguous.is_none());
    assert!(g.request.issues.contains(&StreamIssue::OrdinalConflict));
    assert_eq!(g.ordinal_gaps, vec![0..1]);
    assert!(g.missing_start);
}
#[test]
fn holes_overlaps_and_contradictory_extents_are_not_repaired() {
    for (chunks, ends, expected) in [
        (
            vec![chunk(1, 2, b"ab")],
            vec![end(2, 5)],
            vec![StreamIssue::Gap(0..2), StreamIssue::Gap(4..5)],
        ),
        (
            vec![chunk(1, 0, b"ab"), chunk(2, 1, b"c")],
            vec![end(3, 2)],
            vec![StreamIssue::Overlap { input: 1 }],
        ),
        (
            vec![chunk(1, 0, b"abc")],
            vec![end(2, 2)],
            vec![StreamIssue::BeyondExtent { input: 0 }],
        ),
        (
            vec![chunk(1, 0, b"ab")],
            vec![end(2, 2), end(3, 3)],
            vec![StreamIssue::ConflictingExtents],
        ),
    ] {
        let bytes: Vec<_> = chunks.into_iter().chain(ends).collect();
        let inputs: Vec<_> = bytes.iter().map(|b| input(b)).collect();
        let r = a::assemble(&inputs, limits()).unwrap();
        let s = &r.groups[0].request;
        assert!(s.contiguous.is_none());
        for issue in expected {
            assert!(s.issues.contains(&issue), "{:?}", s.issues);
        }
    }
}
#[test]
fn sparse_u64_and_overflow_coordinates_never_allocate_by_claimed_extent() {
    let x = chunk(u64::MAX, u64::MAX, b"a");
    let mut budget = limits();
    budget.assembled_bytes = 0;
    let r = a::assemble(&[input(&x)], budget).unwrap();
    let g = &r.groups[0];
    assert_eq!(g.ordinals[0].value, u64::MAX);
    assert_eq!(g.ordinal_gaps, vec![0..u64::MAX]);
    assert_eq!(
        g.request.issues,
        vec![StreamIssue::OffsetOverflow { input: 0 }]
    );
    assert!(g.request.contiguous.is_none());
    let x = chunk(0, u64::MAX - 1, b"a");
    let e = end(1, u64::MAX);
    let r = a::assemble(&[input(&x), input(&e)], limits()).unwrap();
    let s = &r.groups[0].request;
    assert_eq!(s.expected_bytes, Some(u64::MAX));
    assert_eq!(s.issues, vec![StreamIssue::Gap(0..u64::MAX - 1)]);
    assert_eq!(r.assembled_bytes, 0);
}
#[test]
fn completed_terminal_is_only_a_claim_and_does_not_fill_missing_evidence() {
    let s = started();
    let r = wire(2, json!({"type":"response-chunk","offset":0}), b"prefix");
    let t = wire(3, json!({"type":"terminal","outcome":"completed"}), b"");
    let out = a::assemble(&[input(&s), input(&r), input(&t)], limits()).unwrap();
    let g = &out.groups[0];
    assert_eq!(g.terminal, Terminal::Claimed(Outcome::Completed));
    assert_eq!(g.ordinal_gaps, vec![1..2]);
    assert_eq!(g.response.expected_bytes, None);
    assert_eq!(g.response.contiguous.as_deref(), Some(&b"prefix"[..]));
    assert!(g.request.contiguous.is_none());
    let after = chunk(4, 0, b"x");
    let second = wire(
        5,
        json!({"type":"terminal","outcome":"outcome-unknown"}),
        b"",
    );
    let out = a::assemble(&[input(&t), input(&after), input(&second)], limits()).unwrap();
    assert_eq!(out.groups[0].terminal, Terminal::Conflicting);
    assert!(out.groups[0].events_after_terminal);
}
#[test]
fn terminal_at_a_conflicting_ordinal_cannot_select_a_winner() {
    let t = wire(1, json!({"type":"terminal","outcome":"completed"}), b"");
    let c = chunk(1, 0, b"x");
    let out = a::assemble(&[input(&t), input(&c)], limits()).unwrap();
    assert_eq!(out.groups[0].terminal, Terminal::Conflicting);
}
#[test]
fn every_non_capture_and_unavailable_input_has_a_result() {
    let opaque = input(b"imported claim");
    let bad = input(b"KANC2");
    let future = input(b"KANC3");
    let absent = Input {
        scope: [1; 32],
        writer: "writer",
        payload: Payload::Unavailable(Unavailable::Missing),
    };
    let out = a::assemble(&[opaque, bad, future, absent], limits()).unwrap();
    assert!(out.groups.is_empty());
    assert!(matches!(out.observations[0], Observation::Opaque));
    assert!(matches!(out.observations[1], Observation::Malformed(_)));
    assert!(matches!(out.observations[2], Observation::Unsupported(_)));
    assert!(matches!(
        out.observations[3],
        Observation::Unavailable(Unavailable::Missing)
    ));
}
#[test]
fn empty_request_extent_and_unknown_extent_remain_distinct() {
    let e = end(0, 0);
    let r = a::assemble(&[input(&e)], limits()).unwrap();
    assert_eq!(r.groups[0].request.contiguous, Some(vec![]));
    assert_eq!(r.groups[0].request.expected_bytes, Some(0));
    assert!(r.groups[0].response.contiguous.is_none());
    let c = chunk(0, 0, b"x");
    let r = a::assemble(&[input(&c)], limits()).unwrap();
    assert_eq!(r.groups[0].request.contiguous, Some(b"x".to_vec()));
    assert_eq!(r.groups[0].request.expected_bytes, None);
}
#[test]
fn repeated_semantic_chunk_at_a_new_ordinal_is_an_overlap_not_deduplicated() {
    let x = chunk(0, 0, b"same");
    let y = chunk(1, 0, b"same");
    let r = a::assemble(&[input(&x), input(&y)], limits()).unwrap();
    assert_eq!(r.groups[0].request.segments.len(), 2);
    assert!(r.groups[0].request.contiguous.is_none());
    assert!(r.groups[0]
        .request
        .issues
        .contains(&StreamIssue::Overlap { input: 1 }));
}
#[test]
fn observed_missing_admission_and_unexpected_start_stay_visible() {
    let s = change(&started(), "ordinal", json!(7));
    let s = change(&s, "unconfirmed_before", json!(9));
    let r = a::assemble(&[input(&s)], limits()).unwrap();
    let g = &r.groups[0];
    assert!(g.unconfirmed_claim);
    assert!(g.missing_start);
    assert_eq!(g.unexpected_starts, vec![0]);
    assert_eq!(g.ordinal_gaps, vec![0..7]);
}
#[test]
fn exact_budget_edges_cancellation_and_repeat_are_deterministic() {
    let c = chunk(0, 0, b"abc");
    let inputs = [input(&c), input(&c)];
    let r = a::assemble(&inputs, limits()).unwrap();
    let mut exact = limits();
    exact.occurrences = 2;
    exact.input_bytes = 2 * (c.len() + "verified-writer".len()) as u64;
    exact.scan_bytes = r.scanned_bytes;
    exact.assembled_bytes = 3;
    let again = a::assemble(&inputs, exact.clone()).unwrap();
    assert_eq!(format!("{r:?}"), format!("{again:?}"));
    for (field, expected) in [
        (0, "occurrences"),
        (1, "input bytes"),
        (2, "scan bytes"),
        (3, "assembled bytes"),
    ] {
        let mut b = exact.clone();
        match field {
            0 => b.occurrences -= 1,
            1 => b.input_bytes -= 1,
            2 => b.scan_bytes -= 1,
            _ => b.assembled_bytes -= 1,
        };
        assert_eq!(a::assemble(&inputs, b).unwrap_err(), Error::Limit(expected));
    }
    let mut b = limits();
    b.cancelled = Arc::new(AtomicBool::new(true));
    assert_eq!(a::assemble(&inputs, b).unwrap_err(), Error::Cancelled);
    let mut b = limits();
    b.duration = Duration::ZERO;
    assert_eq!(
        a::assemble(&inputs, b).unwrap_err(),
        Error::Limit("duration")
    );
}

#[test]
fn a_chunk_after_request_end_cannot_silently_become_a_closed_request() {
    let e = end(1, 3);
    let c = chunk(2, 0, b"abc");
    let out = a::assemble(&[input(&c), input(&e)], limits()).unwrap();
    assert!(out.groups[0].request.contiguous.is_none());
    assert!(out.groups[0]
        .request
        .issues
        .contains(&StreamIssue::ChunkAfterEnd { input: 0 }));
}
