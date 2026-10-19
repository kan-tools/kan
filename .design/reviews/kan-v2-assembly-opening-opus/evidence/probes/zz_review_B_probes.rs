// REVIEWER TEMPORARY PROBES (scope B). Copied into tests/ only for the run, then removed.
// Frames are built from hand-written header JSON text (not serde_json::to_vec), so
// spans depend on byte-exact header lengths including escapes and multibyte UTF-8.
#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_assembly::{self as a, Error, Input, Limits, Observation, Payload, StreamIssue, Terminal, Unavailable},
    evidence_capture::{Observer, Outcome},
};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

const A1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const A2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// Raw header text, written by hand. `extra` is spliced verbatim before "event"
/// so whitespace / escapes / key order can vary without changing semantics.
fn hdr(attempt: &str, observer: &str, ordinal: u64, unconfirmed: u64, extra: &str, event: &str) -> String {
    format!(
        "{{\"version\":2,\"attempt\":\"{attempt}\",\"observer\":\"{observer}\",\"ordinal\":{ordinal},{extra}\"observed_at_unix_micros\":null,\"elapsed_micros\":0,\"unconfirmed_before\":{unconfirmed},\"event\":{event}}}"
    )
}
fn frame(header: &str, body: &[u8]) -> Vec<u8> {
    let mut v = b"KANC2".to_vec();
    v.extend((header.len() as u32).to_be_bytes());
    v.extend(header.as_bytes());
    v.extend(body);
    v
}
fn rq(ord: u64, off: u64, body: &[u8]) -> Vec<u8> {
    frame(&hdr(A1, "collector", ord, 0, "", &format!("{{\"type\":\"request-chunk\",\"offset\":{off}}}")), body)
}
fn rs(ord: u64, off: u64, body: &[u8]) -> Vec<u8> {
    frame(&hdr(A1, "collector", ord, 0, "", &format!("{{\"type\":\"response-chunk\",\"offset\":{off}}}")), body)
}
fn rend(ord: u64, n: u64) -> Vec<u8> {
    frame(&hdr(A1, "collector", ord, 0, "", &format!("{{\"type\":\"request-end\",\"bytes\":{n}}}")), b"")
}
fn term(ord: u64, outcome: &str) -> Vec<u8> {
    frame(&hdr(A1, "collector", ord, 0, "", &format!("{{\"type\":\"terminal\",\"outcome\":\"{outcome}\"}}")), b"")
}
fn start(ord: u64) -> Vec<u8> {
    frame(&hdr(A1, "collector", ord, 0, "", "{\"type\":\"started\",\"method\":\"POST\",\"route\":\"/v1/messages\"}"), b"")
}
fn inp<'a>(b: &'a [u8], scope: u8, writer: &'a str) -> Input<'a> {
    Input { scope: [scope; 32], writer, payload: Payload::Available(b) }
}
fn lim() -> Limits {
    Limits {
        occurrences: 1_000_000,
        input_bytes: 1 << 34,
        scan_bytes: 1 << 34,
        assembled_bytes: 1 << 30,
        duration: Duration::from_secs(60),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn body_of(i: &Input<'_>, span: &std::ops::Range<usize>) -> Vec<u8> {
    match i.payload {
        Payload::Available(b) => b[span.clone()].to_vec(),
        _ => panic!("span on unavailable input"),
    }
}

// B-P01: spans are exact exclusive byte ranges of each input's own decrypted frame,
// even when conflicting variants have different header lengths (escaped / multibyte keys
// in a value are not allowed, so vary insignificant whitespace instead), and binary bodies.
#[test]
fn bp01_spans_exact_for_conflicting_variants_with_different_header_lengths() {
    let x = frame(&hdr(A1, "collector", 1, 0, "", "{\"type\":\"request-chunk\",\"offset\":0}"), "é\u{1F600}".as_bytes());
    // same semantics, extra whitespace -> different bytes -> must be a conflict
    let y = frame(&hdr(A1, "collector", 1, 0, "  ", "{ \"type\" : \"request-chunk\" , \"offset\" : 0 }"), "é\u{1F600}".as_bytes());
    let inputs = [inp(&x, 1, "w"), inp(&y, 1, "w")];
    let r = a::assemble(&inputs, lim()).unwrap();
    let g = &r.groups[0];
    println!("BP01 conflict={} segments={} issues={:?}", g.ordinals[0].conflict, g.request.segments.len(), g.request.issues);
    assert!(g.ordinals[0].conflict, "byte-different same-semantics frames must conflict");
    assert!(g.request.contiguous.is_none());
    for s in &g.request.segments {
        for src in &s.sources {
            assert_eq!(body_of(&inputs[src.input], &src.bytes), "é\u{1F600}".as_bytes());
            assert_eq!(src.bytes.end, match inputs[src.input].payload { Payload::Available(b) => b.len(), _ => 0 });
        }
    }
    let starts: Vec<_> = g.request.segments.iter().map(|s| s.sources[0].bytes.start).collect();
    assert_ne!(starts[0], starts[1], "spans must be per-input, not shared");
}

// B-P02: [A, B, A] at one ordinal: all three lineages retained, both A copies visible.
#[test]
fn bp02_mixed_duplicate_and_conflict_retains_every_lineage() {
    let x = rq(0, 0, b"aa");
    let y = rq(0, 0, b"bb");
    let inputs = [inp(&x, 1, "w"), inp(&y, 1, "w"), inp(&x, 1, "w")];
    let r = a::assemble(&inputs, lim()).unwrap();
    let g = &r.groups[0];
    let mut all: Vec<usize> = g.request.segments.iter().flat_map(|s| s.sources.iter().map(|x| x.input)).collect();
    all.sort();
    println!("BP02 ordinal.inputs={:?} conflict={} segment sources={:?} issues={:?}", g.ordinals[0].inputs, g.ordinals[0].conflict, all, g.request.issues);
    assert_eq!(g.ordinals[0].inputs, vec![0, 1, 2]);
    assert!(g.ordinals[0].conflict);
    assert_eq!(all, vec![0, 1, 2]);
}

// B-P03: exact duplicates across DIFFERENT writers / scopes never merge, even byte-identical.
// Arbitrary caller identities: empty, NUL-containing, non-ASCII, case-variant writers.
#[test]
fn bp03_arbitrary_caller_identities_are_exact_and_isolated() {
    let x = rq(0, 0, b"z");
    let writers = ["", "w", "W", "w\0", "w ", "é", "e\u{301}"];
    let inputs: Vec<_> = writers.iter().map(|w| inp(&x, 1, w)).chain([inp(&x, 2, "w")]).collect();
    let r = a::assemble(&inputs, lim()).unwrap();
    println!("BP03 groups={} writers={:?}", r.groups.len(), r.groups.iter().map(|g| (g.scope[0], g.writer.clone())).collect::<Vec<_>>());
    assert_eq!(r.groups.len(), writers.len() + 1);
    for g in &r.groups {
        assert_eq!(g.ordinals.len(), 1);
        assert_eq!(g.ordinals[0].inputs.len(), 1);
        assert_eq!(g.request.contiguous.as_deref(), Some(&b"z"[..]));
    }
    // writer bytes are charged to input_bytes per occurrence
    let total: u64 = inputs.iter().map(|i| (x.len() + i.writer.len()) as u64).sum();
    let mut l = lim();
    l.input_bytes = total;
    assert!(a::assemble(&inputs, l.clone()).is_ok());
    l.input_bytes = total - 1;
    assert_eq!(a::assemble(&inputs, l).unwrap_err(), Error::Limit("input bytes"));
}

// B-P04: an unsupported (unknown event) or malformed frame inside an attempt is NOT placed
// in the group: the group reports an ordinal hole where an input actually exists.
#[test]
fn bp04_unsupported_and_malformed_frames_leave_ordinal_holes_in_groups() {
    let s = start(0);
    let unk = frame(&hdr(A1, "collector", 1, 0, "", "{\"type\":\"future-event\",\"x\":1}"), b"");
    let bad = frame(&hdr(A1, "collector", 2, 0, "", "{\"type\":\"request-chunk\",\"offset\":\"0\"}"), b"q");
    let c = rq(3, 0, b"abc");
    let inputs = [inp(&s, 1, "w"), inp(&unk, 1, "w"), inp(&bad, 1, "w"), inp(&c, 1, "w")];
    let r = a::assemble(&inputs, lim()).unwrap();
    let g = &r.groups[0];
    println!(
        "BP04 obs=[{}] ordinal_gaps={:?} request.contiguous={:?} issues={:?}",
        r.observations.iter().map(|o| match o { Observation::Capture(_) => "Capture", Observation::Opaque => "Opaque", Observation::Unsupported(_) => "Unsupported", Observation::Malformed(_) => "Malformed", Observation::Unavailable(_) => "Unavailable" }).collect::<Vec<_>>().join(","),
        g.ordinal_gaps, g.request.contiguous, g.request.issues
    );
    assert!(matches!(r.observations[1], Observation::Unsupported(_)));
    assert!(matches!(r.observations[2], Observation::Malformed(_)));
    assert_eq!(g.ordinal_gaps, vec![1..3]);
}

// B-P05: permutation invariance of everything except input labels.
#[test]
fn bp05_permutation_invariance_of_groups_bytes_and_issues() {
    let frames = vec![start(0), rq(1, 0, b"he"), rq(2, 2, b"llo"), rend(3, 5), rs(4, 0, b"ok"), term(5, "completed"), rq(2, 2, b"llo")];
    let base: Vec<_> = frames.iter().map(|f| inp(f, 1, "w")).collect();
    let r0 = a::assemble(&base, lim()).unwrap();
    let summary = |r: &a::Assembly<'_>| {
        let g = &r.groups[0];
        (g.request.contiguous.clone(), g.response.contiguous.clone(), g.request.expected_bytes, g.terminal, g.ordinal_gaps.clone(), g.ordinals.iter().map(|o| (o.value, o.inputs.len(), o.conflict)).collect::<Vec<_>>(), r.scanned_bytes, r.assembled_bytes)
    };
    let s0 = summary(&r0);
    println!("BP05 base={s0:?}");
    let mut perm: Vec<usize> = (0..frames.len()).collect();
    for k in 0..40 {
        perm.rotate_left(k % 5 + 1);
        perm.swap(k % frames.len(), (k * 3 + 1) % frames.len());
        let p: Vec<_> = perm.iter().map(|&i| inp(&frames[i], 1, "w")).collect();
        let r = a::assemble(&p, lim()).unwrap();
        assert_eq!(summary(&r), s0, "permutation {perm:?}");
        // lineage: segment sources map back to frames whose body equals the span
        for g in &r.groups {
            for s in g.request.segments.iter().chain(&g.response.segments) {
                for src in &s.sources {
                    assert_eq!(body_of(&p[src.input], &src.bytes).len(), s.length);
                }
            }
        }
    }
    assert_eq!(s0.0.as_deref(), Some(&b"hello"[..]));
    assert_eq!(s0.1.as_deref(), Some(&b"ok"[..]));
    assert_eq!(s0.3, Terminal::Claimed(Outcome::Completed));
}

// B-P06: exact scan-byte accounting formula, derived independently:
// scanned = sum(len(available)) + sum over extra exact-duplicate comparisons (len) + 2x? no:
// copy() also scans, so contiguous bytes are counted in both scanned and assembled.
#[test]
fn bp06_scan_and_assembled_accounting_formula() {
    let a0 = rq(0, 0, b"abcd");
    let a1 = rq(1, 4, b"ef");
    let rr = rs(2, 0, b"xyz");
    let inputs = [inp(&a0, 1, "w"), inp(&a0, 1, "w"), inp(&a0, 1, "w"), inp(&a1, 1, "w"), inp(&rr, 1, "w")];
    let r = a::assemble(&inputs, lim()).unwrap();
    let decode: u64 = inputs.iter().map(|i| match i.payload { Payload::Available(b) => b.len() as u64, _ => 0 }).sum();
    let dup = 2 * a0.len() as u64;
    let copied = 6 + 3;
    println!("BP06 scanned={} assembled={} expected scanned={} assembled={}", r.scanned_bytes, r.assembled_bytes, decode + dup + copied, copied);
    assert_eq!(r.scanned_bytes, decode + dup + copied);
    assert_eq!(r.assembled_bytes, copied);
}

// B-P07: sparse / huge coordinates: gaps are ranges; nothing scales with claimed integers.
#[test]
fn bp07_sparse_u64_offsets_and_ordinals_are_ranges_not_allocations() {
    let frames = vec![rq(0, 0, b"a"), rq(1 << 62, 1 << 63, b"b"), rend(u64::MAX - 1, u64::MAX), rs(7, u64::MAX, b""), rs(8, u64::MAX, b"x")];
    let inputs: Vec<_> = frames.iter().map(|f| inp(f, 1, "w")).collect();
    let t = Instant::now();
    let r = a::assemble(&inputs, lim()).unwrap();
    let g = &r.groups[0];
    println!("BP07 elapsed={:?} gaps={:?} req.issues={:?} resp.issues={:?} assembled={}", t.elapsed(), g.ordinal_gaps, g.request.issues, g.response.issues, r.assembled_bytes);
    assert!(g.request.issues.contains(&StreamIssue::Gap(1..(1 << 63))));
    assert!(g.request.issues.contains(&StreamIssue::Gap((1 << 63) + 1..u64::MAX)));
    assert!(g.request.issues.iter().any(|i| matches!(i, StreamIssue::ChunkAfterEnd { .. })) == false);
    assert!(g.response.issues.contains(&StreamIssue::Gap(0..u64::MAX)));
    assert!(g.response.issues.contains(&StreamIssue::OffsetOverflow { input: 4 }));
    assert_eq!(r.assembled_bytes, 0);
    assert!(t.elapsed() < Duration::from_secs(1));
}

// B-P08: empty vs unknown extent, and empty chunk at a gap.
#[test]
fn bp08_empty_versus_unknown_extent_and_empty_frames() {
    // no request evidence at all -> None, not Some(empty)
    let only_resp = rs(0, 0, b"r");
    let r = a::assemble(&[inp(&only_resp, 1, "w")], lim()).unwrap();
    assert!(r.groups[0].request.contiguous.is_none());
    assert_eq!(r.groups[0].request.expected_bytes, None);
    // empty chunk at offset 5 with nothing before -> gap 0..5
    let e = rq(0, 5, b"");
    let r = a::assemble(&[inp(&e, 1, "w")], lim()).unwrap();
    println!("BP08 empty-at-5 issues={:?} contiguous={:?}", r.groups[0].request.issues, r.groups[0].request.contiguous);
    assert!(r.groups[0].request.issues.contains(&StreamIssue::Gap(0..5)));
    assert!(r.groups[0].request.contiguous.is_none());
    // request-end 0 plus an empty chunk at 0 -> Some(empty) with extent 0
    let (c, z) = (rq(0, 0, b""), rend(1, 0));
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&z, 1, "w")], lim()).unwrap();
    assert_eq!(r.groups[0].request.contiguous, Some(vec![]));
    // request-end 0 but a nonempty chunk -> beyond extent
    let (c, z) = (rq(0, 0, b"x"), rend(1, 0));
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&z, 1, "w")], lim()).unwrap();
    assert!(r.groups[0].request.issues.contains(&StreamIssue::BeyondExtent { input: 0 }));
    assert!(r.groups[0].request.contiguous.is_none());
}

// B-P09: duplicate exact RequestEnd at one ordinal keeps both extent lineages; distinct
// identical-valued RequestEnds at two ordinals: chunks between are ChunkAfterEnd.
#[test]
fn bp09_request_end_lineage_and_chunks_between_two_ends() {
    let (c, e) = (rq(0, 0, b"ab"), rend(1, 2));
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&e, 1, "w"), inp(&e, 1, "w")], lim()).unwrap();
    let s = &r.groups[0].request;
    println!("BP09a extents={:?} expected={:?}", s.extents, s.expected_bytes);
    assert_eq!(s.extents, vec![(1, 2), (2, 2)]);
    assert_eq!(s.contiguous.as_deref(), Some(&b"ab"[..]));
    let (c0, e1, c2, e3) = (rq(0, 0, b"a"), rend(1, 2), rq(2, 1, b"b"), rend(3, 2));
    let r = a::assemble(&[inp(&c0, 1, "w"), inp(&e1, 1, "w"), inp(&c2, 1, "w"), inp(&e3, 1, "w")], lim()).unwrap();
    let s = &r.groups[0].request;
    println!("BP09b issues={:?} contiguous={:?}", s.issues, s.contiguous);
    assert!(s.issues.contains(&StreamIssue::ChunkAfterEnd { input: 2 }));
    assert!(s.contiguous.is_none());
}

// B-P10: terminal semantics.
#[test]
fn bp10_terminal_claims() {
    // exact duplicate terminal at one ordinal -> still one claim
    let t = term(1, "completed");
    let r = a::assemble(&[inp(&t, 1, "w"), inp(&t, 1, "w")], lim()).unwrap();
    assert_eq!(r.groups[0].terminal, Terminal::Claimed(Outcome::Completed));
    assert!(!r.groups[0].events_after_terminal);
    // same outcome at two ordinals -> Conflicting (reported, not merged)
    let (t1, t2) = (term(1, "completed"), term(2, "completed"));
    let r = a::assemble(&[inp(&t1, 1, "w"), inp(&t2, 1, "w")], lim()).unwrap();
    println!("BP10 two-same-outcome-terminals={:?} after={}", r.groups[0].terminal, r.groups[0].events_after_terminal);
    assert_eq!(r.groups[0].terminal, Terminal::Conflicting);
    // outcome-unknown is a claim, not Unknown
    let tu = term(0, "outcome-unknown");
    let r = a::assemble(&[inp(&tu, 1, "w")], lim()).unwrap();
    assert_eq!(r.groups[0].terminal, Terminal::Claimed(Outcome::OutcomeUnknown));
    // a terminal in another attempt or writer never affects this group
    let other = frame(&hdr(A2, "collector", 9, 0, "", "{\"type\":\"terminal\",\"outcome\":\"completed\"}"), b"");
    let c = rq(0, 0, b"x");
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&other, 1, "w"), inp(&t, 1, "v")], lim()).unwrap();
    let mine = r.groups.iter().find(|g| g.attempt == A1 && g.writer == "w").unwrap();
    assert_eq!(mine.terminal, Terminal::Unknown);
}

// B-P11: an ordinal conflict among *response/terminal* frames also suppresses the request
// rendering (conservative coupling) - recorded as behaviour, not asserted as required.
#[test]
fn bp11_conflict_coupling_between_streams() {
    let (c, e) = (rq(0, 0, b"ab"), rend(1, 2));
    let (t1, t2) = (term(2, "completed"), term(2, "outcome-unknown"));
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&e, 1, "w"), inp(&t1, 1, "w"), inp(&t2, 1, "w")], lim()).unwrap();
    let g = &r.groups[0];
    println!("BP11 request.contiguous={:?} request.issues={:?} terminal={:?}", g.request.contiguous, g.request.issues, g.terminal);
    assert_eq!(g.terminal, Terminal::Conflicting);
}

// B-P12: gateway vs collector frames of the same attempt never interleave.
#[test]
fn bp12_observer_isolation_same_attempt() {
    let c = rq(0, 0, b"ab");
    let gw = frame(&hdr(A1, "gateway", 1, 0, "", "{\"type\":\"request-chunk\",\"offset\":2}"), b"cd");
    let r = a::assemble(&[inp(&c, 1, "w"), inp(&gw, 1, "w")], lim()).unwrap();
    assert_eq!(r.groups.len(), 2);
    let col = r.groups.iter().find(|g| g.observer == Observer::Collector).unwrap();
    let gate = r.groups.iter().find(|g| g.observer == Observer::Gateway).unwrap();
    println!("BP12 collector={:?} gateway issues={:?}", col.request.contiguous, gate.request.issues);
    assert_eq!(col.request.contiguous.as_deref(), Some(&b"ab"[..]));
    assert!(gate.request.issues.contains(&StreamIssue::Gap(0..2)));
}

// B-P13: budget boundaries: zero occurrences on empty input, >3600s refusal, unavailable
// only inputs, occurrence limit before any decode.
#[test]
fn bp13_budget_edges() {
    let mut l = lim();
    l.occurrences = 0;
    let r = a::assemble(&[], l.clone()).unwrap();
    assert!(r.observations.is_empty() && r.groups.is_empty());
    let mut l2 = lim();
    l2.duration = Duration::from_secs(3601);
    assert_eq!(a::assemble(&[], l2).unwrap_err(), Error::Limit("duration"));
    let mut l3 = lim();
    l3.duration = Duration::from_secs(3600);
    assert!(a::assemble(&[], l3).is_ok());
    let un = Input { scope: [1; 32], writer: "abc", payload: Payload::Unavailable(Unavailable::Corrupt) };
    let mut l4 = lim();
    l4.input_bytes = 2;
    l4.scan_bytes = 0;
    assert_eq!(a::assemble(&[un], l4).unwrap_err(), Error::Limit("input bytes"));
    let un = Input { scope: [1; 32], writer: "abc", payload: Payload::Unavailable(Unavailable::Withheld) };
    let mut l5 = lim();
    l5.input_bytes = 3;
    l5.scan_bytes = 0;
    l5.assembled_bytes = 0;
    let r = a::assemble(&[un], l5).unwrap();
    assert!(matches!(r.observations[0], Observation::Unavailable(Unavailable::Withheld)));
    // a 2nd big input over the scan budget refuses the WHOLE operation (no partial success)
    let big = rq(0, 0, &[7u8; 60000]);
    let mut l6 = lim();
    l6.scan_bytes = big.len() as u64 + 10;
    let res = a::assemble(&[inp(&big, 1, "w"), inp(&big, 2, "w")], l6);
    println!("BP13 over-scan={:?}", res.as_ref().err());
    assert_eq!(res.unwrap_err(), Error::Limit("scan bytes"));
}

// B-P14: cancellation from another thread during a large assembly.
#[test]
fn bp14_cross_thread_cancellation_and_scale() {
    let frames: Vec<Vec<u8>> = (0..20000u64).map(|i| rq(i, i * 3, b"abc")).collect();
    let inputs: Vec<_> = frames.iter().map(|f| inp(f, 1, "w")).collect();
    let t = Instant::now();
    let r = a::assemble(&inputs, lim()).unwrap();
    let full = t.elapsed();
    println!("BP14 20000 inputs elapsed={full:?} contiguous_len={:?} scanned={}", r.groups[0].request.contiguous.as_ref().map(|c| c.len()), r.scanned_bytes);
    assert_eq!(r.groups[0].request.contiguous.as_ref().unwrap().len(), 60000);
    let l = lim();
    let flag = l.cancelled.clone();
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_micros(200));
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    let t = Instant::now();
    let res = a::assemble(&inputs, l);
    h.join().unwrap();
    println!("BP14 cancel result={:?} elapsed={:?}", res.as_ref().err(), t.elapsed());
    if full > Duration::from_millis(5) {
        assert_eq!(res.unwrap_err(), Error::Cancelled);
    }
    // all-overlap worst case: issues bounded linearly
    let same: Vec<Vec<u8>> = (0..5000u64).map(|i| rq(i, 0, b"abc")).collect();
    let inputs: Vec<_> = same.iter().map(|f| inp(f, 1, "w")).collect();
    let r = a::assemble(&inputs, lim()).unwrap();
    println!("BP14 overlap issues={} segments={}", r.groups[0].request.issues.len(), r.groups[0].request.segments.len());
    assert!(r.groups[0].request.issues.len() <= 5000);
}

// B-P15: unconfirmed_before claim on a non-start event, unexpected duplicate starts.
#[test]
fn bp15_unconfirmed_claims_and_multiple_starts() {
    let s0 = start(0);
    let s3 = start(3);
    let c = frame(&hdr(A1, "collector", 1, 0, "", "{\"type\":\"request-chunk\",\"offset\":0}"), b"x");
    let u = frame(&hdr(A1, "collector", 2, 4, "", "{\"type\":\"response-head\",\"status\":200}"), b"");
    let r = a::assemble(&[inp(&s0, 1, "w"), inp(&c, 1, "w"), inp(&u, 1, "w"), inp(&s3, 1, "w")], lim()).unwrap();
    let g = &r.groups[0];
    println!("BP15 missing_start={} unexpected={:?} unconfirmed={}", g.missing_start, g.unexpected_starts, g.unconfirmed_claim);
    assert!(!g.missing_start);
    assert_eq!(g.unexpected_starts, vec![3]);
    assert!(g.unconfirmed_claim);
}
