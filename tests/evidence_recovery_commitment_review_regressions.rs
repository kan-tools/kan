#![cfg(feature = "v2-storage")]
//! Promoted independent RA3/RA4 probes from frozen a8927a6 review.
//! Every assertion states the behaviour the design/doc requires. Vectors come from
//! review-evidence/probes/indep_commitments.py (prose-only implementation).
use atproto_dasl::Cid;
use kan::evidence_recovery_commitment::{
    Counts, Domain, Header, Limits, MemberFraming, RestorationFraming,
};
use sha2::{Digest, Sha256};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

const MIB4: usize = 4 * 1024 * 1024;

fn limits() -> Limits {
    Limits {
        items: 1000,
        bytes: 256 * 1024 * 1024,
        duration: Duration::from_secs(60),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn counts(m: u64, r: u64, o: u64) -> Counts {
    Counts {
        membership: m,
        records: r,
        objects: o,
    }
}
fn header2() -> Header<'static> {
    Header {
        profile: 2,
        archive: [1; 32],
        scope: [2; 32],
        issuer: "reviewer-framing-only",
        plan: None,
    }
}
fn header3() -> Header<'static> {
    Header {
        profile: 3,
        plan: Some(b"plan"),
        ..header2()
    }
}
fn cid(bytes: &[u8]) -> Cid {
    let mut raw = vec![1, 0x55, 0x12, 0x20];
    raw.extend_from_slice(&Sha256::digest(bytes));
    Cid::from_bytes(&raw).unwrap()
}
fn emit(name: &str, body: &str) {
    eprintln!("{name}: {body}");
}

/// RA3: section, count and sequence boundaries beyond the author suite.
#[test]
fn rv_a3_section_count_sequence_boundaries() {
    let mut out = String::new();
    let mut check = |name: &str, refused: bool| {
        out.push_str(&format!("{name}\trefused={refused}\n"));
        assert!(refused, "{name} must refuse");
    };
    let (k1, k2) = {
        let mut v = [cid(b"k1"), cid(b"k2")];
        v.sort_by_key(|c| c.to_string());
        (v[0].clone(), v[1].clone())
    };
    // membership call after begin_records (counts allow a second membership row)
    let mut m = MemberFraming::new(header3(), counts(1, 1, 0), Domain::Member, limits()).unwrap();
    m.membership(&k1, 1).unwrap();
    m.begin_records().unwrap();
    check(
        "membership-after-begin-records",
        m.membership(&k2, 1).is_err(),
    );
    // begin_records twice
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check("begin-records-twice", m.begin_records().is_err());
    // record before begin_records
    let mut m = MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    check(
        "record-before-begin-records",
        m.record(1, b"m", b"r", b"p").is_err(),
    );
    // object during records phase
    let mut m = MemberFraming::new(header2(), counts(0, 1, 1), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check(
        "object-in-records-phase",
        m.original_object(&k1, b"x").is_err(),
    );
    // finish with fewer objects than declared
    let mut m = MemberFraming::new(header2(), counts(0, 0, 2), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    m.original_object(&k1, b"x").unwrap();
    check("member-finish-fewer-objects", m.finish().is_err());
    // finish before begin_objects / in membership phase
    let m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    check("finish-in-membership-phase", m.finish().is_err());
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check("finish-in-records-phase", m.finish().is_err());
    // record sequence zero; extra record; skipped (1,3)
    let mut m = MemberFraming::new(header2(), counts(0, 2, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check(
        "record-sequence-zero",
        m.record(0, b"m", b"r", b"p").is_err(),
    );
    let mut m = MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.record(1, b"m", b"r", b"p").unwrap();
    check(
        "record-beyond-count",
        m.record(2, b"m", b"r", b"p").is_err(),
    );
    let mut m = MemberFraming::new(header2(), counts(0, 2, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.record(1, b"m", b"r", b"p").unwrap();
    check(
        "record-repeat-sequence",
        m.record(1, b"m", b"r", b"p").is_err(),
    );
    // begin_records with fewer membership rows than declared
    let mut m = MemberFraming::new(header3(), counts(2, 0, 0), Domain::Member, limits()).unwrap();
    m.membership(&k1, 1).unwrap();
    check("begin-records-fewer-membership", m.begin_records().is_err());
    // begin_objects twice
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    check("begin-objects-twice", m.begin_objects().is_err());
    // R1 extra candidate
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    r.candidate(&cid(b"a"), b"a").unwrap();
    check(
        "r1-candidate-beyond-count",
        r.candidate(&cid(b"b"), b"b").is_err(),
    );
    // Order state is per section: an object key below the last membership key is valid.
    let mut m = MemberFraming::new(header3(), counts(1, 0, 1), Domain::Member, limits()).unwrap();
    m.membership(&k2, 1).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    let ok = m.original_object(&k1, b"x").is_ok() && m.finish().is_ok();
    out.push_str(&format!("object-key-below-membership-key\taccepted={ok}\n"));
    assert!(ok, "order state must reset between sections");
    emit("ra3-sections.tsv", &out);
}

/// RA4: local size bounds at exact edges (each field independently).
#[test]
fn rv_a4_local_bounds_exact_edges() {
    let mut out = String::new();
    let mut expect = |name: &str, got: bool, want: bool| {
        out.push_str(&format!("{name}\taccepted={got}\n"));
        assert_eq!(got, want, "{name}");
    };
    let k = cid(b"k");
    for (len, want) in [
        (0u64, false),
        (1, true),
        (MIB4 as u64, true),
        (MIB4 as u64 + 1, false),
    ] {
        let mut m =
            MemberFraming::new(header3(), counts(1, 0, 0), Domain::Member, limits()).unwrap();
        expect(
            &format!("membership-length-{len}"),
            m.membership(&k, len).is_ok(),
            want,
        );
    }
    for field in 0..3 {
        let maxes = [65536usize, 65536, 16384];
        for (len, want) in [
            (0usize, false),
            (1, true),
            (maxes[field], true),
            (maxes[field] + 1, false),
        ] {
            let mut parts = [vec![1u8], vec![1u8], vec![1u8]];
            parts[field] = vec![7; len];
            let mut m =
                MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
            m.begin_records().unwrap();
            expect(
                &format!("record-field{field}-len-{len}"),
                m.record(1, &parts[0], &parts[1], &parts[2]).is_ok(),
                want,
            );
        }
    }
    for (len, want) in [(0usize, false), (1, true), (4096, true), (4097, false)] {
        let plan = vec![3u8; len];
        let mut h = header3();
        h.plan = Some(&plan);
        expect(
            &format!("plan-len-{len}"),
            MemberFraming::new(h, counts(0, 0, 0), Domain::Member, limits()).is_ok(),
            want,
        );
    }
    for (len, want) in [(0usize, false), (1, true), (80, true), (81, false)] {
        let issuer = "d".repeat(len);
        let mut h = header2();
        h.issuer = &issuer;
        expect(
            &format!("issuer-len-{len}"),
            MemberFraming::new(h, counts(0, 0, 0), Domain::Member, limits()).is_ok(),
            want,
        );
    }
    for (len, want) in [(0usize, true), (MIB4, true), (MIB4 + 1, false)] {
        let bytes = vec![5u8; len];
        let mut m =
            MemberFraming::new(header2(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
        m.begin_records().unwrap();
        m.begin_objects().unwrap();
        expect(
            &format!("original-object-len-{len}"),
            m.original_object(&k, &bytes).is_ok(),
            want,
        );
    }
    // Restoration: empty candidate refused even when the CID IS the empty-bytes CID.
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    expect(
        "candidate-empty-with-matching-cid",
        r.candidate(&cid(b""), b"").is_ok(),
        false,
    );
    let big = vec![4u8; MIB4 + 1];
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    expect(
        "candidate-4MiB+1-matching-cid",
        r.candidate(&cid(&big), &big).is_ok(),
        false,
    );
    // Counts above the safe integer, and duration edges.
    let mut l = limits();
    l.items = u64::MAX;
    expect(
        "count-above-safe",
        MemberFraming::new(
            header2(),
            counts(0, 9_007_199_254_740_992, 0),
            Domain::Member,
            l.clone(),
        )
        .is_ok(),
        false,
    );
    expect(
        "r1-count-above-safe",
        RestorationFraming::new(9_007_199_254_740_992, l).is_ok(),
        false,
    );
    for (d, want) in [
        (Duration::ZERO, false),
        (Duration::from_secs(3600), true),
        (Duration::from_secs(3601), false),
    ] {
        let mut l = limits();
        l.duration = d;
        expect(
            &format!("duration-{d:?}"),
            RestorationFraming::new(0, l).is_ok(),
            want,
        );
    }
    emit("ra4-bounds.tsv", &out);
}
