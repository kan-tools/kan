#![cfg(feature = "v2-storage")]
//! Reviewer probes for a8927a6 (temporary; copied into tests/ only while run).
//! Every assertion states the behaviour the design/doc requires. Vectors come from
//! review-evidence/probes/indep_commitments.py (prose-only implementation).
use atproto_dasl::Cid;
use kan::{
    evidence_recovery_commitment::{
        Counts, Domain, Error, Header, Limits, MemberFraming, RestorationFraming,
    },
    evidence_service::{hex, unhex},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
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
fn h(s: &str) -> Vec<u8> {
    unhex(s, 8 * 1024 * 1024).unwrap()
}
fn vectors() -> Value {
    let path = std::env::var("REVIEW_VECTORS").expect("REVIEW_VECTORS");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn emit(name: &str, body: &str) {
    eprintln!("{body}");
    if let Ok(dir) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{dir}/{name}"), body).unwrap();
    }
}
fn shape_err<T>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Shape(_)))
}

/// Feed a reviewer vector; caller must sort by CID text (the API contract).
fn feed(v: &Value, domain: Domain, limit: Limits) -> Result<[u8; 32], Error> {
    let m = &v["member"];
    let plan = (!m["plan"].is_null()).then(|| h(m["plan"].as_str().unwrap()));
    let mut ms: Vec<_> = m["membership"].as_array().unwrap().iter().collect();
    ms.sort_by_key(|r| r[0].as_str().unwrap().to_string());
    let rs = m["records"].as_array().unwrap();
    let mut os: Vec<_> = m["objects"].as_array().unwrap().iter().collect();
    os.sort_by_key(|r| r[0].as_str().unwrap().to_string());
    let archive = h(m["archive"].as_str().unwrap());
    let scope = h(m["scope"].as_str().unwrap());
    let mut b = MemberFraming::new(
        Header {
            profile: m["profile"].as_u64().unwrap() as u8,
            archive: archive.try_into().unwrap(),
            scope: scope.try_into().unwrap(),
            issuer: m["issuer"].as_str().unwrap(),
            plan: plan.as_deref(),
        },
        counts(ms.len() as u64, rs.len() as u64, os.len() as u64),
        domain,
        limit,
    )?;
    for r in ms {
        b.membership(&r[0].as_str().unwrap().parse().unwrap(), r[1].as_u64().unwrap())?;
    }
    b.begin_records()?;
    for r in rs {
        b.record(
            r[0].as_u64().unwrap(),
            &h(r[1].as_str().unwrap()),
            &h(r[2].as_str().unwrap()),
            &h(r[3].as_str().unwrap()),
        )?;
    }
    b.begin_objects()?;
    for r in os {
        b.original_object(&r[0].as_str().unwrap().parse().unwrap(), &h(r[1].as_str().unwrap()))?;
    }
    b.finish()
}
fn feed_r1(v: &Value, limit: Limits) -> Result<[u8; 32], Error> {
    let mut cs: Vec<_> = v["candidates"].as_array().unwrap().iter().collect();
    cs.sort_by_key(|r| r[0].as_str().unwrap().to_string());
    let mut b = RestorationFraming::new(cs.len() as u64, limit)?;
    for c in cs {
        b.candidate(&c[0].as_str().unwrap().parse().unwrap(), &h(c[1].as_str().unwrap()))?;
    }
    b.finish()
}
fn with_bytes(n: u64) -> Limits {
    let mut l = limits();
    l.bytes = n;
    l
}

/// RA1: digests equal the prose-only implementation, and the work-byte budget is
/// exact: preimage-stream length for M1/O1, plus candidate verification for R1.
#[test]
fn rv_a1_vectors_and_exact_work_accounting() {
    let mut out = String::new();
    for v in vectors()["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let mw = v["member_work"].as_u64().unwrap();
        let ow = v["output_work"].as_u64().unwrap();
        let m = feed(v, Domain::Member, limits()).unwrap();
        let o = feed(v, Domain::Output, limits()).unwrap();
        assert_eq!(hex(&m), v["M1"], "{name} M1");
        assert_eq!(hex(&o), v["O1"], "{name} O1");
        assert_eq!(feed(v, Domain::Member, with_bytes(mw)).unwrap(), m, "{name} exact");
        assert_eq!(feed(v, Domain::Member, with_bytes(mw - 1)), Err(Error::Budget), "{name} -1");
        assert_eq!(feed(v, Domain::Output, with_bytes(ow)).unwrap(), o, "{name} O exact");
        out.push_str(&format!("{name}\tM1=match\tO1=match\tmember_work={mw}\texact=ok\tminus1=Budget\n"));
        if !v["R1"].is_null() {
            let rw = v["r1_work"].as_u64().unwrap();
            let r = feed_r1(v, limits()).unwrap();
            assert_eq!(hex(&r), v["R1"], "{name} R1");
            assert_eq!(feed_r1(v, with_bytes(rw)).unwrap(), r, "{name} R1 exact");
            if rw > 0 {
                assert_eq!(feed_r1(v, with_bytes(rw - 1)), Err(Error::Budget), "{name} R1 -1");
            }
            out.push_str(&format!("{name}\tR1=match\tr1_work={rw}\texact=ok\tminus1=Budget\n"));
        }
    }
    emit("ra1-vectors.tsv", &out);
}

/// RA2: canonical CID *text* order is accepted; binary order is refused, for
/// membership, original objects and R1 candidates (semantic, not label-only).
#[test]
fn rv_a2_text_order_accepted_binary_order_refused() {
    let mut out = String::new();
    for p in vectors()["pairs"].as_array().unwrap() {
        let (ta, a, tb, b) = (
            p[0].as_str().unwrap(),
            h(p[1].as_str().unwrap()),
            p[2].as_str().unwrap(),
            h(p[3].as_str().unwrap()),
        );
        let (ca, cb): (Cid, Cid) = (ta.parse().unwrap(), tb.parse().unwrap());
        assert!(ta < tb && cb.to_bytes() < ca.to_bytes(), "pair discriminates");
        for (label, first, second, ok) in [("text", &ca, &cb, true), ("binary", &cb, &ca, false)] {
            let mut m = MemberFraming::new(header3(), counts(2, 0, 0), Domain::Member, limits()).unwrap();
            m.membership(first, 1).unwrap();
            assert_eq!(m.membership(second, 1).is_ok(), ok, "membership {label}");
            let mut o = MemberFraming::new(header2(), counts(0, 0, 2), Domain::Output, limits()).unwrap();
            o.begin_records().unwrap();
            o.begin_objects().unwrap();
            o.original_object(first, b"x").unwrap();
            assert_eq!(o.original_object(second, b"x").is_ok(), ok, "objects {label}");
            let mut r = RestorationFraming::new(2, limits()).unwrap();
            let bytes = |c: &Cid| if c == &ca { a.clone() } else { b.clone() };
            r.candidate(first, &bytes(first)).unwrap();
            assert_eq!(r.candidate(second, &bytes(second)).is_ok(), ok, "R1 {label}");
            out.push_str(&format!("{ta} {tb}\t{label}\taccepted={ok}\n"));
        }
    }
    emit("ra2-order.tsv", &out);
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
    check("membership-after-begin-records", m.membership(&k2, 1).is_err());
    // begin_records twice
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check("begin-records-twice", m.begin_records().is_err());
    // record before begin_records
    let mut m = MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    check("record-before-begin-records", m.record(1, b"m", b"r", b"p").is_err());
    // object during records phase
    let mut m = MemberFraming::new(header2(), counts(0, 1, 1), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    check("object-in-records-phase", m.original_object(&k1, b"x").is_err());
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
    check("record-sequence-zero", m.record(0, b"m", b"r", b"p").is_err());
    let mut m = MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.record(1, b"m", b"r", b"p").unwrap();
    check("record-beyond-count", m.record(2, b"m", b"r", b"p").is_err());
    let mut m = MemberFraming::new(header2(), counts(0, 2, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.record(1, b"m", b"r", b"p").unwrap();
    check("record-repeat-sequence", m.record(1, b"m", b"r", b"p").is_err());
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
    check("r1-candidate-beyond-count", r.candidate(&cid(b"b"), b"b").is_err());
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
    for (len, want) in [(0u64, false), (1, true), (MIB4 as u64, true), (MIB4 as u64 + 1, false)] {
        let mut m = MemberFraming::new(header3(), counts(1, 0, 0), Domain::Member, limits()).unwrap();
        expect(&format!("membership-length-{len}"), m.membership(&k, len).is_ok(), want);
    }
    for field in 0..3 {
        let maxes = [65536usize, 65536, 16384];
        for (len, want) in [(0usize, false), (1, true), (maxes[field], true), (maxes[field] + 1, false)] {
            let mut parts = [vec![1u8], vec![1u8], vec![1u8]];
            parts[field] = vec![7; len];
            let mut m = MemberFraming::new(header2(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
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
        let mut m = MemberFraming::new(header2(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
        m.begin_records().unwrap();
        m.begin_objects().unwrap();
        expect(&format!("original-object-len-{len}"), m.original_object(&k, &bytes).is_ok(), want);
    }
    // Restoration: empty candidate refused even when the CID IS the empty-bytes CID.
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    expect("candidate-empty-with-matching-cid", r.candidate(&cid(b""), b"").is_ok(), false);
    let big = vec![4u8; MIB4 + 1];
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    expect("candidate-4MiB+1-matching-cid", r.candidate(&cid(&big), &big).is_ok(), false);
    // Counts above the safe integer, and duration edges.
    let mut l = limits();
    l.items = u64::MAX;
    expect(
        "count-above-safe",
        MemberFraming::new(header2(), counts(0, 9_007_199_254_740_992, 0), Domain::Member, l.clone()).is_ok(),
        false,
    );
    expect("r1-count-above-safe", RestorationFraming::new(9_007_199_254_740_992, l).is_ok(), false);
    for (d, want) in [(Duration::ZERO, false), (Duration::from_secs(3600), true), (Duration::from_secs(3601), false)] {
        let mut l = limits();
        l.duration = d;
        expect(&format!("duration-{d:?}"), RestorationFraming::new(0, l).is_ok(), want);
    }
    emit("ra4-bounds.tsv", &out);
}

/// RA5: only CIDv1 raw/sha2-256 object identifiers are framed.
#[test]
fn rv_a5_non_raw_sha256_cids_refused_everywhere() {
    let digest = Sha256::digest(b"x");
    let mut cases: Vec<(&str, Vec<u8>)> = vec![];
    let mut dag = vec![1, 0x71, 0x12, 0x20];
    dag.extend_from_slice(&digest);
    cases.push(("dag-cbor", dag));
    let mut v0 = vec![0x12, 0x20];
    v0.extend_from_slice(&digest);
    cases.push(("cidv0", v0));
    let mut s512 = vec![1, 0x55, 0x13, 0x40];
    s512.extend_from_slice(&[9u8; 64]);
    cases.push(("sha2-512", s512));
    cases.push(("identity", vec![1, 0x55, 0x00, 0x01, b'x']));
    let mut out = String::new();
    for (name, raw) in cases {
        let Ok(c) = Cid::from_bytes(&raw) else {
            out.push_str(&format!("{name}\tCid::from_bytes refused (not constructible)\n"));
            continue;
        };
        let mut m = MemberFraming::new(header3(), counts(1, 0, 0), Domain::Member, limits()).unwrap();
        let a = shape_err(m.membership(&c, 1));
        let mut o = MemberFraming::new(header2(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
        o.begin_records().unwrap();
        o.begin_objects().unwrap();
        let b = shape_err(o.original_object(&c, b"x"));
        let mut r = RestorationFraming::new(1, limits()).unwrap();
        let d = shape_err(r.candidate(&c, b"x"));
        out.push_str(&format!("{name}\tmembership={a}\tobject={b}\tcandidate={d}\n"));
        assert!(a && b && d, "{name}");
    }
    emit("ra5-cid-shapes.tsv", &out);
}

/// RA6: every failed operation kind poisons every later operation and finish.
#[test]
fn rv_a6_any_failure_poisons_all_later_operations() {
    let (k1, k2) = {
        let mut v = [cid(b"k1"), cid(b"k2")];
        v.sort_by_key(|c| c.to_string());
        (v[0].clone(), v[1].clone())
    };
    let mut out = String::new();
    type Step = fn(&mut MemberFraming, &Cid, &Cid) -> Result<(), Error>;
    let failures: Vec<(&str, Step)> = vec![
        ("membership-unordered", |m, a, b| {
            m.membership(b, 1)?;
            m.membership(a, 1)
        }),
        ("membership-length", |m, a, _| m.membership(a, 0)),
        ("begin-records-early", |m, _, _| m.begin_records()),
    ];
    for (name, fail) in failures {
        let mut m = MemberFraming::new(header3(), counts(2, 1, 1), Domain::Member, limits()).unwrap();
        assert!(fail(&mut m, &k1, &k2).is_err(), "{name} must fail first");
        let after = [
            m.membership(&k2, 1),
            m.begin_records(),
            m.record(1, b"m", b"r", b"p"),
            m.begin_objects(),
            m.original_object(&k1, b"x"),
        ];
        let fin = m.finish();
        let poisoned = after.iter().all(|r| r == &Err(Error::Poisoned)) && fin == Err(Error::Poisoned);
        out.push_str(&format!("{name}\tafter={after:?}\tfinish={fin:?}\n"));
        assert!(poisoned, "{name}");
    }
    // Budget failure mid-object, cancellation during begin_objects, record shape.
    let l = with_bytes(400);
    let mut m = MemberFraming::new(header2(), counts(0, 0, 2), Domain::Member, l).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    assert_eq!(m.original_object(&k1, &[0u8; 1000]), Err(Error::Budget));
    let after = m.original_object(&k2, b"x");
    out.push_str(&format!("budget-mid-object\tafter={after:?}\n"));
    assert_eq!(after, Err(Error::Poisoned));
    let l = limits();
    let c = l.cancelled.clone();
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, l).unwrap();
    m.begin_records().unwrap();
    c.store(true, Ordering::Relaxed);
    assert_eq!(m.begin_objects(), Err(Error::Cancelled));
    c.store(false, Ordering::Relaxed);
    let after = m.begin_objects();
    out.push_str(&format!("cancel-then-uncancel\tafter={after:?}\n"));
    assert_eq!(after, Err(Error::Poisoned));
    assert_eq!(m.finish(), Err(Error::Poisoned));
    let mut m = MemberFraming::new(header2(), counts(0, 2, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    assert!(m.record(1, b"", b"r", b"p").is_err());
    let after = m.record(1, b"m", b"r", b"p");
    out.push_str(&format!("record-shape-then-valid\tafter={after:?}\n"));
    assert_eq!(after, Err(Error::Poisoned));
    // R1: budget during verification poisons.
    let big = vec![1u8; 200_000];
    let mut r = RestorationFraming::new(2, with_bytes(150_000)).unwrap();
    assert_eq!(r.candidate(&cid(&big), &big), Err(Error::Budget));
    let after = r.candidate(&cid(b"z"), b"z");
    out.push_str(&format!("r1-budget-then-valid\tafter={after:?}\n"));
    assert_eq!(after, Err(Error::Poisoned));
    emit("ra6-poison.tsv", &out);
}

/// RA7: missing, zero-length, corrupt and correct originals are distinct M1s,
/// and every M1 differs from its O1.
#[test]
fn rv_a7_presence_states_are_distinct() {
    let good = b"good object".to_vec();
    let k = cid(&good);
    let digest = |obj: Option<&[u8]>, d: Domain| {
        let n = u64::from(obj.is_some());
        let mut m = MemberFraming::new(header2(), counts(0, 0, n), d, limits()).unwrap();
        m.begin_records().unwrap();
        m.begin_objects().unwrap();
        if let Some(b) = obj {
            m.original_object(&k, b).unwrap();
        }
        m.finish().unwrap()
    };
    let states: [(&str, Option<&[u8]>); 4] = [
        ("missing", None),
        ("empty", Some(b"")),
        ("corrupt", Some(b"bad")),
        ("correct", Some(&good)),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    for (name, obj) in states {
        let (m, o) = (digest(obj, Domain::Member), digest(obj, Domain::Output));
        assert_ne!(m, o);
        assert!(seen.insert(m) && seen.insert(o), "{name} collides");
        out.push_str(&format!("{name}\tM1={}\tO1={}\n", hex(&m), hex(&o)));
    }
    emit("ra7-presence.tsv", &out);
}

fn hash_time_4mib() -> Duration {
    let data = vec![7u8; MIB4];
    let t = Instant::now();
    std::hint::black_box(Sha256::digest(&data));
    t.elapsed()
}

/// RA8: cancellation is observed *within* a single large object or candidate
/// (per-chunk polling), not only between operations. Timing-based; the probe
/// records the measured hash time and refuses to judge if hashing is too fast.
#[test]
fn rv_a8_cancellation_and_deadline_are_polled_within_one_payload() {
    let full = hash_time_4mib();
    let mut out = format!("sha256-4MiB-in-test-build={full:?}\n");
    if full < Duration::from_millis(30) {
        out.push_str("SKIP: hashing too fast for a timing judgement\n");
        emit("ra8-polling.tsv", &out);
        return;
    }
    let data = vec![7u8; MIB4];
    let key = cid(&data);
    for kind in ["member-object", "r1-candidate"] {
        let l = limits();
        let cancel = l.cancelled.clone();
        let go = Arc::new(AtomicBool::new(false));
        let go2 = go.clone();
        let t = std::thread::spawn(move || {
            while !go2.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            std::thread::sleep(Duration::from_millis(2));
            cancel.store(true, Ordering::SeqCst);
        });
        let (r, el) = if kind == "member-object" {
            let mut m = MemberFraming::new(header2(), counts(0, 0, 1), Domain::Member, l).unwrap();
            m.begin_records().unwrap();
            m.begin_objects().unwrap();
            go.store(true, Ordering::SeqCst);
            let s = Instant::now();
            (m.original_object(&key, &data), s.elapsed())
        } else {
            let mut r = RestorationFraming::new(1, l).unwrap();
            go.store(true, Ordering::SeqCst);
            let s = Instant::now();
            (r.candidate(&key, &data), s.elapsed())
        };
        t.join().unwrap();
        out.push_str(&format!("cancel-{kind}\tresult={r:?}\tcall={el:?}\n"));
        assert_eq!(r, Err(Error::Cancelled), "{kind}: cancellation must interrupt the payload");
        assert!(el < full / 2, "{kind}: latency {el:?} vs full hash {full:?}");
    }
    // Deadline expiring during one object.
    let mut l = limits();
    l.duration = Duration::from_millis(5);
    let mut m = MemberFraming::new(header2(), counts(0, 0, 1), Domain::Member, l).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    let s = Instant::now();
    let r = m.original_object(&key, &data);
    let el = s.elapsed();
    out.push_str(&format!("deadline-member-object\tresult={r:?}\tcall={el:?}\n"));
    assert_eq!(r, Err(Error::Budget));
    assert!(el < full / 2);
    emit("ra8-polling.tsv", &out);
}

/// RA9: item and deadline limits at their exact edges; finish re-checks.
#[test]
fn rv_a9_item_edges_and_finish_rechecks() {
    let mut out = String::new();
    let mut l = limits();
    l.items = 3;
    let ok = MemberFraming::new(header3(), counts(1, 1, 1), Domain::Member, l.clone()).is_ok();
    out.push_str(&format!("items==total\taccepted={ok}\n"));
    assert!(ok);
    l.items = 2;
    let r = MemberFraming::new(header3(), counts(1, 1, 1), Domain::Member, l.clone()).err();
    out.push_str(&format!("items==total-1\t{r:?}\n"));
    assert_eq!(r, Some(Error::Budget));
    let r = RestorationFraming::new(3, l).err();
    out.push_str(&format!("r1 items==count-1\t{r:?}\n"));
    assert_eq!(r, Some(Error::Budget));
    let mut l = limits();
    l.duration = Duration::from_millis(20);
    let mut m = MemberFraming::new(header2(), counts(0, 0, 0), Domain::Member, l).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let r = m.finish();
    out.push_str(&format!("finish-after-deadline\t{r:?}\n"));
    assert_eq!(r, Err(Error::Budget));
    emit("ra9-items.tsv", &out);
}

/// RA10 (characterisation of documented non-verification): the O1 builder frames
/// whatever object bytes it is given, including empty or hash-mismatched bytes.
/// The doc says O1 commits to a *fully verified* output; that verification is a
/// caller duty this module does not perform. Recorded, not asserted as a defect.
#[test]
fn rv_a10_output_domain_does_not_verify_objects() {
    let k = cid(b"expected");
    let mut out = String::new();
    for (name, bytes) in [("o1-corrupt", b"other".as_slice()), ("o1-empty", b"".as_slice())] {
        let mut m = MemberFraming::new(header2(), counts(0, 0, 1), Domain::Output, limits()).unwrap();
        m.begin_records().unwrap();
        m.begin_objects().unwrap();
        let r = m.original_object(&k, bytes).and_then(|_| m.finish().map(|_| ()));
        out.push_str(&format!("{name}\tframed={}\n", r.is_ok()));
    }
    emit("ra10-output-unverified.tsv", &out);
}
