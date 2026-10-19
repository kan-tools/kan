#![cfg(feature = "v2-storage")]
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
    time::Duration,
};
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../.design/fixtures/recovery-commitments-v1.json"
    ))
    .unwrap()
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v["$bytes"].as_str().unwrap(), 4 * 1024 * 1024).unwrap()
}
fn limits() -> Limits {
    Limits {
        items: 1000,
        bytes: 32 * 1024 * 1024,
        duration: Duration::from_secs(5),
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
fn header() -> Header<'static> {
    Header {
        profile: 2,
        archive: [1; 32],
        scope: [2; 32],
        issuer: "framing-only-fixture-not-authority",
        plan: None,
    }
}
fn cid(bytes: &[u8]) -> Cid {
    let mut raw = vec![1, 0x55, 0x12, 0x20];
    raw.extend_from_slice(&Sha256::digest(bytes));
    Cid::from_bytes(&raw).unwrap()
}
fn member(value: &Value, domain: Domain) -> [u8; 32] {
    let m = &value["member"];
    let plan = (!m["plan"].is_null()).then(|| raw(&m["plan"]));
    let mut memberships: Vec<_> = m["membership"].as_array().unwrap().iter().collect();
    memberships.sort_by_key(|row| row[0].as_str().unwrap());
    let records = m["records"].as_array().unwrap();
    let mut objects: Vec<_> = m["objects"].as_array().unwrap().iter().collect();
    objects.sort_by_key(|row| row[0].as_str().unwrap());
    let mut hash = MemberFraming::new(
        Header {
            profile: m["profile"].as_u64().unwrap() as u8,
            archive: raw(&m["archive"]).try_into().unwrap(),
            scope: raw(&m["scope"]).try_into().unwrap(),
            issuer: m["issuer"].as_str().unwrap(),
            plan: plan.as_deref(),
        },
        counts(
            memberships.len() as u64,
            records.len() as u64,
            objects.len() as u64,
        ),
        domain,
        limits(),
    )
    .unwrap();
    for row in memberships {
        hash.membership(
            &row[0].as_str().unwrap().parse().unwrap(),
            row[1].as_u64().unwrap(),
        )
        .unwrap()
    }
    hash.begin_records().unwrap();
    for row in records {
        hash.record(
            row[0].as_u64().unwrap(),
            &raw(&row[1]),
            &raw(&row[2]),
            &raw(&row[3]),
        )
        .unwrap()
    }
    hash.begin_objects().unwrap();
    for row in objects {
        hash.original_object(&row[0].as_str().unwrap().parse().unwrap(), &raw(&row[1]))
            .unwrap()
    }
    hash.finish().unwrap()
}
#[test]
fn independent_python_member_output_and_restoration_framing_matches() {
    let f = fixture();
    for row in f["member"].as_array().unwrap() {
        let m = member(row, Domain::Member);
        let o = member(row, Domain::Output);
        assert_eq!(hex(&m), row["M1"], "{}", row["name"]);
        assert_eq!(hex(&o), row["O1"], "{}", row["name"]);
        assert_ne!(m, o);
    }
    for row in f["restorations"].as_array().unwrap() {
        let mut candidates: Vec<_> = row["candidates"].as_array().unwrap().iter().collect();
        candidates.sort_by_key(|r| r[0].as_str().unwrap());
        let mut hash = RestorationFraming::new(candidates.len() as u64, limits()).unwrap();
        for candidate in candidates {
            hash.candidate(
                &candidate[0].as_str().unwrap().parse().unwrap(),
                &raw(&candidate[1]),
            )
            .unwrap()
        }
        assert_eq!(hex(&hash.finish().unwrap()), row["R1"]);
    }
}
#[test]
fn missing_empty_corrupt_and_restored_bytes_remain_distinct() {
    let f = fixture();
    let rows = f["member"].as_array().unwrap();
    let digests: std::collections::HashSet<_> =
        rows.iter().map(|r| member(r, Domain::Member)).collect();
    assert_eq!(digests.len(), rows.len());
    let mut m = MemberFraming::new(header(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    m.original_object(&cid(b"X"), b"").unwrap();
    assert!(m.finish().is_ok());
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    assert!(r.candidate(&cid(b"X"), b"").is_err());
    assert_eq!(r.finish(), Err(Error::Poisoned));
}
#[test]
fn skipped_extra_and_reordered_sections_never_finish() {
    let mut early =
        MemberFraming::new(header(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    assert!(early.begin_objects().is_err());
    assert_eq!(early.begin_records(), Err(Error::Poisoned));
    assert_eq!(early.finish(), Err(Error::Poisoned));
    let mut missing =
        MemberFraming::new(header(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    missing.begin_records().unwrap();
    assert!(missing.begin_objects().is_err());
    assert_eq!(missing.finish(), Err(Error::Poisoned));
    let mut sequence =
        MemberFraming::new(header(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    sequence.begin_records().unwrap();
    assert!(sequence.record(2, b"m", b"r", b"p").is_err());
    assert_eq!(sequence.finish(), Err(Error::Poisoned));
    let mut extra =
        MemberFraming::new(header(), counts(0, 0, 0), Domain::Member, limits()).unwrap();
    extra.begin_records().unwrap();
    extra.begin_objects().unwrap();
    assert!(extra.original_object(&cid(b"x"), b"x").is_err());
    assert_eq!(extra.finish(), Err(Error::Poisoned));
    let incomplete = RestorationFraming::new(1, limits()).unwrap();
    assert!(incomplete.finish().is_err());
}
#[test]
fn sorted_unique_cids_are_required_and_candidate_hashes_are_checked() {
    let mut names = [cid(b"a"), cid(b"b")];
    names.sort_by_key(|c| c.to_string());
    for keys in [[&names[0], &names[0]], [&names[1], &names[0]]] {
        let mut m =
            MemberFraming::new(header(), counts(0, 0, 2), Domain::Member, limits()).unwrap();
        m.begin_records().unwrap();
        m.begin_objects().unwrap();
        m.original_object(keys[0], b"corrupt").unwrap();
        assert!(m.original_object(keys[1], b"corrupt").is_err());
        assert_eq!(m.finish(), Err(Error::Poisoned));
    }
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    assert!(r.candidate(&cid(b"a"), b"b").is_err());
    assert_eq!(r.candidate(&cid(b"a"), b"a"), Err(Error::Poisoned));
    assert_eq!(r.finish(), Err(Error::Poisoned));
}
#[test]
fn local_limits_cancellation_and_failed_work_are_explicit() {
    let mut low = limits();
    low.items = 1;
    assert!(matches!(
        MemberFraming::new(header(), counts(0, 0, 2), Domain::Member, low),
        Err(Error::Budget)
    ));
    let mut low = limits();
    low.bytes = 1;
    assert!(matches!(
        MemberFraming::new(header(), counts(0, 0, 0), Domain::Member, low),
        Err(Error::Budget)
    ));
    let limit = limits();
    let cancel = limit.cancelled.clone();
    let mut m = MemberFraming::new(header(), counts(0, 0, 0), Domain::Member, limit).unwrap();
    cancel.store(true, Ordering::Relaxed);
    assert_eq!(m.begin_records(), Err(Error::Cancelled));
    cancel.store(false, Ordering::Relaxed);
    assert_eq!(m.finish(), Err(Error::Poisoned));
    let limit = limits();
    let cancel = limit.cancelled.clone();
    let r = RestorationFraming::new(0, limit).unwrap();
    cancel.store(true, Ordering::Relaxed);
    assert_eq!(r.finish(), Err(Error::Cancelled));
    let mut short = limits();
    short.duration = Duration::from_millis(25);
    let m = MemberFraming::new(header(), counts(0, 0, 0), Domain::Member, short).unwrap();
    std::thread::sleep(Duration::from_millis(35));
    let mut m = m;
    assert_eq!(m.begin_records(), Err(Error::Budget));
    assert_eq!(m.finish(), Err(Error::Poisoned));
}
#[test]
fn maximum_objects_and_metadata_bounds_do_not_change_framing() {
    let bytes = vec![0xab; 4 * 1024 * 1024];
    let key = cid(&bytes);
    let mut r = RestorationFraming::new(1, limits()).unwrap();
    r.candidate(&key, &bytes).unwrap();
    assert!(r.finish().is_ok());
    let mut m = MemberFraming::new(header(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.record(1, &vec![0; 65536], &vec![1; 65536], &vec![2; 16384])
        .unwrap();
    m.begin_objects().unwrap();
    assert!(m.finish().is_ok());
    let mut m = MemberFraming::new(header(), counts(0, 1, 0), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    assert!(m.record(1, &vec![0; 65537], b"r", b"p").is_err());
    assert_eq!(m.finish(), Err(Error::Poisoned));
    let mut m = MemberFraming::new(header(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    assert!(m
        .original_object(&key, &vec![0; 4 * 1024 * 1024 + 1])
        .is_err());
    assert_eq!(m.finish(), Err(Error::Poisoned));
}

#[test]
fn failure_mid_payload_and_candidate_verification_consumes_budget_and_poisons() {
    let bytes = vec![9; 3 * 1024 * 1024];
    let key = cid(&bytes);
    let mut limit = limits();
    limit.bytes = 1024;
    let mut m = MemberFraming::new(header(), counts(0, 0, 1), Domain::Member, limit).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    assert_eq!(m.original_object(&key, &bytes), Err(Error::Budget));
    assert_eq!(m.finish(), Err(Error::Poisoned));
    // R1 spends work on both hash verification and commitment framing.
    let mut limit = limits();
    limit.bytes = 5 * 1024 * 1024;
    let mut r = RestorationFraming::new(1, limit).unwrap();
    assert_eq!(r.candidate(&key, &bytes), Err(Error::Budget));
    assert_eq!(r.finish(), Err(Error::Poisoned));
}

#[test]
fn profile_plan_and_cid_shape_cannot_be_silently_reinterpreted() {
    assert!(MemberFraming::new(header(), counts(1, 0, 0), Domain::Member, limits()).is_err());
    let mut h = header();
    h.profile = 3;
    assert!(MemberFraming::new(h, counts(0, 0, 0), Domain::Member, limits()).is_err());
    let mut h = header();
    h.plan = Some(b"plan");
    assert!(MemberFraming::new(h, counts(0, 0, 0), Domain::Member, limits()).is_err());
    let mut h = header();
    h.profile = 4;
    assert!(MemberFraming::new(h, counts(0, 0, 0), Domain::Member, limits()).is_err());
    let mut bytes = cid(b"x").to_bytes();
    bytes[1] = 0x71;
    let wrong = Cid::from_bytes(&bytes).unwrap();
    let mut m = MemberFraming::new(header(), counts(0, 0, 1), Domain::Member, limits()).unwrap();
    m.begin_records().unwrap();
    m.begin_objects().unwrap();
    assert!(m.original_object(&wrong, b"x").is_err());
    assert_eq!(m.finish(), Err(Error::Poisoned));
}
