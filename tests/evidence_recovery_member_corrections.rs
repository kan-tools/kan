#![cfg(feature = "v2-storage")]
//! Behaviour probes intentionally use only the pre-correction public API, so a
//! whole production-file reversion can compile and demonstrate the regressions.
use atproto_dasl::Cid;
use kan::{
    evidence_recovery_member::{self as member, Budget, Input, Membership, Object, Row},
    evidence_recovery_observation::Context,
    evidence_service::unhex,
};
use serde_json::Value;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn bytes(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 4 * 1024 * 1024).unwrap()
}
fn check(name: &str) -> Result<member::Member, member::Error> {
    let fixture: Value =
        serde_json::from_str(include_str!("../.design/fixtures/recovery-member-v1.json")).unwrap();
    let v = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    let c = &v["context"];
    let context = Context {
        bundle: bytes(&c["bundle"]).try_into().unwrap(),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: bytes(&c["archive"]).try_into().unwrap(),
        scope: bytes(&c["scope"]).try_into().unwrap(),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    };
    let plan = (!v["plan"].is_null()).then(|| bytes(&v["plan"]));
    let rs: Vec<_> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r[0].as_u64().unwrap(),
                bytes(&r[1]),
                bytes(&r[2]),
                bytes(&r[3]),
            )
        })
        .collect();
    let ms: Vec<(Cid, u64)> = v["membership"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m[0].as_str().unwrap().parse().unwrap(),
                m[1].as_u64().unwrap(),
            )
        })
        .collect();
    let os: Vec<(Cid, Vec<u8>)> = v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o[0].as_str().unwrap().parse().unwrap(), bytes(&o[1])))
        .collect();
    let records: Vec<_> = rs
        .iter()
        .map(|(sequence, manifest, receipt, proof)| Row {
            sequence: *sequence,
            manifest,
            receipt,
            proof,
        })
        .collect();
    let membership: Vec<_> = ms
        .iter()
        .map(|(cid, length)| Membership {
            cid,
            length: *length,
        })
        .collect();
    let objects: Vec<_> = os
        .iter()
        .map(|(cid, bytes)| Object { cid, bytes })
        .collect();
    member::verify(
        Input {
            context: &context,
            plan: plan.as_deref(),
            records: &records,
            membership: &membership,
            objects: &objects,
        },
        Budget {
            items: 1000,
            input_bytes: 32 * 1024 * 1024,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )
}
#[test]
fn authentic_bytes_with_false_metadata_are_not_repairable_loss() {
    assert_eq!(check("profile2-3-intact").unwrap().verified_requests(), 3);
    for name in [
        "hash-valid-false-authenticated-length",
        "empty-cid-false-authenticated-length",
        "unrepresentable-service-request-length",
        "reused-missing-service-request",
    ] {
        assert!(
            check(name).is_err(),
            "{name}: contradictory metadata accepted as repairable loss"
        );
    }
}
#[test]
fn incomplete_membership_has_no_authenticated_length_or_byte_classification() {
    let m = check("partial-membership-fabrication-remains-unverified").unwrap();
    assert!(!m.recipe_metadata_complete());
    assert_eq!(m.losses().len(), 1);
    assert_eq!(m.losses()[0].occurrence, None);
    assert_eq!(m.losses()[0].expected_length, None);
    let m = check("partial-membership-length-does-not-corrupt-valid-bytes").unwrap();
    assert!(!m.recipe_metadata_complete());
    assert!(
        m.losses().is_empty(),
        "unauthenticated length reclassified authentic bytes"
    );
}
