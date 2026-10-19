#![cfg(feature = "v2-storage")]
use kan::evidence_copy_plan::Plan;
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../.design/fixtures/copy-plan-v1.json")).unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn independent_plan_bytes_and_archive_commitments_match() {
    let fixtures = fixture();
    for vector in fixtures["positive"].as_array().unwrap() {
        let raw = unhex(vector["hex"].as_str().unwrap());
        let plan = Plan::decode(&raw).unwrap();
        assert_eq!(plan.bytes(), raw);
        assert_eq!(
            plan.archive_id().as_slice(),
            unhex(vector["archiveHex"].as_str().unwrap())
        );
        plan.check_archive(&plan.archive_id()).unwrap();
        let encoded =
            Plan::new(plan.source().clone(), plan.target().clone(), *plan.nonce()).unwrap();
        assert_eq!(encoded.bytes(), raw);
        assert_eq!(
            plan.source().through,
            vector["plan"]["sourceThrough"].as_u64().unwrap()
        );
    }
}
#[test]
fn malformed_or_unsupported_plans_refuse() {
    let fixtures = fixture();
    for vector in fixtures["negative"].as_array().unwrap() {
        let error = Plan::decode(&unhex(vector["hex"].as_str().unwrap())).unwrap_err();
        assert_eq!(
            error.class(),
            vector["expectedClass"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
        let reason = match error {
            kan::evidence::Error::Canonical(reason) | kan::evidence::Error::Schema(reason) => {
                reason
            }
        };
        assert_eq!(
            reason,
            vector["expectedReason"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}
#[test]
fn changing_each_owner_pin_or_source_coordinate_changes_archive_identity() {
    let fixtures = fixture();
    let original = Plan::decode(&unhex(fixtures["positive"][0]["hex"].as_str().unwrap())).unwrap();
    for field in [
        "through",
        "tip",
        "digest",
        "historical",
        "scope",
        "issuer",
        "nonce",
    ] {
        let mut source = original.source().clone();
        let mut target = original.target().clone();
        let mut nonce = *original.nonce();
        match field {
            "through" => source.through += 1,
            "tip" => {
                source.tip = Some(
                    kan::cid::content_cid(&atproto_dasl::Ipld::String("other-tip".into())).unwrap(),
                )
            }
            "digest" => source.digest[0] ^= 1,
            "historical" => source.historical_issuer = target.issuer.clone(),
            "scope" => target.scope[0] ^= 1,
            "issuer" => target.issuer = source.historical_issuer.clone(),
            _ => nonce[0] ^= 1,
        }
        let changed = Plan::new(source, target, nonce).unwrap();
        assert_ne!(changed.archive_id(), original.archive_id(), "{field}");
        assert!(
            changed.check_archive(&original.archive_id()).is_err(),
            "{field}"
        );
    }
}
