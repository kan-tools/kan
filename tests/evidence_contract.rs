#![cfg(feature = "evidence-contract")]

use std::collections::BTreeMap;

use atproto_dasl::{Cid, Ipld};
use kan::evidence::{self, Decoded, Inventory, Operation, Record};
use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/evidence-v1/vectors.json")).unwrap()
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn ipld(value: &Value) -> Ipld {
    match value {
        Value::Null => Ipld::Null,
        Value::Bool(v) => Ipld::Bool(*v),
        Value::Number(v) => Ipld::Integer(v.as_i64().unwrap() as i128),
        Value::String(v) => Ipld::String(v.clone()),
        Value::Array(v) => Ipld::List(v.iter().map(ipld).collect()),
        Value::Object(v) if v.len() == 1 && v.contains_key("$map") => Ipld::Map(
            v["$map"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), ipld(v)))
                .collect(),
        ),
        Value::Object(v) if v.len() == 1 && v.contains_key("$bytes") => {
            Ipld::Bytes(unhex(v["$bytes"].as_str().unwrap()))
        }
        Value::Object(v) if v.len() == 1 && v.contains_key("$link") => {
            Ipld::Link(v["$link"].as_str().unwrap().parse().unwrap())
        }
        Value::Object(v) => Ipld::Map(v.iter().map(|(k, v)| (k.clone(), ipld(v))).collect()),
    }
}

fn value(name: &str) -> Value {
    fixtures()["positive"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["value"]
        .clone()
}

fn record(value: &Value) -> Record {
    let Decoded::Known(record) = evidence::encode(&ipld(value)).unwrap() else {
        panic!("expected known record");
    };
    record
}

#[test]
fn independent_canonical_cid_and_signing_vectors() {
    for vector in fixtures()["positive"].as_array().unwrap() {
        let expected = unhex(vector["hex"].as_str().unwrap());
        let cid: Cid = vector["cid"].as_str().unwrap().parse().unwrap();
        for decoded in [
            evidence::decode(&expected).unwrap(),
            evidence::encode(&ipld(&vector["value"])).unwrap(),
        ] {
            match decoded {
                Decoded::Known(record) => {
                    assert_eq!(vector["supported"], true);
                    assert_eq!(record.bytes(), expected, "{}", vector["name"]);
                    assert_eq!(record.cid(), &cid);
                    assert_eq!(
                        record.signing_preimage(),
                        unhex(vector["signingHex"].as_str().unwrap())
                    );
                }
                Decoded::Unsupported { bytes, cid: actual } => {
                    assert_eq!(vector["supported"], false);
                    assert_eq!(bytes, expected);
                    assert_eq!(actual, cid);
                }
            }
        }
    }
}

#[test]
fn malformed_known_records_never_fall_back_to_unsupported() {
    for vector in fixtures()["negative"].as_array().unwrap() {
        let error = evidence::decode(&unhex(vector["hex"].as_str().unwrap())).unwrap_err();
        assert_eq!(
            error.class(),
            vector["class"].as_str().unwrap(),
            "{}: {error}",
            vector["name"]
        );
    }
}

#[test]
fn byte_depth_and_allocation_bounds() {
    assert!(evidence::decode(&vec![0; evidence::MAX_RECORD_BYTES + 1]).is_err());
    // Unknown records obey the same scalar and resource rules.
    let mut future = value("unknown-version");
    future["body"]["future"] = Value::String("x".repeat(evidence::MAX_RECORD_BYTES));
    assert!(evidence::encode(&ipld(&future)).is_err());
    let mut nested = Ipld::Null;
    for _ in 0..34 {
        nested = Ipld::List(vec![nested]);
    }
    let envelope = Ipld::Map(BTreeMap::from([
        ("v".into(), Ipld::Integer(2)),
        ("kind".into(), Ipld::String("future".into())),
        (
            "body".into(),
            Ipld::Map(BTreeMap::from([("nested".into(), nested)])),
        ),
    ]));
    assert!(evidence::encode(&envelope).is_err());
    assert!(evidence::decode(&atproto_dasl::to_vec(&envelope).unwrap()).is_err());
    for scalar in [
        Ipld::Float(1.0),
        Ipld::Integer(-1),
        Ipld::Integer(evidence::MAX_SAFE_INTEGER + 1),
    ] {
        let envelope = Ipld::Map(BTreeMap::from([
            ("v".into(), Ipld::Integer(2)),
            ("kind".into(), Ipld::String("future".into())),
            (
                "body".into(),
                Ipld::Map(BTreeMap::from([("scalar".into(), scalar)])),
            ),
        ]));
        assert!(evidence::encode(&envelope).is_err());
    }
}

#[test]
fn receipts_bind_all_manifest_coordinates_but_do_not_prove_durability() {
    let manifest = record(&value("manifest"));
    let receipt = record(&value("receipt"));
    assert!(evidence::binds(&receipt, &manifest));
    assert!(!evidence::binds(&manifest, &receipt));
    assert!(!evidence::binds(&receipt, &record(&value("second-batch"))));
    for (key, replacement) in [
        ("scopeToken", serde_json::json!({"$bytes": "09".repeat(32)})),
        ("operation", serde_json::json!({"$bytes": "09".repeat(16)})),
        ("position", serde_json::json!(1)),
        (
            "manifest",
            serde_json::json!({"$link": record(&value("capture")).cid().to_string()}),
        ),
    ] {
        let mut changed = value("receipt");
        changed["body"][key] = replacement;
        assert!(
            !evidence::binds(&record(&changed), &manifest),
            "ignored {key}"
        );
    }
}

#[test]
fn inventory_distinguishes_absence_withholding_and_incomplete_coverage() {
    let snapshot = record(&value("manifest")).cid().clone();
    let other = record(&value("second-batch")).cid().clone();
    let matched = record(&value("capture")).cid().clone();
    for row in fixtures()["inventory"].as_array().unwrap() {
        let covered = match row[1].as_str() {
            Some("same") => Some(&snapshot),
            Some("other") => Some(&other),
            _ => None,
        };
        let result = evidence::inventory(
            row[0].as_bool().unwrap(),
            &snapshot,
            covered,
            row[2].as_bool().unwrap(),
            row[3].as_u64().unwrap() as usize,
            if row[4].as_bool().unwrap() {
                vec![matched.clone()]
            } else {
                vec![]
            },
        );
        let label = match &result {
            Inventory::AccessLimited => "access-limited",
            Inventory::Incomplete => "incomplete",
            Inventory::Present { matches, complete } => {
                assert_eq!(matches, &vec![matched.clone()]);
                if *complete {
                    "present-complete"
                } else {
                    "present-incomplete"
                }
            }
            Inventory::AbsentAtSnapshot { snapshot: actual } => {
                assert_eq!(actual, &snapshot);
                "absent-at-snapshot"
            }
        };
        assert_eq!(label, row[6].as_str().unwrap(), "{row}");
        // row[5] is displayExcluded: intentionally not input to source inventory.
    }
}

#[test]
fn retry_decisions_do_not_depend_on_view_trust_or_subject_existence() {
    let candidate = record(&value("manifest")).cid().clone();
    let conflict = record(&value("second-batch")).cid().clone();
    for row in fixtures()["operations"].as_array().unwrap() {
        let prior = match row[1].as_str() {
            Some("same") => Some(&candidate),
            Some("other") => Some(&conflict),
            _ => None,
        };
        let result = evidence::operation(row[0].as_bool().unwrap(), prior, &candidate);
        let label = match result {
            Operation::Unauthorized => "unauthorized",
            Operation::Duplicate => "duplicate",
            Operation::Conflict => "conflict",
            Operation::NewOperation => "new",
        };
        assert_eq!(label, row[2].as_str().unwrap());
    }
    // These APIs have no display-exclusion parameter. This demonstrates the
    // pure boundary, not an end-to-end append regression against a real store.
    assert_eq!(
        evidence::inventory(true, &candidate, Some(&candidate), true, 0, vec![]),
        Inventory::AbsentAtSnapshot {
            snapshot: candidate
        }
    );
}

#[test]
fn exact_encoded_size_boundary() {
    let mut envelope = ipld(&value("unknown-version"));
    let Ipld::Map(ref mut root) = envelope else {
        unreachable!()
    };
    let Ipld::Map(body) = root.get_mut("body").unwrap() else {
        unreachable!()
    };
    body.insert("future".into(), Ipld::Bytes(vec![0; 65_000]));
    let overhead = atproto_dasl::to_vec(&envelope).unwrap().len() - 65_000;
    for extra in [0, 1] {
        let Ipld::Map(ref mut root) = envelope else {
            unreachable!()
        };
        let Ipld::Map(body) = root.get_mut("body").unwrap() else {
            unreachable!()
        };
        body.insert(
            "future".into(),
            Ipld::Bytes(vec![0; evidence::MAX_RECORD_BYTES - overhead + extra]),
        );
        let raw = atproto_dasl::to_vec(&envelope).unwrap();
        assert_eq!(raw.len(), evidence::MAX_RECORD_BYTES + extra);
        assert_eq!(evidence::decode(&raw).is_ok(), extra == 0);
        assert_eq!(evidence::encode(&envelope).is_ok(), extra == 0);
    }
}
