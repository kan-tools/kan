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
        .chunks_exact(2)
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
        assert!(
            evidence::decode(&unhex(vector["hex"].as_str().unwrap())).is_err(),
            "accepted {}",
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
    for authorized in [false, true] {
        for covered in [None, Some(&snapshot), Some(&other)] {
            for fully_indexed in [false, true] {
                for unsupported in [0, 2] {
                    for matches in [vec![], vec![matched.clone()]] {
                        let result = evidence::inventory(
                            authorized,
                            &snapshot,
                            covered,
                            fully_indexed,
                            unsupported,
                            matches.clone(),
                        );
                        let complete = fully_indexed && unsupported == 0;
                        let expected = if !authorized {
                            Inventory::AccessLimited
                        } else if covered != Some(&snapshot) {
                            Inventory::Incomplete
                        } else if !matches.is_empty() {
                            Inventory::Present { matches, complete }
                        } else if complete {
                            Inventory::AbsentAtSnapshot {
                                snapshot: snapshot.clone(),
                            }
                        } else {
                            Inventory::Incomplete
                        };
                        assert_eq!(result, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn retry_decisions_do_not_depend_on_view_trust_or_subject_existence() {
    let candidate = record(&value("manifest")).cid().clone();
    let conflict = record(&value("second-batch")).cid().clone();
    for prior in [None, Some(&candidate), Some(&conflict)] {
        assert_eq!(
            evidence::operation(false, prior, &candidate),
            Operation::Unauthorized
        );
    }
    assert_eq!(
        evidence::operation(true, None, &candidate),
        Operation::NewOperation
    );
    assert_eq!(
        evidence::operation(true, Some(&candidate), &candidate),
        Operation::Duplicate
    );
    assert_eq!(
        evidence::operation(true, Some(&conflict), &candidate),
        Operation::Conflict
    );
    // These APIs have no display-exclusion parameter. This demonstrates the
    // pure boundary, not an end-to-end append regression against a real store.
    assert_eq!(
        evidence::inventory(true, &candidate, Some(&candidate), true, 0, vec![]),
        Inventory::AbsentAtSnapshot {
            snapshot: candidate
        }
    );
}
