#![cfg(feature = "v2-storage")]
//! Reviewer multi-fault probe for a78fa61's diagnostic-precedence decision
//! (temporary; copied into tests/ only while run).
use kan::{evidence_recovery_observation as observation, evidence_service::unhex};
use serde_json::Value;

fn raw(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 65536).unwrap()
}
fn context(c: &Value) -> observation::Context {
    observation::Context {
        bundle: raw(&c["bundle"]["$bytes"]).try_into().unwrap(),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: raw(&c["archive"]["$bytes"]).try_into().unwrap(),
        scope: raw(&c["scope"]["$bytes"]).try_into().unwrap(),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
#[test]
fn review_multifault_both_refuse_labels_recorded() {
    let f: Value = serde_json::from_str(include_str!("../.design/fixtures/recovery-observation-v1.json")).unwrap();
    let ctx = context(&f["context"]);
    let mut chain: Vec<observation::Authenticated> = Vec::new();
    for row in f["positive"].as_array().unwrap() {
        chain.push(observation::authenticate(&raw(&row["envelopeHex"]), &ctx, chain.last()).unwrap());
    }
    let path = std::env::var("REVIEW_MULTIFAULT").expect("REVIEW_MULTIFAULT");
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = String::new();
    for c in cases["cases"].as_array().unwrap() {
        let base = c["base"].as_u64().unwrap() as usize;
        let prev = if base == 0 { None } else { Some(&chain[base - 1]) };
        let r = observation::authenticate(&raw(&c["envelopeHex"]), &ctx, prev);
        let rust = match &r {
            Ok(_) => "ACCEPTED".to_string(),
            Err(kan::evidence::Error::Schema(s)) => s.clone(),
            Err(e) => format!("OTHER:{e:?}"),
        };
        let py = c["python"].as_str().unwrap();
        out.push_str(&format!("{}\tpython={py}\trust={rust}\tsame_label={}\n", c["name"].as_str().unwrap(), py == rust));
        assert!(r.is_err() && py != "ACCEPTED", "both implementations must refuse");
    }
    eprintln!("{out}");
    if let Ok(dir) = std::env::var("REVIEW_OUT") {
        std::fs::write(format!("{dir}/multifault.tsv"), &out).unwrap();
    }
}
