// REVIEWER TEMPORARY PROBE (scope A). Copied into tests/ only for the run, then removed.
#![cfg(feature = "v2-storage")]
use kan::{
    evidence_recovery_observation::Context,
    evidence_service::unhex,
    evidence_store::bundle::{self, Budget, Error},
};
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn budget() -> Budget {
    Budget {
        items: 10000,
        acquired_bytes: 32 * 1024 * 1024,
        source_bytes: 64 * 1024 * 1024,
        replay_items: 10000,
        replay_scan_bytes: 128 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn pins(v: &Value) -> Context {
    let c = &v["member"]["context"];
    let b = |s: &str| unhex(c[s].as_str().unwrap(), 32).unwrap().try_into().unwrap();
    Context {
        bundle: b("bundle"),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: b("archive"),
        scope: b("scope"),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
#[test]
fn zz_review_scope_a_empty_original_probes() {
    let dir = PathBuf::from(std::env::var("REVIEW_A_DIR").expect("REVIEW_A_DIR"));
    let cases: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap()).unwrap();
    let mut mismatches = 0;
    for v in cases["cases"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let path = dir.join(format!("{name}.sqlite"));
        let before = std::fs::read(&path).unwrap();
        let got = bundle::inspect(&path, pins(v), None, budget());
        let unchanged = std::fs::read(&path).unwrap() == before;
        let expect = v["designExpect"].as_str().unwrap();
        let line = match &got {
            Ok(i) => {
                let losses = i.replay().member().losses();
                format!(
                    "ACCEPT latest={} restored={} losses={} states={:?} complete={}",
                    i.replay().latest().sequence,
                    i.replay().restored(),
                    losses.len(),
                    losses.iter().map(|l| format!("{:?}", l.state)).collect::<Vec<_>>(),
                    i.replay().member().recipe_metadata_complete()
                )
            }
            Err(e) => format!("REFUSE {e:?}"),
        };
        let ok = match (expect, &got, v["expectErr"].as_str()) {
            ("accept", Ok(i), _) => {
                // independent expectation: restored count equals candidates and
                // every empty original is a retained loss
                i.replay().restored() == v["candidates"].as_array().unwrap().len() as u64
                    && i.replay().member().losses().len()
                        >= v["emptyOriginals"].as_array().unwrap().len()
            }
            ("refuse", Err(Error::Invalid(w)), Some(want)) => *w == want,
            ("refuse", Err(_), None) => true,
            _ => false,
        };
        if !ok {
            mismatches += 1;
        }
        println!(
            "PROBE {name}: expect={expect} expectErr={:?} -> {line} source_unchanged={unchanged} {}",
            v["expectErr"].as_str(),
            if ok { "MATCH" } else { "MISMATCH" }
        );
        assert!(unchanged, "{name} changed source");
    }
    assert_eq!(mismatches, 0);
}
