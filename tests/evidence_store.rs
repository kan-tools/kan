#![cfg(feature = "v2-storage")]

use atproto_dasl::Ipld;
use kan::{
    evidence::{self, Decoded, Record},
    evidence_store::{Boundary, Error, Ledger, Snapshot, MAX_CHUNK},
};
use serde_json::{json, Value};
use std::{path::Path, process::Command};

fn ipld(value: &Value) -> Ipld {
    match value {
        Value::Null => Ipld::Null,
        Value::Bool(b) => Ipld::Bool(*b),
        Value::Number(n) => Ipld::Integer(n.as_i64().unwrap() as i128),
        Value::String(s) => Ipld::String(s.clone()),
        Value::Array(a) => Ipld::List(a.iter().map(ipld).collect()),
        Value::Object(o) if o.contains_key("$bytes") => {
            let s = o["$bytes"].as_str().unwrap();
            Ipld::Bytes(
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect(),
            )
        }
        Value::Object(o) if o.contains_key("$link") => {
            Ipld::Link(o["$link"].as_str().unwrap().parse().unwrap())
        }
        Value::Object(o) => Ipld::Map(o.iter().map(|(k, v)| (k.clone(), ipld(v))).collect()),
    }
}
fn golden(name: &str) -> Value {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/evidence-v1/vectors.json")).unwrap();
    vectors["positive"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["value"]
        .clone()
}
fn record(v: &Value) -> Record {
    let Decoded::Known(r) = evidence::encode(&ipld(v)).unwrap() else {
        panic!("known");
    };
    r
}
fn pair(bytes: &[u8], position: u64, previous: Option<&Record>, nonce: u8) -> (Record, Record) {
    let mut m = golden("manifest");
    m["body"]["position"] = json!(position);
    m["body"]["previous"] = previous.map_or(Value::Null, |p| json!({"$link":p.cid().to_string()}));
    m["body"]["operation"] = json!({"$bytes":format!("{nonce:02x}").repeat(16)});
    m["body"]["entries"][0] = json!({"slot":{"$bytes":format!("{nonce:02x}").repeat(32)},"ciphertext":{"$link":kan::evidence_store::ciphertext_cid(bytes).to_string()},"length":bytes.len()});
    let manifest = record(&m);
    let mut r = golden("receipt");
    r["body"]["manifest"] = json!({"$link":manifest.cid().to_string()});
    for key in ["scopeToken", "operation", "position"] {
        r["body"][key] = m["body"][key].clone();
    }
    (manifest, record(&r))
}

#[test]
fn chunks_and_total_archive_exceed_legacy_cap() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let mut ledger = Ledger::create(&root).unwrap();
    assert!(ledger.stage(&[]).is_err());
    assert!(ledger.stage(&vec![0; MAX_CHUNK + 1]).is_err());
    let mut previous = None;
    for i in 0..5 {
        let bytes = vec![i; 3 * 1024 * 1024];
        let id = ledger.stage(&bytes).unwrap();
        assert_eq!(ledger.stage(&bytes).unwrap(), id);
        let (m, r) = pair(&bytes, i as u64, previous.as_ref(), i);
        ledger.commit(m.bytes(), r.bytes()).unwrap();
        assert_eq!(ledger.read_object(&id).unwrap(), bytes);
        // Reachability is checked after EVERY insertion, not just at the end.
        let v = ledger.verify().unwrap();
        assert_eq!(v.commits, i as u64 + 1);
        assert_eq!(v.objects, i as u64 + 1);
        previous = Some(m);
    }
    assert!(ledger.verify().unwrap().bytes > 10 * 1024 * 1024);
}

#[test]
fn retry_conflicts_and_atomic_validation() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(temp.path()).unwrap();
    let (m, r) = pair(b"first", 0, None, 1);
    assert!(matches!(
        ledger.commit(m.bytes(), r.bytes()),
        Err(Error::Missing(_))
    ));
    assert_eq!(ledger.snapshot().unwrap().through, 0);
    ledger.stage(b"first").unwrap();
    let first = ledger.commit(m.bytes(), r.bytes()).unwrap();
    assert!(!first.duplicate);
    let retry = ledger.commit(m.bytes(), r.bytes()).unwrap();
    assert!(retry.duplicate);
    assert_eq!(retry.receipt.bytes(), first.receipt.bytes());
    assert_eq!(retry.sequence, first.sequence);
    let mut delayed: Ipld = atproto_dasl::from_reader(r.bytes()).unwrap();
    let Ipld::Map(envelope) = &mut delayed else {
        panic!()
    };
    let Ipld::Map(body) = envelope.get_mut("body").unwrap() else {
        panic!()
    };
    body.insert("issuedAt".into(), Ipld::Integer(1));
    let Decoded::Known(delayed) = evidence::encode(&delayed).unwrap() else {
        panic!()
    };
    assert_ne!(delayed.bytes(), r.bytes());
    let retry = ledger.commit(m.bytes(), delayed.bytes()).unwrap();
    assert_eq!(retry.receipt.bytes(), first.receipt.bytes());
    let (other, other_receipt) = pair(b"other", 0, None, 1);
    assert!(matches!(
        ledger.commit(other.bytes(), other_receipt.bytes()),
        Err(Error::Conflict("operation reused for different manifest"))
    ));
    let (stale, stale_receipt) = pair(b"first", 0, None, 2);
    assert!(matches!(
        ledger.commit(stale.bytes(), stale_receipt.bytes()),
        Err(Error::Conflict("writer frontier"))
    ));
    ledger.stage(b"other").unwrap();
    let (mut v, _) = pair(b"other", 1, Some(&m), 2);
    let mut raw: Ipld = atproto_dasl::from_reader(v.bytes()).unwrap();
    let Ipld::Map(root) = &mut raw else { panic!() };
    let Ipld::Map(body) = root.get_mut("body").unwrap() else {
        panic!()
    };
    let Ipld::List(entries) = body.get_mut("entries").unwrap() else {
        panic!()
    };
    let Ipld::Map(entry) = &mut entries[0] else {
        panic!()
    };
    entry.insert("slot".into(), Ipld::Bytes(vec![1; 32]));
    let Decoded::Known(changed) = evidence::encode(&raw).unwrap() else {
        panic!()
    };
    v = changed;
    let mut receipt = golden("receipt");
    receipt["body"]["manifest"] = json!({"$link":v.cid().to_string()});
    receipt["body"]["position"] = json!(1);
    receipt["body"]["operation"] = json!({"$bytes":"02".repeat(16)});
    assert!(matches!(
        ledger.commit(v.bytes(), record(&receipt).bytes()),
        Err(Error::Conflict("slot rebound"))
    ));
    assert_eq!(ledger.verify().unwrap().commits, 1);
}

#[test]
fn snapshot_pages_survive_appends_and_reject_unknown_frontiers() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(temp.path()).unwrap();
    let genesis = ledger.snapshot().unwrap();
    ledger.stage(b"data").unwrap();
    let (m, r) = pair(b"data", 0, None, 1);
    ledger.commit(m.bytes(), r.bytes()).unwrap();
    let snapshot = ledger.snapshot().unwrap();
    let (m2, r2) = pair(b"data", 1, Some(&m), 2);
    ledger.commit(m2.bytes(), r2.bytes()).unwrap();
    assert!(ledger.page(&genesis, 0, 1).unwrap().is_empty());
    assert_eq!(ledger.page(&snapshot, 0, 1).unwrap().len(), 1);
    assert!(ledger.page(&snapshot, 1, 1).unwrap().is_empty());
    assert!(ledger
        .page(
            &Snapshot {
                through: 3,
                tip: Some(m.cid().clone())
            },
            0,
            1
        )
        .is_err());
    assert!(ledger.page(&snapshot, 0, 129).is_err());
    assert!(ledger.page(&snapshot, 2, 1).is_err());
}

#[test]
fn concurrent_retry_has_one_commit_and_identical_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(temp.path()).unwrap();
    ledger.stage(b"concurrent").unwrap();
    let (m, r) = pair(b"concurrent", 0, None, 1);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = temp.path().to_path_buf();
            let m = m.clone();
            let r = r.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let mut l = Ledger::open(&path).unwrap();
                b.wait();
                l.commit(m.bytes(), r.bytes()).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.duplicate).count(), 1);
    assert_eq!(results[0].receipt.bytes(), results[1].receipt.bytes());
    assert_eq!(ledger.verify().unwrap().commits, 1);
}

#[test]
fn backup_restore_and_independent_oracle() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let mut ledger = Ledger::create(&source).unwrap();
    let mut previous = None;
    for i in 0..4 {
        let bytes = vec![i; 4096];
        ledger.stage(&bytes).unwrap();
        let (m, r) = pair(&bytes, i as u64, previous.as_ref(), i);
        ledger.commit(m.bytes(), r.bytes()).unwrap();
        previous = Some(m);
    }
    let backup = temp.path().join("backup.sqlite");
    let expected = ledger.backup(&backup).unwrap();
    assert_eq!(expected, ledger.verify().unwrap());
    assert!(ledger.backup(&backup).is_err());
    let output = Command::new("python3")
        .arg("scripts/verify_evidence_store.py")
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let measured: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(measured, json!({"objects":4,"commits":4,"bytes":16384}));
    let restored = temp.path().join("restored");
    std::fs::create_dir(&restored).unwrap();
    std::fs::copy(&backup, restored.join("archive.sqlite")).unwrap();
    let restored = Ledger::open(&restored).unwrap();
    assert_eq!(restored.verify().unwrap(), expected);
    let a = ledger.page(&expected.snapshot, 0, 128).unwrap();
    let b = restored.page(&expected.snapshot, 0, 128).unwrap();
    for (a, b) in a.iter().zip(b.iter()) {
        assert_eq!(a.manifest.bytes(), b.manifest.bytes());
        assert_eq!(a.receipt.bytes(), b.receipt.bytes());
    }
}

#[test]
fn corruption_is_not_an_empty_archive() {
    for mutation in [
        "UPDATE objects SET bytes=x'0001'",
        "UPDATE bindings SET length=99",
        "DELETE FROM bindings",
        "UPDATE commits SET operation=x'00'",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::create(temp.path()).unwrap();
        ledger.stage(b"data").unwrap();
        let (m, r) = pair(b"data", 0, None, 1);
        ledger.commit(m.bytes(), r.bytes()).unwrap();
        let conn = rusqlite::Connection::open(temp.path().join("archive.sqlite")).unwrap();
        conn.execute_batch(mutation).unwrap();
        assert!(ledger.verify().is_err(), "accepted {mutation}");
        assert!(
            Ledger::open(temp.path()).is_err(),
            "opened corrupt store: {mutation}"
        );
        let output = Command::new("python3")
            .arg("scripts/verify_evidence_store.py")
            .arg(temp.path().join("archive.sqlite"))
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "independent verifier accepted {mutation}"
        );
    }
}

#[test]
fn crash_worker() {
    let Ok(root) = std::env::var("KAN_V2_CRASH_ROOT") else {
        return;
    };
    let phase = std::env::var("KAN_V2_CRASH_PHASE").unwrap();
    let mut ledger = Ledger::open(Path::new(&root)).unwrap();
    let mut observe = |boundary: Boundary| {
        if format!("{boundary:?}") == phase {
            std::process::exit(91);
        }
    };
    ledger
        .stage_observed(b"crash evidence", &mut observe)
        .unwrap();
    let (m, r) = pair(b"crash evidence", 0, None, 1);
    ledger
        .commit_observed(m.bytes(), r.bytes(), &mut observe)
        .unwrap();
    panic!("fault boundary was not reached");
}

#[test]
fn abrupt_exit_matrix_recovers_atomic_commits_and_exact_retries() {
    for phase in [
        "ObjectInserted",
        "ObjectDurable",
        "ManifestInserted",
        "BindingsInserted",
        "BeforeCommit",
        "AfterCommit",
    ] {
        let temp = tempfile::tempdir().unwrap();
        drop(Ledger::create(temp.path()).unwrap());
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_worker", "--nocapture"])
            .env("KAN_V2_CRASH_ROOT", temp.path())
            .env("KAN_V2_CRASH_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(91),
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut ledger = Ledger::open(temp.path()).unwrap();
        let v = ledger.verify().unwrap();
        assert_eq!(v.commits, u64::from(phase == "AfterCommit"));
        assert_eq!(v.objects, u64::from(phase != "ObjectInserted"));
        ledger.stage(b"crash evidence").unwrap();
        let (m, r) = pair(b"crash evidence", 0, None, 1);
        let result = ledger.commit(m.bytes(), r.bytes()).unwrap();
        assert_eq!(result.duplicate, phase == "AfterCommit");
        assert_eq!(result.receipt.bytes(), r.bytes());
        assert_eq!(ledger.verify().unwrap().commits, 1);
    }
}

#[test]
fn database_columns_match_independent_surface_catalog() {
    let temp = tempfile::tempdir().unwrap();
    drop(Ledger::create(temp.path()).unwrap());
    let conn = rusqlite::Connection::open(temp.path().join("archive.sqlite")).unwrap();
    let mut actual = std::collections::BTreeSet::new();
    let mut tables = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    for table in tables.query_map([], |r| r.get::<_, String>(0)).unwrap() {
        let table = table.unwrap();
        let mut columns = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        for column in columns.query_map([], |r| r.get::<_, String>(1)).unwrap() {
            actual.insert((format!("evidence-sqlite:{table}"), column.unwrap()));
        }
    }
    let expected = include_str!("fixtures/read-write-surface.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let c: Vec<_> = l.split('\t').collect();
            if c.len() > 5 && c[4].starts_with("evidence-sqlite:") {
                Some((c[4].to_string(), c[5].to_string()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(actual, expected);
}
