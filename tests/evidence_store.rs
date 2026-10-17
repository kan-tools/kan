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

#[test]
fn first_manifest_must_name_earliest_slot_use() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(temp.path()).unwrap();
    ledger.stage(b"repeated").unwrap();
    let (first, receipt) = pair(b"repeated", 0, None, 1);
    ledger.commit(first.bytes(), receipt.bytes()).unwrap();
    let (second, _) = pair(b"repeated", 1, Some(&first), 2);
    let mut body = second.body().clone();
    body.insert("entries".into(), first.body()["entries"].clone());
    let value = Ipld::Map(std::collections::BTreeMap::from([
        ("v".into(), Ipld::Integer(1)),
        ("kind".into(), Ipld::String("manifest".into())),
        ("body".into(), Ipld::Map(body)),
    ]));
    let Decoded::Known(second) = evidence::encode(&value).unwrap() else {
        panic!()
    };
    let mut receipt = golden("receipt");
    receipt["body"]["manifest"] = json!({"$link": second.cid().to_string()});
    receipt["body"]["operation"] = json!({"$bytes": "02".repeat(16)});
    receipt["body"]["position"] = json!(1);
    ledger
        .commit(second.bytes(), record(&receipt).bytes())
        .unwrap();
    ledger.verify().unwrap();
    let backup = temp.path().join("valid.sqlite");
    ledger.backup(&backup).unwrap();
    let python = |path: &Path| {
        Command::new("python3")
            .arg("scripts/verify_evidence_store.py")
            .arg(path)
            .output()
            .unwrap()
    };
    assert!(python(&backup).status.success());
    let db = rusqlite::Connection::open(&backup).unwrap();
    db.execute(
        "UPDATE bindings SET first_manifest=?",
        [second.cid().to_string()],
    )
    .unwrap();
    drop(db);
    assert!(matches!(Ledger::verify_file(&backup), Err(Error::Corrupt(s)) if s == "binding"));
    let result = python(&backup);
    assert!(!result.status.success(), "Python accepted later first use");
    assert!(String::from_utf8_lossy(&result.stderr).contains("binding[2] <= sequence"));
}

#[test]
fn relative_path_worker() {
    if std::env::var_os("KAN_V2_RELATIVE_PATH_WORKER").is_none() {
        return;
    }
    let mut ledger = Ledger::create(Path::new("relative-store")).unwrap();
    ledger.stage(b"relative evidence").unwrap();
    let (m, r) = pair(b"relative evidence", 0, None, 1);
    ledger.commit(m.bytes(), r.bytes()).unwrap();
    let expected = ledger.verify().unwrap();
    assert_eq!(ledger.backup(Path::new("backup.sqlite")).unwrap(), expected);
    assert!(ledger.backup(Path::new("backup.sqlite")).is_err());
    assert_eq!(
        Ledger::verify_file(Path::new("backup.sqlite")).unwrap(),
        expected
    );
}

#[test]
fn bare_relative_create_and_backup_succeed_without_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "relative_path_worker", "--nocapture"])
        .current_dir(temp.path())
        .env("KAN_V2_RELATIVE_PATH_WORKER", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temp.path().join("backup.sqlite").is_file());
}

#[test]
fn cid_shaped_tokens_survive_storage_and_independent_backup_verification() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(temp.path()).unwrap();
    let payload = b"opaque token test";
    let object = ledger.stage(payload).unwrap();
    let token = |size: usize| format!("0001551200{}", "05".repeat(size - 5));
    let mut m = golden("web-writer-linked-state");
    m["body"]["scopeToken"] = json!({"$bytes": token(32)});
    m["body"]["operation"] = json!({"$bytes": token(16)});
    m["body"]["entries"][0] = json!({"slot":{"$bytes":token(32)}, "ciphertext":{"$link":object.to_string()}, "length":payload.len()});
    let manifest = record(&m);
    let mut r = golden("web-issuer-linked-state");
    r["body"]["manifest"] = json!({"$link":manifest.cid().to_string()});
    r["body"]["scopeToken"] = m["body"]["scopeToken"].clone();
    r["body"]["operation"] = m["body"]["operation"].clone();
    ledger.commit(manifest.bytes(), record(&r).bytes()).unwrap();
    let backup = temp.path().join("tokens.sqlite");
    ledger.backup(&backup).unwrap();
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
    let restored = ledger.page(&ledger.snapshot().unwrap(), 0, 1).unwrap();
    assert_eq!(restored[0].manifest.bytes(), manifest.bytes());
}

// Four commits: three uses of one slot, then the same slot in another scope.
fn recovery_fixture(root: &Path) -> (Ledger, Vec<(Record, Record)>) {
    let mut ledger = Ledger::create(root).unwrap();
    ledger.stage(b"recovery payload").unwrap();
    ledger.stage(b"retained staged orphan").unwrap();
    let mut records: Vec<(Record, Record)> = Vec::new();
    for i in 0..4 {
        let cross_scope = i == 3;
        let (m, _) = pair(
            b"recovery payload",
            if cross_scope { 0 } else { i },
            if i == 0 || cross_scope {
                None
            } else {
                Some(&records[(i - 1) as usize].0)
            },
            i as u8,
        );
        let mut body = m.body().clone();
        if i > 0 {
            body.insert("entries".into(), records[0].0.body()["entries"].clone());
        }
        if cross_scope {
            body.insert("scopeToken".into(), Ipld::Bytes(vec![99; 32]));
        }
        let Decoded::Known(m) = evidence::encode(&Ipld::Map(std::collections::BTreeMap::from([
            ("v".into(), Ipld::Integer(1)),
            ("kind".into(), Ipld::String("manifest".into())),
            ("body".into(), Ipld::Map(body)),
        ])))
        .unwrap() else {
            panic!()
        };
        let mut receipt = golden("receipt");
        receipt["body"]["manifest"] = json!({"$link": m.cid().to_string()});
        receipt["body"]["position"] = json!(if cross_scope { 0 } else { i });
        receipt["body"]["operation"] = json!({"$bytes":format!("{i:02x}").repeat(16)});
        if cross_scope {
            receipt["body"]["scopeToken"] = json!({"$bytes":"63".repeat(32)});
        }
        let r = record(&receipt);
        ledger.commit(m.bytes(), r.bytes()).unwrap();
        records.push((m, r));
    }
    (ledger, records)
}

#[test]
fn recovery_ignores_derived_damage_and_preserves_exact_evidence() {
    use kan::evidence_store::RecoveryReader;
    for mutation in [
        "DELETE FROM bindings",
        "DROP TABLE bindings",
        "UPDATE bindings SET length=99, ciphertext='poison', first_manifest='missing'",
        "UPDATE bindings SET first_manifest=(SELECT cid FROM commits WHERE sequence=3) WHERE first_manifest=(SELECT cid FROM commits WHERE sequence=1)",
        "UPDATE bindings SET first_manifest=(SELECT cid FROM commits WHERE sequence=4) WHERE first_manifest=(SELECT cid FROM commits WHERE sequence=1)",
        "UPDATE commits SET cid='wrong-' || sequence, scope=x'01', writer='wrong', operation=CAST(sequence AS BLOB), position=sequence+100, previous='wrong'",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (ledger, records) = recovery_fixture(&temp.path().join("source"));
        let source = temp.path().join("damaged.sqlite");
        let expected = ledger.backup(&source).unwrap();
        let db = rusqlite::Connection::open(&source).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        db.execute_batch(mutation).unwrap();
        drop(db);
        let original = std::fs::read(&source).unwrap();
        assert!(Ledger::verify_file(&source).is_err(), "{mutation}");
        let reader = RecoveryReader::open(&source).unwrap();
        assert!(matches!(reader.record(5), Err(Error::MissingCommit(5))));
        assert!(reader.record(0).is_err());
        assert!(reader.record(u64::MAX).is_err());
        for (i, (m,r)) in records.iter().enumerate() {
            let raw = reader.record(i as u64+1).unwrap();
            assert_eq!(raw.manifest.bytes(), m.bytes());
            assert_eq!(raw.receipt.bytes(), r.bytes());
        }
        let id = kan::evidence_store::ciphertext_cid(b"recovery payload");
        assert_eq!(reader.read_object(&id).unwrap(), b"recovery payload");
        let destination = temp.path().join("rebuilt.sqlite");
        assert_eq!(reader.rebuild(&destination).unwrap(), expected);
        let complete = std::fs::read(&destination).unwrap();
        assert!(reader.rebuild(&destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), complete);
        assert!(reader.rebuild(&source).is_err());
        let rebuilt = RecoveryReader::open(&destination).unwrap();
        for (i, (m,r)) in records.iter().enumerate() {
            let raw = rebuilt.record(i as u64+1).unwrap();
            assert_eq!(raw.manifest.bytes(), m.bytes());
            assert_eq!(raw.receipt.bytes(), r.bytes());
        }
        let orphan = kan::evidence_store::ciphertext_cid(b"retained staged orphan");
        assert_eq!(rebuilt.read_object(&orphan).unwrap(), b"retained staged orphan");
        let output = Command::new("python3").arg("scripts/verify_evidence_store.py").arg(&destination).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let measured: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(measured["commits"], 4);
        assert_eq!(measured["objects"], 2);
        assert_eq!(measured["bytes"], expected.bytes);
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert!(Ledger::verify_file(&source).is_err());
    }
}

#[test]
fn recovery_rejects_raw_damage_without_hiding_intact_records() {
    use kan::evidence_store::RecoveryReader;
    for mutation in [
        "UPDATE commits SET manifest=x'00' WHERE sequence=1",
        "UPDATE commits SET receipt=(SELECT receipt FROM commits WHERE sequence=3) WHERE sequence=1",
        "DELETE FROM commits WHERE sequence=1",
        "UPDATE objects SET bytes=x'0001'",
        "DELETE FROM objects",
        "DROP TABLE objects",
        "PRAGMA ignore_check_constraints=ON; UPDATE commits SET manifest=zeroblob(65537) WHERE sequence=1",
        "PRAGMA ignore_check_constraints=ON; UPDATE objects SET bytes=zeroblob(4194305)",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (ledger, records) = recovery_fixture(&temp.path().join("source"));
        let source = temp.path().join("damaged.sqlite");
        ledger.backup(&source).unwrap();
        let db = rusqlite::Connection::open(&source).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        db.execute_batch(mutation).unwrap();
        drop(db);
        let original = std::fs::read(&source).unwrap();
        let reader = RecoveryReader::open(&source).unwrap();
        let raw = reader.record(2).unwrap();
        assert_eq!(raw.manifest.bytes(), records[1].0.bytes());
        assert_eq!(raw.receipt.bytes(), records[1].1.bytes());
        let destination = temp.path().join("incomplete.sqlite");
        assert!(reader.rebuild(&destination).is_err(), "accepted {mutation}");
        assert!(Ledger::verify_file(&destination).is_err(), "published prefix: {mutation}");
        assert!(RecoveryReader::open(&destination).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }
}

#[test]
fn recovery_snapshot_is_pinned_before_concurrent_appends() {
    use kan::evidence_store::RecoveryReader;
    let temp = tempfile::tempdir().unwrap();
    let (mut ledger, records) = recovery_fixture(&temp.path().join("source"));
    let expected = ledger.verify().unwrap();
    let reader = RecoveryReader::open(&temp.path().join("source/archive.sqlite")).unwrap();
    ledger.stage(b"after pinned snapshot").unwrap();
    let (m, r) = pair(b"after pinned snapshot", 3, Some(&records[2].0), 5);
    ledger.commit(m.bytes(), r.bytes()).unwrap();
    assert!(matches!(reader.record(5), Err(Error::MissingCommit(5))));
    assert_eq!(
        reader.rebuild(&temp.path().join("pinned.sqlite")).unwrap(),
        expected
    );
    let fresh = RecoveryReader::open(&temp.path().join("source/archive.sqlite")).unwrap();
    assert_eq!(fresh.record(5).unwrap().manifest.bytes(), m.bytes());
    assert_eq!(
        fresh.rebuild(&temp.path().join("fresh.sqlite")).unwrap(),
        ledger.verify().unwrap()
    );
}

#[test]
fn recovery_crash_worker() {
    use kan::evidence_store::RecoveryReader;
    let Ok(root) = std::env::var("KAN_V2_RECOVERY_CRASH_ROOT") else {
        return;
    };
    let phase = std::env::var("KAN_V2_RECOVERY_CRASH_PHASE").unwrap();
    let reader = RecoveryReader::open(&Path::new(&root).join("source.sqlite")).unwrap();
    reader
        .rebuild_observed(&Path::new(&root).join("output.sqlite"), &mut |boundary| {
            if format!("{boundary:?}") == phase {
                std::process::exit(92);
            }
        })
        .unwrap();
    panic!("fault boundary was not reached");
}

#[test]
fn recovery_process_crashes_never_publish_a_partial_archive() {
    use kan::evidence_store::RecoveryReader;
    for phase in ["ObjectCopied", "CommitCopied", "Verified", "Committed"] {
        let temp = tempfile::tempdir().unwrap();
        let (mut ledger, _) = recovery_fixture(&temp.path().join("source"));
        // Force page spill beyond SQLite's cache before the injected exit.
        ledger.stage(&vec![41; 3 * 1024 * 1024]).unwrap();
        let source = temp.path().join("source.sqlite");
        let expected = ledger.backup(&source).unwrap();
        let original = std::fs::read(&source).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "recovery_crash_worker", "--nocapture"])
            .env("KAN_V2_RECOVERY_CRASH_ROOT", temp.path())
            .env("KAN_V2_RECOVERY_CRASH_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(92),
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let destination = temp.path().join("output.sqlite");
        if phase == "Committed" {
            assert_eq!(Ledger::verify_file(&destination).unwrap(), expected);
        } else {
            assert!(
                Ledger::verify_file(&destination).is_err(),
                "published partial at {phase}"
            );
        }
        let reader = RecoveryReader::open(&source).unwrap();
        assert!(reader.rebuild(&destination).is_err());
        assert_eq!(
            reader.rebuild(&temp.path().join("retry.sqlite")).unwrap(),
            expected
        );
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }
}

#[test]
fn recovery_rejects_structurally_valid_but_inconsistent_raw_history() {
    use kan::evidence_store::RecoveryReader;
    fn changed(r: &Record, key: &str, value: Ipld) -> Record {
        let mut body = r.body().clone();
        body.insert(key.into(), value);
        let Decoded::Known(r) = evidence::encode(&Ipld::Map(std::collections::BTreeMap::from([
            ("v".into(), Ipld::Integer(1)),
            (
                "kind".into(),
                Ipld::String(
                    if r.kind() == evidence::Kind::Manifest {
                        "manifest"
                    } else {
                        "receipt"
                    }
                    .into(),
                ),
            ),
            ("body".into(), Ipld::Map(body)),
        ])))
        .unwrap() else {
            panic!()
        };
        r
    }
    for rebound in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (ledger, records) = recovery_fixture(&temp.path().join("source"));
        let source = temp.path().join("damaged.sqlite");
        ledger.backup(&source).unwrap();
        let m = if rebound {
            let Ipld::List(mut entries) = records[1].0.body()["entries"].clone() else {
                panic!()
            };
            let Ipld::Map(e) = &mut entries[0] else {
                panic!()
            };
            e.insert(
                "ciphertext".into(),
                Ipld::Link(kan::evidence_store::ciphertext_cid(
                    b"retained staged orphan",
                )),
            );
            e.insert(
                "length".into(),
                Ipld::Integer(b"retained staged orphan".len() as i128),
            );
            changed(&records[1].0, "entries", Ipld::List(entries))
        } else {
            changed(
                &records[1].0,
                "previous",
                Ipld::Link(records[2].0.cid().clone()),
            )
        };
        let r = changed(&records[1].1, "manifest", Ipld::Link(m.cid().clone()));
        let db = rusqlite::Connection::open(&source).unwrap();
        db.execute(
            "UPDATE commits SET manifest=?,receipt=? WHERE sequence=2",
            rusqlite::params![m.bytes(), r.bytes()],
        )
        .unwrap();
        drop(db);
        let reader = RecoveryReader::open(&source).unwrap();
        assert_eq!(reader.record(2).unwrap().manifest.bytes(), m.bytes());
        let output = temp.path().join("incomplete.sqlite");
        assert!(reader.rebuild(&output).is_err());
        assert!(
            RecoveryReader::open(&output).is_err(),
            "published unverified history"
        );
    }
}

#[test]
fn recovery_large_row_worker() {
    use kan::evidence_store::RecoveryReader;
    let Ok(source) = std::env::var("KAN_V2_LARGE_ROW_SOURCE") else {
        return;
    };
    let reader = RecoveryReader::open(Path::new(&source)).unwrap();
    let error = if std::env::var("KAN_V2_LARGE_ROW_KIND").unwrap() == "manifest" {
        reader.record(1).unwrap_err()
    } else {
        reader
            .read_object(&kan::evidence_store::ciphertext_cid(b"recovery payload"))
            .unwrap_err()
    };
    assert!(
        matches!(error, Error::Sql(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::TooBig),
        "{error:?}"
    );
    let output = Path::new(&source).with_file_name("rejected.sqlite");
    let error = reader.rebuild(&output).unwrap_err();
    assert!(
        matches!(error, Error::Sql(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::TooBig),
        "{error:?}"
    );
    assert!(Ledger::verify_file(&output).is_err());
}

#[test]
fn recovery_large_rows_hit_sqlite_limit_before_materialization() {
    for kind in ["manifest", "object"] {
        let temp = tempfile::tempdir().unwrap();
        let (ledger, _) = recovery_fixture(&temp.path().join("source"));
        let source = temp.path().join("damaged.sqlite");
        ledger.backup(&source).unwrap();
        let db = rusqlite::Connection::open(&source).unwrap();
        db.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        if kind == "manifest" {
            db.execute_batch("UPDATE commits SET manifest=zeroblob(100663296) WHERE sequence=1")
                .unwrap();
        } else {
            db.execute(
                "UPDATE objects SET bytes=zeroblob(100663296) WHERE cid=?",
                [kan::evidence_store::ciphertext_cid(b"recovery payload").to_string()],
            )
            .unwrap();
        }
        drop(db);
        // Measure only the fresh worker, not the fixture writer's allocations.
        // The 64 MiB ceiling is deliberately above normal worker overhead and
        // below materializing the poisoned 96 MiB value. Unix resource units vary.
        #[cfg(unix)]
        let out = Command::new("python3")
            .args(["-c", r#"import json,resource,subprocess,sys
p=subprocess.run([sys.argv[1], '--exact', 'recovery_large_row_worker', '--nocapture'], capture_output=True, text=True)
peak=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != 'darwin': peak *= 1024
print(json.dumps({'exit':p.returncode,'peak_bytes':peak,'stdout':p.stdout,'stderr':p.stderr}))
sys.exit(0 if p.returncode == 0 and peak < 64*1024*1024 else 1)
"#])
            .arg(std::env::current_exe().unwrap())
            .env("KAN_V2_LARGE_ROW_SOURCE", &source)
            .env("KAN_V2_LARGE_ROW_KIND", kind)
            .output().unwrap();
        #[cfg(not(unix))]
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "recovery_large_row_worker", "--nocapture"])
            .env("KAN_V2_LARGE_ROW_SOURCE", &source)
            .env("KAN_V2_LARGE_ROW_KIND", kind)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn recovery_rejects_overlapping_sqlite_namespaces_and_existing_sidecars() {
    use kan::evidence_store::RecoveryReader;
    let temp = tempfile::tempdir().unwrap();
    let (ledger, _) = recovery_fixture(&temp.path().join("source"));
    let source = temp.path().join("source.sqlite");
    ledger.backup(&source).unwrap();
    let original = std::fs::read(&source).unwrap();
    let reader = RecoveryReader::open(&source).unwrap();
    for name in [
        "source.sqlite-journal",
        "source.sqlite-wal",
        "source.sqlite-shm",
        "SOURCE.SQLITE-JOURNAL",
    ] {
        let output = temp.path().join(name);
        assert!(
            matches!(reader.rebuild(&output), Err(Error::Invalid(_))),
            "accepted {name}"
        );
        assert!(!output.exists());
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = temp.path().join(format!("output.sqlite{suffix}"));
        std::fs::write(&sidecar, b"unrelated retained data").unwrap();
        assert!(reader.rebuild(&temp.path().join("output.sqlite")).is_err());
        assert!(!temp.path().join("output.sqlite").exists());
        assert_eq!(std::fs::read(&sidecar).unwrap(), b"unrelated retained data");
        std::fs::remove_file(sidecar).unwrap();
    }
    // The output's journal must not be the source database, either.
    let reverse_source = temp.path().join("reverse.sqlite-journal");
    ledger.backup(&reverse_source).unwrap();
    let reverse = RecoveryReader::open(&reverse_source).unwrap();
    assert!(reverse
        .rebuild(&temp.path().join("reverse.sqlite"))
        .is_err());
    assert!(!temp.path().join("reverse.sqlite").exists());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(temp.path(), temp.path().join("alias")).unwrap();
        assert!(reader
            .rebuild(&temp.path().join("alias/source.sqlite-journal"))
            .is_err());
        std::fs::hard_link(&source, temp.path().join("hardlink.sqlite")).unwrap();
        assert!(reader
            .rebuild(&temp.path().join("hardlink.sqlite-journal"))
            .is_err());
        assert!(!temp.path().join("hardlink.sqlite-journal").exists());
        let unicode_source = temp.path().join("caf\u{e9}.sqlite");
        ledger.backup(&unicode_source).unwrap();
        let unicode = RecoveryReader::open(&unicode_source).unwrap();
        if temp.path().join("cafe\u{301}.sqlite").exists() {
            assert!(unicode
                .rebuild(&temp.path().join("cafe\u{301}.sqlite-journal"))
                .is_err());
        }
    }
}

#[test]
fn recovery_length_limit_preserves_maximum_valid_chunks() {
    use kan::evidence_store::RecoveryReader;
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::create(&temp.path().join("source")).unwrap();
    let bytes = vec![17; MAX_CHUNK];
    let id = ledger.stage(&bytes).unwrap();
    let reader = RecoveryReader::open(&temp.path().join("source/archive.sqlite")).unwrap();
    assert_eq!(reader.read_object(&id).unwrap(), bytes);
    let output = temp.path().join("maximum.sqlite");
    assert_eq!(reader.rebuild(&output).unwrap().bytes, MAX_CHUNK as u64);
    assert_eq!(
        RecoveryReader::open(&output)
            .unwrap()
            .read_object(&id)
            .unwrap(),
        bytes
    );
}
