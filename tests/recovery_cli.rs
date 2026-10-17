#![cfg(feature = "v2-storage")]

use kan::evidence_store::{ciphertext_cid, Ledger};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Command, Output},
};

const PAYLOAD: &[u8] = b"synthetic opaque ciphertext\x00";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn fixture(root: &Path) -> (Vec<u8>, Vec<u8>) {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/evidence-v1/vectors.json")).unwrap();
    let raw = |name| {
        let v = vectors["positive"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let h = v["hex"].as_str().unwrap();
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let m = raw("manifest");
    let r = raw("receipt");
    let mut ledger = Ledger::create(root).unwrap();
    ledger.stage(PAYLOAD).unwrap();
    ledger.commit(&m, &r).unwrap();
    (m, r)
}
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(args)
        .current_dir(root)
        .env("PATH", "/no-legacy-kan-here")
        .output()
        .unwrap()
}
fn success(out: Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    serde_json::from_slice(&out.stdout).unwrap()
}
fn failure(out: Output) {
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn cli_reads_and_rebuilds_damaged_derived_data_without_touching_original() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (m, r) = fixture(&root.join("source"));
    let source = root.join("source/archive.sqlite");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("DROP TABLE bindings; UPDATE commits SET cid='wrong', operation=x'00'")
        .unwrap();
    drop(db);
    let original = std::fs::read(&source).unwrap();
    assert!(Ledger::verify_file(&source).is_err());
    let record = success(run(root, &["read-record", "source/archive.sqlite", "1"]));
    assert_eq!(record["manifest"], hex(&m));
    assert_eq!(record["receipt"], hex(&r));
    assert_eq!(record["encoding"], "hex");
    assert_eq!(record["record_format"], "dag-cbor");
    let kan::evidence::Decoded::Known(manifest) = kan::evidence::decode(&m).unwrap() else {
        panic!()
    };
    let kan::evidence::Decoded::Known(receipt) = kan::evidence::decode(&r).unwrap() else {
        panic!()
    };
    assert_eq!(record["manifest_cid"], manifest.cid().to_string());
    assert_eq!(record["receipt_cid"], receipt.cid().to_string());
    assert_eq!(record["cryptographic_admission"], "not-verified");
    assert_eq!(record["historical_completeness"], "not-verified");
    let id = ciphertext_cid(PAYLOAD).to_string();
    let object = success(run(root, &["read-object", "source/archive.sqlite", &id]));
    assert_eq!(object["bytes"], hex(PAYLOAD));
    assert_eq!(object["encoding"], "hex");
    assert_eq!(object["content"], "opaque-ciphertext");
    assert_eq!(object["length"], PAYLOAD.len());
    assert_eq!(object["verification"], "length-and-content-hash");
    let result = success(run(
        root,
        &["recover", "source/archive.sqlite", "rebuilt.sqlite"],
    ));
    assert_eq!(result["objects"], 1);
    assert_eq!(result["through"], 1);
    assert_eq!(result["tip"], manifest.cid().to_string());
    assert_eq!(result["commits"], 1);
    assert_eq!(result["verification"], "structural-closure");
    assert_eq!(result["historical_completeness"], "not-verified");
    assert_eq!(result["promoted"], false);
    assert_eq!(result["independent_backup"], false);
    assert_eq!(
        Ledger::verify_file(&root.join("rebuilt.sqlite"))
            .unwrap()
            .commits,
        1
    );
    let restored = success(run(root, &["read-record", "rebuilt.sqlite", "1"]));
    assert_eq!(restored, record);
    let complete = std::fs::read(root.join("rebuilt.sqlite")).unwrap();
    failure(run(
        root,
        &["recover", "source/archive.sqlite", "rebuilt.sqlite"],
    ));
    failure(run(
        root,
        &["recover", "source/archive.sqlite", "source/archive.sqlite"],
    ));
    assert_eq!(
        std::fs::read(root.join("rebuilt.sqlite")).unwrap(),
        complete
    );
    assert_eq!(std::fs::read(source).unwrap(), original);
    let python = Command::new("python3")
        .arg("scripts/verify_evidence_store.py")
        .arg(root.join("rebuilt.sqlite"))
        .output()
        .unwrap();
    assert!(
        python.status.success(),
        "{}",
        String::from_utf8_lossy(&python.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&python.stdout).unwrap(),
        json!({"objects":1,"commits":1,"bytes":PAYLOAD.len()})
    );
}

#[test]
fn cli_recovery_fails_explicitly_on_bad_raw_data_and_retains_incomplete_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fixture(&root.join("source"));
    let source = root.join("source/archive.sqlite");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("UPDATE commits SET manifest=x'00'")
        .unwrap();
    drop(db);
    let original = std::fs::read(&source).unwrap();
    failure(run(root, &["read-record", "source/archive.sqlite", "1"]));
    let id = ciphertext_cid(PAYLOAD).to_string();
    success(run(root, &["read-object", "source/archive.sqlite", &id]));
    failure(run(
        root,
        &["recover", "source/archive.sqlite", "incomplete.sqlite"],
    ));
    assert!(root.join("incomplete.sqlite").is_file());
    assert!(Ledger::verify_file(&root.join("incomplete.sqlite")).is_err());
    failure(run(root, &["verify", "incomplete.sqlite"]));
    failure(run(
        root,
        &["recover", "source/archive.sqlite", "incomplete.sqlite"],
    ));
    assert_eq!(std::fs::read(source).unwrap(), original);
}

#[test]
fn cli_missing_or_corrupt_evidence_is_never_empty_success() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fixture(&root.join("source"));
    for sequence in ["0", "2", "18446744073709551615"] {
        failure(run(
            root,
            &["read-record", "source/archive.sqlite", sequence],
        ));
    }
    let absent = run(root, &["read-record", "absent.sqlite", "1"]);
    assert!(String::from_utf8_lossy(&absent.stderr).contains("absent.sqlite"));
    failure(absent);
    let missing_parent = run(
        root,
        &[
            "recover",
            "source/archive.sqlite",
            "missing-parent/output.sqlite",
        ],
    );
    assert!(
        String::from_utf8_lossy(&missing_parent.stderr).contains("missing-parent/output.sqlite")
    );
    failure(missing_parent);
    assert!(!root.join("absent.sqlite").exists());
    failure(run(
        root,
        &["read-object", "source/archive.sqlite", "not-a-CID"],
    ));
    let missing = ciphertext_cid(b"absent").to_string();
    failure(run(
        root,
        &["read-object", "source/archive.sqlite", &missing],
    ));
    let source = root.join("source/archive.sqlite");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("UPDATE objects SET bytes=x'00'").unwrap();
    drop(db);
    let id = ciphertext_cid(PAYLOAD).to_string();
    failure(run(root, &["read-object", "source/archive.sqlite", &id]));
}

#[cfg(unix)]
#[test]
fn cli_recovery_rejects_non_utf8_output_before_creating_it() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    fixture(&temp.path().join("source"));
    let destination = temp.path().join(std::ffi::OsString::from_vec(
        b"invalid-\xff.sqlite".to_vec(),
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("recover")
        .arg(temp.path().join("source/archive.sqlite"))
        .arg(&destination)
        .env("PATH", "/no-legacy-kan-here")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("UTF-8 destination path"));
    assert_eq!(output.status.code(), Some(1));
    failure(output);
    assert!(!destination.exists());
}
