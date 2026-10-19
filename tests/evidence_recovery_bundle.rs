#![cfg(feature = "v2-storage")]
use kan::{
    evidence_recovery_observation::Context,
    evidence_recovery_replay::Checkpoint,
    evidence_service::unhex,
    evidence_store::{
        self as store,
        bundle::{self, Budget, Error},
    },
};
use rusqlite::Connection;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
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
fn cases() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("../.design/fixtures/recovery-replay-v1.json"))
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
fn pins(v: &Value) -> Context {
    let c = &v["member"]["context"];
    let bytes = |s: &str| {
        unhex(c[s].as_str().unwrap(), 32)
            .unwrap()
            .try_into()
            .unwrap()
    };
    Context {
        bundle: bytes("bundle"),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: bytes("archive"),
        scope: bytes("scope"),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
fn checkpoint(v: &Value) -> Option<Checkpoint> {
    (!v["checkpoint"].is_null()).then(|| Checkpoint {
        context: pins(v),
        sequence: v["checkpoint"][0].as_u64().unwrap(),
        statement: v["checkpoint"][1].as_str().unwrap().parse().unwrap(),
    })
}
fn construct(dir: &Path, name: Option<&str>, encoding: &str) {
    let python = std::env::var_os("KAN_TLS_ORACLE_PYTHON").unwrap_or_else(|| "python3".into());
    let mut cmd = Command::new(python);
    cmd.arg(".design/tools/recovery_bundle_files.py")
        .arg(dir)
        .arg("--encoding")
        .arg(encoding);
    if let Some(name) = name {
        cmd.arg("--case").arg(name);
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn fixture() -> (tempfile::TempDir, PathBuf, Value) {
    let dir = tempfile::tempdir().unwrap();
    let name = "profile2-restored-failure-observed";
    construct(dir.path(), Some(name), "UTF-8");
    let path = dir.path().join(format!("{name}.sqlite"));
    let v = cases().into_iter().find(|v| v["name"] == name).unwrap();
    (dir, path, v)
}
fn change(path: &Path, sql: &str) {
    let c = Connection::open(path).unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    c.execute_batch(sql).unwrap();
}
#[test]
fn python_sqlite_histories_match_independent_state_results_and_preserve_source() {
    let dir = tempfile::tempdir().unwrap();
    construct(dir.path(), None, "UTF-8");
    let mut counts = (0, 0);
    for v in cases() {
        let name = v["name"].as_str().unwrap();
        let path = dir.path().join(format!("{name}.sqlite"));
        let original = std::fs::read(&path).unwrap();
        let result = bundle::inspect(&path, pins(&v), checkpoint(&v).as_ref(), budget());
        if v.get("error").is_some() {
            assert!(result.is_err(), "accepted {name}");
            counts.1 += 1;
        } else {
            let r = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                r.replay().latest().statement.to_string(),
                v["expected"]["latestCid"]
            );
            assert_eq!(
                r.replay().restored(),
                v["expected"]["restored"].as_u64().unwrap()
            );
            counts.0 += 1;
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "source rewritten: {name}"
        );
    }
    assert_eq!(counts, (13, 32));
}
#[test]
fn schema_marker_history_identity_and_physical_cell_damage_refuse() {
    let mutations=[
 "PRAGMA application_id=1263940097;",
 "PRAGMA user_version=2;",
 "CREATE TABLE extra(n);",
 "CREATE INDEX extra ON observations(envelope);",
 "CREATE VIEW extra AS SELECT * FROM observations;",
 "CREATE TRIGGER extra AFTER INSERT ON observations BEGIN DELETE FROM restored_objects; END;",
 "DROP TABLE observations;",
 "DELETE FROM observations;",
 "DELETE FROM bundle_identity;",
 "UPDATE bundle_identity SET bundle=zeroblob(32);",
 "UPDATE bundle_identity SET observer=issuer;",
 "UPDATE bundle_identity SET profile=3;",
 "UPDATE bundle_identity SET issuer=issuer||char(0);",
 "UPDATE member_records SET manifest=CAST(manifest AS TEXT) WHERE sequence=1;",
 "UPDATE member_records SET receipt=zeroblob(65537) WHERE sequence=1;",
 "UPDATE member_records SET envelope=zeroblob(16385) WHERE sequence=1;",
 "UPDATE observations SET envelope=CAST(envelope AS TEXT) WHERE sequence=1;",
 "UPDATE observations SET sequence=100 WHERE sequence=(SELECT max(sequence) FROM observations);",
 "UPDATE restored_objects SET bytes=CAST(bytes AS TEXT);",
 "UPDATE restored_objects SET bytes=zeroblob(4194305);",
 "UPDATE restored_objects SET cid=upper(cid);",
 "UPDATE restored_objects SET cid=cid||char(0);",
 "DELETE FROM restored_objects;",
 ];
    for sql in mutations {
        let (_dir, path, v) = fixture();
        change(&path, sql);
        assert!(
            bundle::inspect(&path, pins(&v), None, budget()).is_err(),
            "accepted mutation: {sql}"
        );
    }
}
#[test]
fn utf16_refuses_despite_identical_logical_columns() {
    let dir = tempfile::tempdir().unwrap();
    let v = cases()
        .into_iter()
        .find(|v| v["name"] == "profile2-restored-failure-observed")
        .unwrap();
    construct(dir.path(), Some(v["name"].as_str().unwrap()), "UTF-16le");
    let path = dir.path().join("profile2-restored-failure-observed.sqlite");
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, budget()),
        Err(Error::Invalid("bundle encoding"))
    ));
}
#[test]
fn acquisition_budgets_have_exact_edges_and_replay_has_separate_limits() {
    let (_dir, path, v) = fixture();
    let r = bundle::inspect(&path, pins(&v), None, budget()).unwrap();
    let mut b = budget();
    b.items = r.items();
    b.acquired_bytes = r.acquired_bytes();
    bundle::inspect(&path, pins(&v), None, b.clone()).unwrap();
    b.items -= 1;
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Budget("items"))
    ));
    let mut b = budget();
    b.acquired_bytes = r.acquired_bytes() - 1;
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Budget("acquired bytes"))
    ));
    let mut b = budget();
    b.source_bytes = std::fs::metadata(&path).unwrap().len() - 1;
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Budget("source bytes"))
    ));
    let mut b = budget();
    b.replay_items = 0;
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Replay(_))
    ));
    let mut b = budget();
    b.cancelled = Arc::new(AtomicBool::new(true));
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Cancelled)
    ));
    let mut b = budget();
    b.duration = Duration::ZERO;
    assert!(matches!(
        bundle::inspect(&path, pins(&v), None, b),
        Err(Error::Invalid("duration"))
    ));
}
#[test]
fn restored_bundle_is_still_refused_by_all_standalone_readers() {
    let (_dir, path, v) = fixture();
    bundle::inspect(&path, pins(&v), None, budget()).unwrap();
    let c = pins(&v);
    let binding = store::attested::Binding {
        archive: c.archive,
        scope: c.scope,
        issuer: c.issuer,
    };
    assert!(store::Ledger::verify_file(&path).is_err());
    assert!(store::RecoveryReader::open(&path).is_err());
    assert!(store::attested::Archive::verify_file(&path, binding.clone()).is_err());
    assert!(store::attested::Recovery::open(&path, binding.clone()).is_err());
    assert!(store::copied::Archive::verify_file(&path, binding.clone()).is_err());
    assert!(store::copied::Recovery::open(&path, binding).is_err());
}
#[test]
fn foreign_external_pins_and_checkpoint_refuse() {
    let (_dir, path, v) = fixture();
    let c = pins(&v);
    let mut wrong = c.clone();
    wrong.archive[0] ^= 1;
    assert!(matches!(
        bundle::inspect(&path, wrong, None, budget()),
        Err(Error::Invalid("archive pin"))
    ));
    let r = bundle::inspect(&path, c.clone(), None, budget()).unwrap();
    let mut p = r.replay().latest().clone();
    p.sequence += 1;
    assert!(bundle::inspect(&path, c, Some(&p), budget()).is_err());
}
#[test]
fn busy_source_refuses_with_bounded_wait_and_no_recovery_write() {
    let (_dir, path, v) = fixture();
    let before = std::fs::read(&path).unwrap();
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    let start = Instant::now();
    assert!(bundle::inspect(&path, pins(&v), None, budget()).is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    writer.execute_batch("ROLLBACK;").unwrap();
    drop(writer);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
#[cfg(unix)]
#[test]
fn public_mode_and_symlink_source_refuse_before_sqlite_open() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (_dir, path, v) = fixture();
    let alias = path.with_extension("alias");
    symlink(&path, &alias).unwrap();
    assert!(bundle::inspect(&alias, pins(&v), None, budget()).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(bundle::inspect(&path, pins(&v), None, budget()).is_err());
}

#[cfg(unix)]
#[test]
fn existing_sqlite_sidecar_symlink_or_hardlink_refuses_before_open() {
    use std::os::unix::fs::symlink;
    for suffix in ["-wal", "-shm", "-journal"] {
        let (_dir, path, v) = fixture();
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        symlink(&path, &sidecar).unwrap();
        assert!(bundle::inspect(&path, pins(&v), None, budget()).is_err());
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::hard_link(&path, &sidecar).unwrap();
        assert!(matches!(
            bundle::inspect(&path, pins(&v), None, budget()),
            Err(Error::Invalid("aliased SQLite source files"))
        ));
    }
}
