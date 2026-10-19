#![cfg(feature = "v2-storage")]
use kan::{
    evidence_service::{hex, Command as Operation, Grant, Request, SignedRequest},
    evidence_store::{
        attested::{Archive, Binding, Recovery},
        Ledger, RecoveryReader,
    },
    sign::Identity,
};
use rusqlite::Connection;
use std::{io::Write, path::Path, process::Command};

fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn binding() -> Binding {
    Binding {
        archive: [8; 32],
        scope: [9; 32],
        issuer: identity(7).did().to_string(),
    }
}
fn append(a: &mut Archive, n: u8) {
    let request = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&binding().scope),
            audience: binding().issuer,
            principal: identity(n).did().to_string(),
            expires: None,
            command: Operation::Append {
                id: hex(&[n; 16]),
                position: 0,
                previous: None,
                ciphertext: hex(b"retained payload"),
            },
        },
        &identity(n),
    )
    .unwrap()
    .bytes()
    .unwrap();
    a.admit(
        &request,
        &identity(7),
        &Grant {
            principal: identity(n).did().to_string(),
            append: true,
            inventory: false,
        },
        100 + n as u64,
    )
    .unwrap();
}
fn populate(root: &Path) -> Archive {
    let mut a = Archive::create(root, binding()).unwrap();
    append(&mut a, 5);
    append(&mut a, 6);
    a
}
type Raw = Vec<(i64, Vec<u8>, Vec<u8>, Vec<u8>)>;
fn raw(path: &Path) -> Raw {
    let c = Connection::open(path).unwrap();
    let mut s=c.prepare("SELECT c.sequence,c.manifest,c.receipt,a.envelope FROM commits c JOIN attestations a USING(sequence) ORDER BY c.sequence").unwrap();
    let rows = s
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}
fn source_bytes(path: &Path) -> Vec<Option<Vec<u8>>> {
    [
        path.to_path_buf(),
        Path::new(&format!("{}-wal", path.display())).to_path_buf(),
    ]
    .iter()
    .map(|p| std::fs::read(p).ok())
    .collect()
}

#[test]
fn proof_bytes_survive_backup_rebuild_and_derived_repair() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    let a = populate(&root);
    let db = root.join("archive.sqlite");
    let original = raw(&db);
    let backup = t.path().join("backup.sqlite");
    let v = a.backup(&backup).unwrap();
    assert_eq!(v.commits, 2);
    assert_eq!(
        raw(&backup),
        original,
        "backup must preserve exact evidence and proof bytes"
    );
    assert!(Ledger::verify_file(&backup).is_err());
    assert!(RecoveryReader::open(&backup).is_err());
    drop(a);
    let c = Connection::open(&db).unwrap();
    c.execute("UPDATE commits SET cid='damaged-derived-' || sequence", [])
        .unwrap();
    c.execute("DELETE FROM bindings", []).unwrap();
    drop(c);
    let before = source_bytes(&db);
    let r = Recovery::open(&db, binding()).unwrap();
    let rebuilt = t.path().join("rebuilt.sqlite");
    assert_eq!(r.rebuild(&rebuilt).unwrap(), v);
    drop(r);
    assert_eq!(
        raw(&rebuilt),
        original,
        "rebuild must not mint replacement attestations"
    );
    assert_eq!(
        source_bytes(&db),
        before,
        "raw recovery cannot alter source database/WAL"
    );
    assert_eq!(Archive::verify_file(&rebuilt, binding()).unwrap(), v);
    assert!(
        Archive::verify_file(&db, binding()).is_err(),
        "source derived damage must remain"
    );
}

#[test]
fn recovery_refuses_missing_or_corrupt_proofs_and_payloads() {
    for mutation in [
        "DELETE FROM attestations WHERE sequence=1",
        "INSERT INTO attestations VALUES(3,X'00')",
        "UPDATE attestations SET envelope=X'00' WHERE sequence=1",
        "DELETE FROM objects WHERE cid=(SELECT cid FROM objects LIMIT 1)",
        "UPDATE objects SET bytes=X'00'",
        "UPDATE archive_identity SET archive=zeroblob(32)",
    ] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("source");
        drop(populate(&root));
        let db = root.join("archive.sqlite");
        let c = Connection::open(&db).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        c.execute(mutation, []).unwrap();
        drop(c);
        let before = source_bytes(&db);
        let output = t.path().join("output.sqlite");
        let result = Recovery::open(&db, binding()).and_then(|r| r.rebuild(&output));
        assert!(result.is_err(), "must refuse {mutation}");
        assert!(Archive::verify_file(&db, binding()).is_err());
        assert_eq!(
            before,
            source_bytes(&db),
            "source unchanged after {mutation}"
        );
        if output.exists() {
            assert!(
                Archive::verify_file(&output, binding()).is_err(),
                "no partial success for {mutation}"
            );
        }
    }
}

#[test]
fn owner_binding_profile_and_destination_are_explicit() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    let a = populate(&root);
    let db = root.join("archive.sqlite");
    let before = raw(&db);
    for wrong in [
        Binding {
            archive: [0; 32],
            ..binding()
        },
        Binding {
            scope: [0; 32],
            ..binding()
        },
        Binding {
            issuer: identity(4).did().to_string(),
            ..binding()
        },
    ] {
        assert!(Recovery::open(&db, wrong.clone()).is_err());
        assert!(Archive::resume_initialization(&root, wrong).is_err());
    }
    assert!(a.backup(&db).is_err());
    assert!(Recovery::open(&db, binding())
        .unwrap()
        .rebuild(&db)
        .is_err());
    let occupied = t.path().join("occupied.sqlite");
    std::fs::write(&occupied, b"owner bytes").unwrap();
    assert!(a.backup(&occupied).is_err());
    assert_eq!(std::fs::read(&occupied).unwrap(), b"owner bytes");
    assert_eq!(raw(&db), before);
    let legacy = t.path().join("legacy");
    drop(Ledger::create(&legacy).unwrap());
    assert!(Archive::resume_initialization(&legacy, binding()).is_err());
    assert!(Recovery::open(&legacy.join("archive.sqlite"), binding()).is_err());
    Ledger::open(&legacy).unwrap();
}

#[test]
fn recovery_pins_source_before_later_admission() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    let mut a = populate(&root);
    let db = root.join("archive.sqlite");
    let original = raw(&db);
    let r = Recovery::open(&db, binding()).unwrap();
    append(&mut a, 4);
    let output = t.path().join("pinned.sqlite");
    assert_eq!(r.rebuild(&output).unwrap().commits, 2);
    assert_eq!(raw(&output), original);
    assert_eq!(a.verify().unwrap().through, 3);
}

#[test]
fn backup_success_requires_verifying_the_copied_proof_chain() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    let a = populate(&root);
    let c = Connection::open(root.join("archive.sqlite")).unwrap();
    c.execute(
        "UPDATE attestations SET envelope=X'00' WHERE sequence=1",
        [],
    )
    .unwrap();
    drop(c);
    let output = t.path().join("bad-backup.sqlite");
    assert!(
        a.backup(&output).is_err(),
        "byte-copy completion is not proof verification"
    );
    assert!(output.exists(), "failed output is preserved for diagnosis");
    assert!(Archive::verify_file(&output, binding()).is_err());
}

#[test]
fn lifecycle_crash_child() {
    let Ok(mode) = std::env::var("KAN_PROOF_LIFECYCLE_CHILD") else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("KAN_PROOF_LIFECYCLE_ROOT").unwrap());
    let phase = std::env::var("KAN_PROOF_LIFECYCLE_PHASE").unwrap();
    let crash = |observed: String| {
        if observed == phase {
            std::process::exit(91)
        }
    };
    if mode == "init" {
        Archive::create_observed(&root, binding(), &mut |b| crash(format!("{b:?}"))).unwrap();
    } else {
        let output = root.parent().unwrap().join("output.sqlite");
        Recovery::open(&root.join("archive.sqlite"), binding())
            .unwrap()
            .rebuild_observed(&output, &mut |b| crash(format!("{b:?}")))
            .unwrap();
    }
    panic!("requested crash boundary not reached");
}
fn child(root: &Path, mode: &str, phase: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_crash_child", "--nocapture"])
        .env("KAN_PROOF_LIFECYCLE_CHILD", mode)
        .env("KAN_PROOF_LIFECYCLE_ROOT", root)
        .env("KAN_PROOF_LIFECYCLE_PHASE", phase)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(91),
        "{phase}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn interrupted_initialization_resumes_only_by_explicit_owner_action() {
    for phase in ["FileCreated", "SchemaWritten", "SchemaCommitted", "Ready"] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("source");
        child(&root, "init", phase);
        let mut a = Archive::resume_initialization(&root, binding()).unwrap();
        assert_eq!(a.verify().unwrap().through, 0);
        append(&mut a, 5);
        drop(a);
        assert_eq!(
            Archive::resume_initialization(&root, binding())
                .unwrap()
                .verify()
                .unwrap()
                .through,
            1
        );
    }
}
#[test]
fn rebuild_process_death_never_publishes_partial_profile() {
    for phase in ["ObjectCopied", "CommitCopied", "Verified", "Committed"] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("source");
        drop(populate(&root));
        let db = root.join("archive.sqlite");
        let original = raw(&db);
        let before = source_bytes(&db);
        child(&root, "rebuild", phase);
        let output = t.path().join("output.sqlite");
        let check = Archive::verify_file(&output, binding());
        if phase == "Committed" {
            assert_eq!(check.unwrap().commits, 2);
            assert_eq!(raw(&output), original)
        } else {
            assert!(check.is_err(), "uncommitted {phase}")
        }
        assert_eq!(before, source_bytes(&db));
        let fresh = t.path().join("fresh.sqlite");
        Recovery::open(&db, binding())
            .unwrap()
            .rebuild(&fresh)
            .unwrap();
        assert_eq!(raw(&fresh), original);
    }
}

#[test]
fn owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle() {
    fn run(args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args(args)
            .output()
            .unwrap()
    }
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    let pins = [
        "--proof-archive",
        &hex(&binding().archive),
        "--proof-scope",
        &hex(&binding().scope),
        "--proof-issuer",
        &binding().issuer,
    ];
    let args = [vec!["init", root.to_str().unwrap()], pins.to_vec()].concat();
    let incomplete = run(&[
        "init",
        root.to_str().unwrap(),
        "--proof-archive",
        &hex(&binding().archive),
    ]);
    assert!(!incomplete.status.success());
    assert!(!root.exists(), "pin validation precedes output creation");
    let initialized = run(&args);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&initialized.stdout).unwrap()["profile"],
        2
    );
    let mut a = Archive::open(&root, binding()).unwrap();
    append(&mut a, 5);
    drop(a);
    let db = root.join("archive.sqlite");
    let original = raw(&db);
    let backup = t.path().join("backup.sqlite");
    let copied = run(&[
        vec!["backup", root.to_str().unwrap(), backup.to_str().unwrap()],
        pins.to_vec(),
    ]
    .concat());
    assert!(
        copied.status.success(),
        "{}",
        String::from_utf8_lossy(&copied.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&copied.stdout).unwrap();
    assert_eq!(json["issuer_proofs"], "verified-preserved");
    assert_eq!(json["independent_backup"], false);
    let rebuilt = t.path().join("rebuilt.sqlite");
    let recovered = run(&[
        vec![
            "recover",
            backup.to_str().unwrap(),
            rebuilt.to_str().unwrap(),
        ],
        pins.to_vec(),
    ]
    .concat());
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(json["cryptographic_admission"], "proof-purpose-dependent");
    assert_eq!(json["promoted"], false);
    assert_eq!(raw(&rebuilt), original);
    let verified = run(&[vec!["verify", rebuilt.to_str().unwrap()], pins.to_vec()].concat());
    assert!(verified.status.success());
    let json: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(
        json["verification"],
        "payloads-writer-requests-and-issuer-proofs"
    );
    assert_eq!(json["historical_completeness"], "not-verified");
    assert!(
        !run(&["verify", rebuilt.to_str().unwrap()]).status.success(),
        "legacy CLI must not guess proof profile"
    );
}
