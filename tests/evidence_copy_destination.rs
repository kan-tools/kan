#![cfg(feature = "v2-storage")]
use kan::{
    evidence_copy_plan::Target,
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        attested,
        copied::{Archive, Budget, CopyBoundary},
        copy_upgrade::PlannedCopy,
        Ledger, RecoveryReader, MAX_CHUNK,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
fn identity(n: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[n; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn request(writer: u8, audience: u8, n: u8, previous: Option<String>) -> Vec<u8> {
    let signer = identity(writer);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: signer.did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic opaque payload"),
            },
        },
        &signer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn grant(writer: u8) -> Grant {
    Grant {
        principal: identity(writer).did().to_string(),
        append: true,
        inventory: false,
    }
}
fn fixture(parent: &Path, records: usize, staged: usize) -> PathBuf {
    fixture_historical(parent, records, staged, 7)
}
fn fixture_historical(parent: &Path, records: usize, staged: usize, historical: u8) -> PathBuf {
    let root = parent.join("source");
    let mut s = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        identity(historical),
        vec![grant(6)],
    )
    .unwrap();
    let mut previous = None;
    for n in 0..records {
        let bytes = request(6, historical, n as u8, previous);
        assert!(s
            .dispatch(&bytes, 100 + n as u64)
            .unwrap()
            .reply
            .result
            .is_ok());
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
    }
    drop(s);
    let mut ledger = Ledger::open(&root).unwrap();
    for n in 0..staged {
        ledger.stage(&vec![n as u8; 17 + n]).unwrap();
    }
    drop(ledger);
    root.join("archive.sqlite")
}
fn source(path: &Path) -> PlannedCopy {
    source_historical(path, 7)
}
fn source_historical(path: &Path, historical: u8) -> PlannedCopy {
    PlannedCopy::open(
        path,
        Target {
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
        identity(historical).did().to_string(),
        [9; 32],
    )
    .unwrap()
}
fn binding(source: &PlannedCopy) -> attested::Binding {
    attested::Binding {
        archive: source.plan().archive_id(),
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    }
}
fn small() -> Budget {
    Budget {
        objects: 1,
        records: 1,
        bytes: MAX_CHUNK,
    }
}
fn finish(archive: &mut Archive, source: &PlannedCopy) {
    for n in 0..30 {
        if archive.verify().unwrap().copy.source_copy_complete {
            return;
        }
        let batch = archive
            .copy_batch(source, &identity(8), 1000 + n, small())
            .unwrap();
        assert!(batch.objects_written + batch.records_written > 0);
    }
    panic!("bounded fixture did not finish")
}
fn rows(root: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    let mut q=c.prepare("SELECT manifest,receipt,envelope FROM commits JOIN attestations USING(sequence) ORDER BY sequence").unwrap();
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn bounded_copy_preserves_original_bytes_and_acknowledged_proofs_before_new_admission() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 2, 2);
    let planned = source(&path);
    let before = std::fs::read(&path).unwrap();
    let root = t.path().join("copy");
    let pins = binding(&planned);
    let mut a = Archive::create(&root, &planned, pins.clone()).unwrap();
    assert!(!a.verify().unwrap().copy.source_copy_complete);
    assert!(a
        .admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200)
        .is_err());
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    assert_eq!(
        c.query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "incomplete admission must refuse before staging"
    );
    drop(c);
    let mut acknowledged = Vec::new();
    for n in 0..20 {
        let report = a
            .copy_batch(&planned, &identity(8), 1000 + n, small())
            .unwrap();
        let now = rows(&root);
        assert!(now.starts_with(&acknowledged));
        acknowledged = now;
        drop(a);
        a = Archive::open(&root, pins.clone()).unwrap();
        if report.status.source_copy_complete {
            break;
        }
    }
    assert!(a.verify().unwrap().copy.source_copy_complete);
    assert_eq!(acknowledged.len(), 2);
    // A separate Python CBOR/CID implementation checks the copied artifact,
    // including all staged objects, before any later admission changes it.
    let oracle = std::process::Command::new("python3")
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/.design/tools/copy_source_digest.py"
        ))
        .arg(root.join("archive.sqlite"))
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    assert_eq!(
        String::from_utf8(oracle.stdout).unwrap().trim(),
        service::hex(&planned.plan().source().digest)
    );
    let original = RecoveryReader::open(&path).unwrap();
    for (i, (manifest, receipt, _)) in acknowledged.iter().enumerate() {
        let row = original.record(i as u64 + 1).unwrap();
        assert_eq!(manifest, row.manifest.bytes());
        assert_eq!(receipt, row.receipt.bytes());
    }
    let admitted = a
        .admit(&request(9, 8, 0, None), &identity(8), &grant(9), 300)
        .unwrap();
    assert_eq!(admitted.record.sequence, 3);
    let after = rows(&root);
    assert!(after.starts_with(&acknowledged));
    let resumed = a
        .copy_batch(&planned, &identity(8), 99999, small())
        .unwrap();
    assert!(resumed.status.source_copy_complete);
    assert_eq!(resumed.objects_written + resumed.records_written, 0);
    assert_eq!(rows(&root), after);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let backup = t.path().join("backup.sqlite");
    let report = a.backup(&backup).unwrap();
    assert!(report.copy.source_copy_complete);
    assert_eq!(report.contents.commits, 3);
    assert!(Ledger::verify_file(&backup).is_err());
    assert!(attested::Archive::verify_file(&backup, pins).is_err());
}
#[test]
fn empty_record_history_is_incomplete_until_all_staged_objects_are_copied() {
    for staged in [0, 3] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 0, staged);
        let s = source(&path);
        let root = t.path().join("copy");
        let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
        assert_eq!(a.verify().unwrap().copy.source_copy_complete, staged == 0);
        finish(&mut a, &s);
        let v = a.verify().unwrap();
        assert!(v.copy.source_copy_complete);
        assert_eq!(v.copy.original_objects, staged as u64);
    }
}
#[test]
fn later_admission_can_share_an_original_staged_object_without_changing_membership() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 0);
    let later = request(9, 8, 0, None);
    let mut raw = Ledger::open(path.parent().unwrap()).unwrap();
    raw.stage(&later).unwrap();
    drop(raw);
    let s = source(&path);
    let mut a = Archive::create(&t.path().join("copy"), &s, binding(&s)).unwrap();
    finish(&mut a, &s);
    let before = a.verify().unwrap();
    a.admit(&later, &identity(8), &grant(9), 300).unwrap();
    let after = a.verify().unwrap();
    assert!(after.copy.source_copy_complete);
    assert_eq!(after.copy.original_objects, before.copy.original_objects);
    assert_eq!(after.contents.objects, before.contents.objects);
}
#[test]
fn owner_recipe_signer_and_profile_are_required_before_mutation() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 0);
    let s = source(&path);
    let root = t.path().join("copy");
    let mut wrong = binding(&s);
    wrong.archive[0] ^= 1;
    assert!(Archive::create(&root, &s, wrong).is_err());
    assert!(!root.exists());
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    assert!(a.copy_batch(&s, &identity(7), 1, small()).is_err());
    assert_eq!(a.verify().unwrap().contents.objects, 0);
    let sibling = PlannedCopy::open(
        &path,
        s.plan().target().clone(),
        identity(7).did().to_string(),
        [10; 32],
    )
    .unwrap();
    assert!(a.copy_batch(&sibling, &identity(8), 1, small()).is_err());
    assert!(Archive::resume_initialization(&root, &sibling, binding(&sibling)).is_err());
    assert!(Ledger::open(&root).is_err());
    assert!(attested::Archive::open(&root, binding(&s)).is_err());
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    c.execute(
        "UPDATE upgrade_plan SET envelope=? WHERE singleton=1",
        [sibling.plan().bytes()],
    )
    .unwrap();
    drop(c);
    assert!(a.verify().is_err());
    assert!(Archive::open(&root, binding(&s)).is_err());
}
#[test]
fn incomplete_copy_backup_remains_incomplete_and_resume_rejects_wrong_object_length() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 2, 2);
    let s = source(&path);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    a.copy_batch(&s, &identity(8), 1000, small()).unwrap();
    let backup = t.path().join("partial.sqlite");
    assert!(!a.backup(&backup).unwrap().copy.source_copy_complete);
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    c.execute("UPDATE upgrade_objects SET length=length+1", [])
        .unwrap();
    drop(c);
    assert!(a.copy_batch(&s, &identity(8), 1001, small()).is_err());
    assert!(a
        .admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200)
        .is_err());
}
#[test]
fn copy_death_child() {
    let Ok(phase) = std::env::var("KAN_COPY_DEATH_PHASE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("KAN_COPY_DEATH_ROOT").unwrap());
    let s = source(&root.join("source/archive.sqlite"));
    let mut a = Archive::open(&root.join("copy"), binding(&s)).unwrap();
    a.copy_batch_observed(
        &s,
        &identity(8),
        1000,
        Budget {
            objects: 100,
            records: 100,
            bytes: 8 * MAX_CHUNK,
        },
        &mut |b| {
            if format!("{b:?}") == phase {
                std::process::exit(91);
            }
        },
    )
    .unwrap();
    panic!("unreached death boundary");
}
#[test]
fn every_copy_transaction_boundary_resumes_without_replacing_acknowledged_bytes() {
    for phase in [
        CopyBoundary::ObjectInserted,
        CopyBoundary::InventoryInserted,
        CopyBoundary::ManifestInserted,
        CopyBoundary::ProofSigned,
        CopyBoundary::ProofInserted,
        CopyBoundary::BeforeCommit,
        CopyBoundary::AfterCommit,
    ] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 2, 2);
        let s = source(&path);
        let root = t.path().join("copy");
        drop(Archive::create(&root, &s, binding(&s)).unwrap());
        let before = std::fs::read(&path).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "copy_death_child", "--nocapture"])
            .env("KAN_COPY_DEATH_PHASE", format!("{phase:?}"))
            .env("KAN_COPY_DEATH_ROOT", t.path())
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(91),
            "{phase:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let acknowledged = rows(&root);
        let mut a = Archive::open(&root, binding(&s)).unwrap();
        finish(&mut a, &s);
        assert!(rows(&root).starts_with(&acknowledged));
        assert_eq!(rows(&root).len(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
#[test]
fn concurrent_owner_batches_revalidate_under_the_writer_transaction() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 2, 2);
    let s = source(&path);
    let root = t.path().join("copy");
    let pins = binding(&s);
    drop(Archive::create(&root, &s, pins.clone()).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for n in 0..2 {
        let path = path.clone();
        let root = root.clone();
        let pins = pins.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let s = source(&path);
            let mut a = Archive::open(&root, pins).unwrap();
            barrier.wait();
            a.copy_batch(&s, &identity(8), 1000 + n, small()).unwrap()
        }));
    }
    for worker in workers {
        assert_eq!(worker.join().unwrap().objects_written, 1);
    }
    let mut a = Archive::open(&root, pins).unwrap();
    finish(&mut a, &s);
    assert_eq!(rows(&root).len(), 2);
}
#[test]
fn independent_sqlite_inventory_matches_the_copy_surface_catalog() {
    use std::collections::BTreeSet;
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 0, 0);
    let s = source(&path);
    let root = t.path().join("copy");
    drop(Archive::create(&root, &s, binding(&s)).unwrap());
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    let mut actual = BTreeSet::new();
    for table in ["upgrade_plan", "upgrade_objects"] {
        let mut q = c.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        for column in q.query_map([], |r| r.get::<_, String>(1)).unwrap() {
            actual.insert((format!("evidence-copy-sqlite:{table}"), column.unwrap()));
        }
    }
    let expected = include_str!("fixtures/read-write-surface.tsv")
        .lines()
        .filter_map(|l| {
            let c: Vec<_> = l.split('\t').collect();
            (c.len() > 5 && c[4].starts_with("evidence-copy-sqlite:"))
                .then(|| (c[4].to_owned(), c[5].to_owned()))
        })
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn rebuild_repairs_derived_columns_and_keeps_authoritative_copy_bytes() {
    for complete in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 2, 2);
        let s = source(&path);
        let pins = binding(&s);
        let root = t.path().join("copy");
        let mut a = Archive::create(&root, &s, pins.clone()).unwrap();
        if complete {
            finish(&mut a, &s);
        } else {
            a.copy_batch(&s, &identity(8), 1000, small()).unwrap();
        }
        let expected = a.verify().unwrap().copy;
        let proof_bytes = rows(&root);
        drop(a);
        let db = root.join("archive.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("DELETE FROM bindings; UPDATE commits SET position=position+100;")
            .unwrap();
        drop(c);
        let before = std::fs::read(&db).unwrap();
        let output = t.path().join("rebuilt.sqlite");
        let r = kan::evidence_store::copied::Recovery::open(&db, pins.clone())
            .unwrap()
            .rebuild(&output)
            .unwrap();
        assert_eq!(r.copy, expected);
        assert_eq!(std::fs::read(&db).unwrap(), before);
        let out_root = t.path().join("repaired");
        std::fs::create_dir(&out_root).unwrap();
        std::fs::rename(output, out_root.join("archive.sqlite")).unwrap();
        assert_eq!(rows(&out_root), proof_bytes);
        let mut a = Archive::open(&out_root, pins).unwrap();
        finish(&mut a, &s);
        assert!(rows(&out_root).starts_with(&proof_bytes));
        assert_eq!(a.verify().unwrap().contents.commits, 2);
    }
}
#[test]
fn rebuild_refuses_lost_or_replaced_authoritative_evidence_without_publishing_profile() {
    for sql in [
        "UPDATE attestations SET envelope=x'00' WHERE sequence=1",
        "UPDATE upgrade_plan SET envelope=x'00'",
        "DELETE FROM objects WHERE cid IN (SELECT cid FROM upgrade_objects LIMIT 1)",
        "UPDATE upgrade_objects SET length=length+1",
    ] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 2, 2);
        let s = source(&path);
        let pins = binding(&s);
        let root = t.path().join("copy");
        let mut a = Archive::create(&root, &s, pins.clone()).unwrap();
        finish(&mut a, &s);
        drop(a);
        let db = root.join("archive.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        let original = std::fs::read(&db).unwrap();
        let output = t.path().join("refused.sqlite");
        let result =
            kan::evidence_store::copied::Recovery::open(&db, pins).and_then(|r| r.rebuild(&output));
        assert!(result.is_err(), "{sql}");
        assert_eq!(std::fs::read(&db).unwrap(), original);
        if output.exists() {
            let c = rusqlite::Connection::open(output).unwrap();
            assert_eq!(
                c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}
#[test]
fn initialization_death_child() {
    let Ok(phase) = std::env::var("KAN_COPY_INIT_PHASE") else {
        return;
    };
    let parent = PathBuf::from(std::env::var_os("KAN_COPY_DEATH_ROOT").unwrap());
    let s = source(&parent.join("source/archive.sqlite"));
    Archive::create_observed(&parent.join("copy"), &s, binding(&s), &mut |b| {
        if format!("{b:?}") == phase {
            std::process::exit(92);
        }
    })
    .unwrap();
    panic!("unreached initialization boundary");
}
#[test]
fn interrupted_initialization_requires_explicit_resume_with_retained_recipe() {
    use kan::evidence_store::InitializationBoundary::*;
    for phase in [FileCreated, SchemaWritten, SchemaCommitted, Ready] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 2, 1);
        let s = source(&path);
        let pins = binding(&s);
        let root = t.path().join("copy");
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "initialization_death_child", "--nocapture"])
            .env("KAN_COPY_INIT_PHASE", format!("{phase:?}"))
            .env("KAN_COPY_DEATH_ROOT", t.path())
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(92),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(Archive::create(&root, &s, pins.clone()).is_err());
        let mut wrong = pins.clone();
        wrong.archive[0] ^= 1;
        assert!(Archive::resume_initialization(&root, &s, wrong).is_err());
        let mut a = Archive::resume_initialization(&root, &s, pins).unwrap();
        finish(&mut a, &s);
        assert_eq!(a.verify().unwrap().contents.commits, 2);
    }
}
fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(args)
        .output()
        .unwrap()
}
fn succeeded(output: std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn owner_cli_pins_private_recipe_and_explicit_profile_through_lifecycle() {
    use kan::evidence_service::hex;
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 2, 2);
    let root = t.path().join("copy");
    let plan = t.path().join("recipe.cbor");
    let key = t.path().join("key");
    std::fs::write(&key, [8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let scope = hex(&[1; 32]);
    let issuer = identity(8).did().to_string();
    let old = identity(7).did().to_string();
    let nonce = hex(&[9; 32]);
    let report = succeeded(cli(&[
        "copy-plan",
        path.to_str().unwrap(),
        plan.to_str().unwrap(),
        "--scope",
        &scope,
        "--issuer",
        &issuer,
        "--historical-issuer",
        &old,
        "--nonce",
        &nonce,
    ]));
    let pin = report["archive"].as_str().unwrap();
    assert!(!root.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&plan).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(std::fs::read(&plan).unwrap(), source(&path).plan().bytes());
    let pins = [
        "--copy-profile",
        "--proof-archive",
        pin,
        "--proof-scope",
        &scope,
        "--proof-issuer",
        &issuer,
    ];
    let mut args = vec![
        "copy-batch",
        path.to_str().unwrap(),
        root.to_str().unwrap(),
        "--plan",
        plan.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--objects",
        "1",
        "--records",
        "1",
    ];
    args.extend(pins);
    let first = succeeded(cli(&args));
    assert_eq!(first["copy"]["source_copy_complete"], false);
    assert_eq!(first["activated"], false);
    assert!(!cli(&args).status.success());
    args.push("--resume");
    for _ in 0..10 {
        if succeeded(cli(&args))["copy"]["source_copy_complete"] == true {
            break;
        }
    }
    let db = root.join("archive.sqlite");
    let mut verify = vec!["verify", db.to_str().unwrap()];
    verify.extend(pins);
    assert_eq!(
        succeeded(cli(&verify))["copy"]["source_copy_complete"],
        true
    );
    verify.retain(|s| *s != "--copy-profile");
    assert!(!cli(&verify).status.success());
    for command in ["backup", "recover"] {
        let out = t.path().join(format!("{command}.sqlite"));
        let input = if command == "backup" { &root } else { &db };
        let mut a = vec![command, input.to_str().unwrap(), out.to_str().unwrap()];
        a.extend(pins);
        let r = succeeded(cli(&a));
        assert_eq!(r["copy"]["source_copy_complete"], true);
        assert_eq!(r["independent_backup"], false);
        assert!(
            Archive::verify_file(&out, binding(&source(&path)))
                .unwrap()
                .copy
                .source_copy_complete
        );
    }
}

#[test]
fn owner_recipe_refusals_happen_before_destination_creation() {
    use kan::evidence_service::hex;
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 1);
    let s = source(&path);
    let plan = t.path().join("recipe");
    let key = t.path().join("key");
    std::fs::write(&key, [8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    kan::evidence_store::copy_upgrade::retain_plan(&plan, &s).unwrap();
    assert!(kan::evidence_store::copy_upgrade::retain_plan(&plan, &s).is_err());
    let exact = std::fs::read(&plan).unwrap();
    let pin = hex(&s.plan().archive_id());
    let scope = hex(&[1; 32]);
    let issuer = identity(8).did().to_string();
    let wrong = hex(&[0; 32]);
    for (i, artifact, pin_value, extra) in [
        (0, t.path().join("missing"), pin.as_str(), vec![]),
        (1, plan.clone(), wrong.as_str(), vec![]),
        (
            2,
            plan.clone(),
            pin.as_str(),
            vec!["--objects", "0", "--records", "0"],
        ),
    ] {
        let output = t.path().join(format!("refused-{i}"));
        let mut args = vec![
            "copy-batch",
            path.to_str().unwrap(),
            output.to_str().unwrap(),
            "--plan",
            artifact.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--copy-profile",
            "--proof-archive",
            pin_value,
            "--proof-scope",
            &scope,
            "--proof-issuer",
            &issuer,
        ];
        args.extend(extra);
        assert!(!cli(&args).status.success());
        assert!(!output.exists());
    }
    let output = t.path().join("changed-source");
    drop(s);
    Ledger::open(path.parent().unwrap())
        .unwrap()
        .stage(b"changed pinned source")
        .unwrap();
    assert!(!cli(&[
        "copy-batch",
        path.to_str().unwrap(),
        output.to_str().unwrap(),
        "--plan",
        plan.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--copy-profile",
        "--proof-archive",
        &pin,
        "--proof-scope",
        &scope,
        "--proof-issuer",
        &issuer
    ])
    .status
    .success());
    assert!(!output.exists());
    assert_eq!(std::fs::read(&plan).unwrap(), exact);
}
#[test]
fn byte_budget_never_splits_objects_or_admits_before_complete_source() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 0);
    Ledger::open(path.parent().unwrap())
        .unwrap()
        .stage(&vec![17; MAX_CHUNK])
        .unwrap();
    let s = source(&path);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    for n in 0..8 {
        let b = a
            .copy_batch(
                &s,
                &identity(8),
                1000 + n,
                Budget {
                    objects: 4096,
                    records: 4096,
                    bytes: MAX_CHUNK,
                },
            )
            .unwrap();
        assert!(b.bytes_written <= MAX_CHUNK);
        assert!(b.objects_written + b.records_written > 0);
        if b.status.source_copy_complete {
            break;
        }
        assert!(a
            .admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200)
            .is_err());
    }
    assert!(a.verify().unwrap().copy.source_copy_complete);
    let before = rows(&root);
    for b in [
        Budget {
            objects: 4097,
            records: 1,
            bytes: MAX_CHUNK,
        },
        Budget {
            objects: 1,
            records: 4097,
            bytes: MAX_CHUNK,
        },
        Budget {
            objects: 0,
            records: 0,
            bytes: MAX_CHUNK,
        },
        Budget {
            objects: 1,
            records: 1,
            bytes: MAX_CHUNK - 1,
        },
    ] {
        assert!(a.copy_batch(&s, &identity(8), 1000, b).is_err());
    }
    assert_eq!(rows(&root), before);
}
#[test]
fn admission_rechecks_original_membership_after_staging_under_writer_transaction() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 2);
    let s = source(&path);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    finish(&mut a, &s);
    let proofs = rows(&root);
    let mut changed = false;
    let result=a.admit_observed(&request(9,8,0,None),&identity(8),&grant(9),200,&mut |boundary| {
        if boundary==kan::evidence_store::Boundary::ObjectDurable {
            let c=rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();c.execute("DELETE FROM upgrade_objects WHERE cid=(SELECT cid FROM upgrade_objects ORDER BY cid LIMIT 1)",[]).unwrap();changed=true;
        }
    });
    assert!(changed);
    assert!(result.is_err());
    assert_eq!(rows(&root), proofs);
}

#[test]
fn profile3_rejects_mixed_historical_issuers_with_a_specific_reason() {
    use kan::evidence_attestation::{self as proof, Context, Frontier, Purpose};
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 2, 0);
    let s = source(&path);
    let root = t.path().join("copy");
    let pins = binding(&s);
    let a = Archive::create(&root, &s, pins.clone()).unwrap();
    let ctx = Context {
        archive: pins.archive,
        scope: pins.scope,
        issuer: &pins.issuer,
    };
    let mut frontier = Frontier::default();
    for (i, h) in [7, 10].into_iter().enumerate() {
        let source_root = t.path().join(format!("issuer-{h}"));
        let writer = 20 + i as u8;
        let mut service = Service::new(
            Ledger::create(&source_root).unwrap(),
            [1; 32],
            identity(h),
            vec![grant(writer)],
        )
        .unwrap();
        assert!(service
            .dispatch(&request(writer, h, 0, None), 100)
            .unwrap()
            .reply
            .result
            .is_ok());
        drop(service);
        let source_db = source_root.join("archive.sqlite");
        let r = RecoveryReader::open(&source_db).unwrap().record(1).unwrap();
        let envelope = proof::issue(
            &identity(8),
            &ctx,
            &r.manifest,
            &r.receipt,
            &frontier,
            Purpose::RetainedVerified,
            1000,
        )
        .unwrap();
        let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
        c.execute("ATTACH DATABASE ? AS src", [source_db.to_str().unwrap()])
            .unwrap();
        c.execute_batch("INSERT INTO objects SELECT * FROM src.objects; INSERT INTO upgrade_objects SELECT cid,length(bytes) FROM src.objects; INSERT INTO commits(cid,scope,writer,operation,position,previous,manifest,receipt) SELECT cid,scope,writer,operation,position,previous,manifest,receipt FROM src.commits; INSERT INTO bindings SELECT * FROM src.bindings;").unwrap();
        c.execute(
            "INSERT INTO attestations VALUES(?,?)",
            rusqlite::params![i as i64 + 1, envelope.bytes()],
        )
        .unwrap();
        frontier = envelope.frontier().clone();
    }
    assert_eq!(
        a.verify().unwrap_err().to_string(),
        "corrupt evidence: retained-verified historical issuer differs from copy plan"
    );
}
#[test]
fn profile3_rejects_retained_after_admission_and_admission_inside_original_prefix() {
    use kan::evidence_attestation::{self as proof, Context, Frontier, Purpose};
    for tamper_prefix in [false, true] {
        let t = tempfile::tempdir().unwrap();
        // Admitted-purpose encoding itself requires the receipt's issuer C.
        // Use H=C to isolate the planned-prefix position guard in that case.
        let historical = if tamper_prefix { 8 } else { 7 };
        let path = fixture_historical(t.path(), 1, 0, historical);
        let s = source_historical(&path, historical);
        let root = t.path().join("copy");
        let pins = binding(&s);
        let mut a = Archive::create(&root, &s, pins.clone()).unwrap();
        finish(&mut a, &s);
        let admitted = a
            .admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200)
            .unwrap();
        let raw = rows(&root);
        let ctx = Context {
            archive: pins.archive,
            scope: pins.scope,
            issuer: &pins.issuer,
        };
        let original = RecoveryReader::open(&path).unwrap().record(1).unwrap();
        let first = proof::verify(
            &raw[0].2,
            &ctx,
            &original.manifest,
            &original.receipt,
            &Frontier::default(),
        )
        .unwrap();
        assert_eq!(first.purpose(), Purpose::RetainedVerified);
        let (sequence, envelope, expected) = if tamper_prefix {
            (
                1,
                proof::issue(
                    &identity(8),
                    &ctx,
                    &original.manifest,
                    &original.receipt,
                    &Frontier::default(),
                    Purpose::Admitted,
                    1000,
                )
                .unwrap(),
                "corrupt evidence: admission inside planned retained prefix",
            )
        } else {
            (
                2,
                proof::issue(
                    &identity(8),
                    &ctx,
                    &admitted.record.manifest,
                    &admitted.record.receipt,
                    first.frontier(),
                    Purpose::RetainedVerified,
                    1000,
                )
                .unwrap(),
                "corrupt evidence: retained-verified row after planned prefix",
            )
        };
        let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
        c.execute(
            "UPDATE attestations SET envelope=? WHERE sequence=?",
            rusqlite::params![envelope.bytes(), sequence],
        )
        .unwrap();
        assert_eq!(a.verify().unwrap_err().to_string(), expected);
    }
}

#[test]
fn rebuild_death_child() {
    let Ok(phase) = std::env::var("KAN_COPY_REBUILD_PHASE") else {
        return;
    };
    let parent = PathBuf::from(std::env::var_os("KAN_COPY_DEATH_ROOT").unwrap());
    let s = source(&parent.join("source/archive.sqlite"));
    kan::evidence_store::copied::Recovery::open(&parent.join("copy/archive.sqlite"), binding(&s))
        .unwrap()
        .rebuild_observed(&parent.join("rebuild.sqlite"), &mut |b| {
            if format!("{b:?}") == phase {
                std::process::exit(93);
            }
        })
        .unwrap();
    panic!("unreached rebuild boundary");
}
#[test]
fn rebuild_process_death_publishes_all_copy_authority_or_no_profile() {
    use kan::evidence_store::RecoveryBoundary::*;
    for phase in [ObjectCopied, CommitCopied, Verified, Committed] {
        let t = tempfile::tempdir().unwrap();
        let path = fixture(t.path(), 2, 2);
        let s = source(&path);
        let root = t.path().join("copy");
        let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
        finish(&mut a, &s);
        drop(a);
        let before = std::fs::read(root.join("archive.sqlite")).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rebuild_death_child", "--nocapture"])
            .env("KAN_COPY_REBUILD_PHASE", format!("{phase:?}"))
            .env("KAN_COPY_DEATH_ROOT", t.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(93),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let db = t.path().join("rebuild.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        let version: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        drop(c);
        if phase == Committed {
            assert_eq!(version, 3);
            let v = Archive::verify_file(&db, binding(&s)).unwrap();
            assert!(v.copy.source_copy_complete);
            assert_eq!(v.contents.commits, 2);
        } else {
            assert_eq!(version, 0);
            assert!(Archive::verify_file(&db, binding(&s)).is_err());
        }
        assert_eq!(std::fs::read(root.join("archive.sqlite")).unwrap(), before);
    }
}
#[test]
fn pinned_wal_source_copies_its_original_snapshot_and_later_confirmation_refuses() {
    let t = tempfile::tempdir().unwrap();
    let path = fixture(t.path(), 1, 1);
    let mut writer = Ledger::open(path.parent().unwrap()).unwrap();
    writer.stage(b"retained in WAL before planning").unwrap();
    let s = source(&path);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    a.copy_batch(&s, &identity(8), 1000, small()).unwrap();
    let new_id = writer
        .stage(b"later source payload outside frozen recipe")
        .unwrap();
    finish(&mut a, &s);
    assert!(a.verify().unwrap().copy.source_copy_complete);
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    let found: i64 = c
        .query_row(
            "SELECT count(*) FROM objects WHERE cid=?",
            [new_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(found, 0);
    assert!(PlannedCopy::confirm(&path, s.plan(), &s.plan().archive_id()).is_err());
}

#[test]
fn plan_custody_refuses_sqlite_families_before_opening_or_writing() {
    use kan::evidence_store::copy_upgrade::{read_plan_for_copy, retain_plan};
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 1, 0);
    let source = source(&db);
    let before = std::fs::read(&db).unwrap();
    let root = t.path().join("copy");
    for suffix in ["", "-journal", "-wal", "-shm", "-JOURNAL"] {
        let plan = PathBuf::from(format!("{}{suffix}", db.display()));
        assert!(retain_plan(&plan, &source).is_err(), "accepted {suffix}");
    }
    assert!(!db.with_file_name("archive.sqlite-journal").exists());
    assert_eq!(std::fs::read(&db).unwrap(), before);
    // A pre-existing artifact must also be protected before SQLite gets opened.
    drop(source);
    let source = self::source(&db);
    let bytes = source.plan().bytes().to_vec();
    let pin = source.plan().archive_id();
    drop(source);
    for base in [&db, &root.join("archive.sqlite")] {
        std::fs::create_dir_all(base.parent().unwrap()).unwrap();
        for suffix in ["-journal", "-wal", "-shm", "-JOURNAL"] {
            let path = PathBuf::from(format!("{}{suffix}", base.display()));
            // Source may have retained empty WAL sidecars; do not overwrite them.
            if path.exists() {
                continue;
            }
            std::fs::write(&path, &bytes).unwrap();
            let error = read_plan_for_copy(&path, &db, &root, &pin)
                .unwrap_err()
                .to_string();
            assert!(error.contains("overlaps source SQLite files"), "{error}");
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            std::fs::remove_file(&path).unwrap();
        }
    }
    // Filesystem aliases must not make sidecar paths safe.
    let alias = t.path().join("alias.sqlite");
    std::fs::hard_link(&db, &alias).unwrap();
    let alias_plan = alias.with_file_name("alias.sqlite-journal");
    let source = self::source(&db);
    assert!(retain_plan(&alias_plan, &source)
        .unwrap_err()
        .to_string()
        .contains("aliases source SQLite sidecar"));
    assert!(!alias_plan.exists());
    assert!(read_plan_for_copy(&alias, &db, &root, &pin)
        .unwrap_err()
        .to_string()
        .contains("plan aliases"));
    let good = t.path().join("recipe.cbor");
    retain_plan(&good, &source).unwrap();
    assert_eq!(
        read_plan_for_copy(&good, &db, &root, &pin).unwrap().bytes(),
        bytes
    );
}

#[test]
fn profile3_schema_drift_refuses_open_verify_resume_and_stale_handle_backup() {
    for sql in [
        "CREATE INDEX extra_index ON commits(cid)",
        "CREATE TRIGGER extra_trigger AFTER INSERT ON objects BEGIN SELECT 1; END",
        "CREATE VIEW extra_view AS SELECT cid FROM objects",
        "CREATE TABLE extra_table(x)",
    ] {
        let t = tempfile::tempdir().unwrap();
        let db = fixture(t.path(), 2, 1);
        let source = source(&db);
        let root = t.path().join("copy");
        let archive = Archive::create(&root, &source, binding(&source)).unwrap();
        let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        let expected = "invalid input: unsupported writable archive schema";
        assert_eq!(
            Archive::open(&root, binding(&source))
                .err()
                .unwrap()
                .to_string(),
            expected
        );
        assert_eq!(
            Archive::verify_file(&root.join("archive.sqlite"), binding(&source))
                .unwrap_err()
                .to_string(),
            expected
        );
        assert_eq!(
            Archive::resume_initialization(&root, &source, binding(&source))
                .err()
                .unwrap()
                .to_string(),
            expected
        );
        assert_eq!(archive.verify().unwrap_err().to_string(), expected);
        assert_eq!(
            archive
                .backup(&t.path().join("backup.sqlite"))
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn resume_refuses_self_consistent_foreign_object_prefix_before_advancing() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 1);
    let source = source(&db);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &source, binding(&source)).unwrap();
    let foreign = b"valid hash and length, absent from planned source";
    let cid = kan::evidence_store::ciphertext_cid(foreign).to_string();
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    c.execute(
        "INSERT INTO objects VALUES(?,?)",
        rusqlite::params![cid, foreign],
    )
    .unwrap();
    c.execute(
        "INSERT INTO upgrade_objects VALUES(?,?)",
        rusqlite::params![cid, foreign.len() as i64],
    )
    .unwrap();
    // Local consistency passes: refusal must compare with the exact source.
    assert!(!a.verify().unwrap().copy.source_copy_complete);
    let before = rows(&root);
    assert_eq!(
        a.copy_batch(&source, &identity(8), 1000, small())
            .unwrap_err()
            .to_string(),
        "corrupt evidence: original object inventory differs from source prefix"
    );
    assert_eq!(rows(&root), before);
    assert_eq!(
        c.query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn resume_refuses_valid_foreign_receipt_prefix_before_signing_more_proofs() {
    use kan::evidence_attestation::{self as proof, Context, Frontier, Purpose};
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 0);
    let source = source(&db);
    let root = t.path().join("copy");
    let pins = binding(&source);
    let mut a = Archive::create(&root, &source, pins.clone()).unwrap();
    a.copy_batch(
        &source,
        &identity(8),
        1000,
        Budget {
            objects: 10,
            records: 1,
            bytes: MAX_CHUNK,
        },
    )
    .unwrap();
    let foreign_root = t.path().join("foreign");
    let mut s = Service::new(
        Ledger::create(&foreign_root).unwrap(),
        [1; 32],
        identity(7),
        vec![grant(6)],
    )
    .unwrap();
    assert!(s
        .dispatch(&request(6, 7, 0, None), 999)
        .unwrap()
        .reply
        .result
        .is_ok());
    drop(s);
    let r = RecoveryReader::open(&foreign_root.join("archive.sqlite"))
        .unwrap()
        .record(1)
        .unwrap();
    let ctx = Context {
        archive: pins.archive,
        scope: pins.scope,
        issuer: &pins.issuer,
    };
    let envelope = proof::issue(
        &identity(8),
        &ctx,
        &r.manifest,
        &r.receipt,
        &Frontier::default(),
        Purpose::RetainedVerified,
        1000,
    )
    .unwrap();
    let original = rows(&root);
    assert_eq!(original[0].0, r.manifest.bytes());
    assert_ne!(original[0].1, r.receipt.bytes());
    let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    c.execute(
        "UPDATE commits SET receipt=? WHERE sequence=1",
        [r.receipt.bytes()],
    )
    .unwrap();
    c.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=1",
        [envelope.bytes()],
    )
    .unwrap();
    assert_eq!(a.verify().unwrap().copy.copied_records, 1);
    let before = rows(&root);
    assert_eq!(
        a.copy_batch(&source, &identity(8), 2000, small())
            .unwrap_err()
            .to_string(),
        "corrupt evidence: copied record differs from source"
    );
    assert_eq!(rows(&root), before);
}

#[test]
fn owner_cli_copy_preconditions_refuse_without_creating_output() {
    use kan::evidence_service::hex;
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 1, 0);
    let source = source(&db);
    let plan = t.path().join("plan.cbor");
    kan::evidence_store::copy_upgrade::retain_plan(&plan, &source).unwrap();
    let key = t.path().join("key");
    let wrong_key = t.path().join("wrong-key");
    for (path, n) in [(&key, 8), (&wrong_key, 5)] {
        std::fs::write(path, [n; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let pin = hex(&source.plan().archive_id());
    let scope = hex(&[1; 32]);
    let issuer = identity(8).did().to_string();
    let pins = [
        "--proof-archive",
        &pin,
        "--proof-scope",
        &scope,
        "--proof-issuer",
        &issuer,
    ];
    for case in 0..7 {
        let root = t.path().join(format!("refused-{case}"));
        let selected_key = if case == 2 { &wrong_key } else { &key };
        let mut args = vec![
            "copy-batch",
            db.to_str().unwrap(),
            root.to_str().unwrap(),
            "--plan",
            plan.to_str().unwrap(),
            "--key",
            selected_key.to_str().unwrap(),
        ];
        if case != 0 {
            args.push("--copy-profile");
        }
        if case != 1 {
            args.extend(pins);
        }
        let expected = match case {
            0 => "copy-batch requires --copy-profile and all owner pins",
            1 => "the following required arguments were not provided",
            2 => "copy signer differs from owner issuer",
            3 => {
                args.extend(["--bytes", "4194303"]);
                "invalid input: copy budget"
            }
            4 => {
                args.push("--resume");
                "No such file or directory"
            }
            5 => {
                args = vec!["init", root.to_str().unwrap(), "--copy-profile"];
                args.extend(pins);
                "profile 3 initialization requires copy-batch"
            }
            6 => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&plan, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                #[cfg(not(unix))]
                {
                    continue;
                }
                "plan must be owner-only"
            }
            _ => unreachable!(),
        };
        let output = cli(&args);
        assert!(!output.status.success(), "case {case} accepted");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "case {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root.exists(), "case {case} created output");
    }
    assert_eq!(std::fs::read(&plan).unwrap(), source.plan().bytes());
}

#[test]
fn owner_cli_plan_paths_cannot_be_sqlite_files_or_sidecars() {
    use kan::evidence_service::hex;
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 1, 0);
    let source = source(&db);
    let before = std::fs::read(&db).unwrap();
    let scope = hex(&[1; 32]);
    let issuer = identity(8).did().to_string();
    let historical = identity(7).did().to_string();
    let nonce = hex(&[9; 32]);
    let pin = hex(&source.plan().archive_id());
    let key = t.path().join("key");
    std::fs::write(&key, [8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let journal = db.with_file_name("archive.sqlite-journal");
    for path in [&db, &journal] {
        let o = cli(&[
            "copy-plan",
            db.to_str().unwrap(),
            path.to_str().unwrap(),
            "--scope",
            &scope,
            "--issuer",
            &issuer,
            "--historical-issuer",
            &historical,
            "--nonce",
            &nonce,
        ]);
        assert!(!o.status.success());
        assert!(o.stdout.is_empty());
        assert!(String::from_utf8_lossy(&o.stderr).contains("SQLite"));
    }
    assert!(!journal.exists());
    let root = t.path().join("copy");
    std::fs::create_dir(&root).unwrap();
    let plan = root.join("archive.sqlite-journal");
    kan::evidence_store::copy_upgrade::retain_plan(&plan, &source).unwrap();
    let bytes = std::fs::read(&plan).unwrap();
    let o = cli(&[
        "copy-batch",
        db.to_str().unwrap(),
        root.to_str().unwrap(),
        "--plan",
        plan.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--copy-profile",
        "--proof-archive",
        &pin,
        "--proof-scope",
        &scope,
        "--proof-issuer",
        &issuer,
    ]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("overlaps source SQLite files"));
    assert!(!root.join("archive.sqlite").exists());
    assert_eq!(std::fs::read(&plan).unwrap(), bytes);
    assert_eq!(std::fs::read(&db).unwrap(), before);
}
