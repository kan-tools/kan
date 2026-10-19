#![cfg(feature = "v2-storage")]
use kan::{
    evidence_attestation::Frontier,
    evidence_copy_plan::Target,
    evidence_recovery_observation::Context,
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        self as store, attested,
        bundle::{self, Budget, Creation, CreationBoundary, CreationError},
        copied,
        copy_upgrade::PlannedCopy,
        inventory::{self, Inventory, Profile},
        Ledger,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn grant() -> Grant {
    Grant {
        principal: identity(6).did().to_string(),
        append: true,
        inventory: true,
    }
}
fn request(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: identity(6).did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic encrypted capture"),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap()
}
struct Fixture {
    root: PathBuf,
    binding: attested::Binding,
    requests: Vec<Vec<u8>>,
    profile: Profile,
}
fn fixture(parent: &Path, profile: Profile) -> Fixture {
    fixture_with_staged(parent, profile, false)
}
fn fixture_with_staged(parent: &Path, profile: Profile, staged: bool) -> Fixture {
    let root = parent.join("archive");
    let mut requests = Vec::new();
    let mut previous = None;
    let binding = if profile == Profile::Admitted {
        let binding = attested::Binding {
            archive: [2; 32],
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        };
        let mut a = attested::Archive::create(&root, binding.clone()).unwrap();
        for n in 0..3 {
            let bytes = request(n, 8, previous);
            let r = a
                .admit(&bytes, &identity(8), &grant(), 100 + n as u64)
                .unwrap();
            previous = Some(r.record.manifest.cid().to_string());
            requests.push(bytes);
        }
        binding
    } else {
        let legacy = parent.join("legacy");
        let mut a = Service::new(
            Ledger::create(&legacy).unwrap(),
            [1; 32],
            identity(7),
            vec![grant()],
        )
        .unwrap();
        for n in 0..3 {
            let bytes = request(n, 7, previous);
            assert!(a
                .dispatch(&bytes, 100 + n as u64)
                .unwrap()
                .reply
                .result
                .is_ok());
            previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
            requests.push(bytes);
        }
        drop(a);
        if staged {
            let db = rusqlite::Connection::open(legacy.join("archive.sqlite")).unwrap();
            db.execute(
                "INSERT INTO objects VALUES(?1,?2)",
                rusqlite::params![
                    store::ciphertext_cid(b"staged original").to_string(),
                    b"staged original".as_slice()
                ],
            )
            .unwrap();
        }
        let source = PlannedCopy::open(
            &legacy.join("archive.sqlite"),
            Target {
                scope: [1; 32],
                issuer: identity(8).did().to_string(),
            },
            identity(7).did().to_string(),
            [9; 32],
        )
        .unwrap();
        let binding = attested::Binding {
            archive: source.plan().archive_id(),
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        };
        let mut a = copied::Archive::create(&root, &source, binding.clone()).unwrap();
        assert!(
            a.copy_batch(
                &source,
                &identity(8),
                1000,
                copied::Budget {
                    objects: 100,
                    records: 100,
                    bytes: 16 * 1024 * 1024
                }
            )
            .unwrap()
            .status
            .source_copy_complete
        );
        binding
    };
    Fixture {
        root,
        binding,
        requests,
        profile,
    }
}
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
fn frontier(f: &Fixture) -> Frontier {
    Inventory::open(
        &f.root.join("archive.sqlite"),
        f.profile,
        f.binding.clone(),
        inventory::Budget {
            items: 100,
            metadata_bytes: 4 * 1024 * 1024,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap()
    .frontier()
    .clone()
}
fn context(f: &Fixture, observer: &Identity) -> Context {
    Context {
        bundle: [31; 32],
        profile: f.profile.number() as u8,
        archive: f.binding.archive,
        scope: f.binding.scope,
        issuer: f.binding.issuer.clone(),
        observer: observer.did().into(),
    }
}
fn create<'a>(f: &Fixture, src: &'a Path, dst: &'a Path, observer: &'a Identity) -> Creation<'a> {
    Creation {
        source: src,
        destination: dst,
        context: context(f, observer),
        frontier: frontier(f),
        observer,
        sampled_at: 500,
        budget: budget(),
        output_bytes: 16 * 1024 * 1024,
    }
}
fn edit(path: &Path, sql: &str) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    c.execute_batch(sql).unwrap();
}
#[test]
fn creation_preserves_physical_originals_and_metadata_for_admitted_complete_and_partial_copies() {
    for kind in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_with_staged(
            dir.path(),
            if kind == 0 {
                Profile::Admitted
            } else {
                Profile::Copied
            },
            true,
        );
        let src = f.root.join("archive.sqlite");
        let dst = dir.path().join("bundle.sqlite");
        let observer = identity(10);
        if kind == 2 {
            edit(
                &src,
                "DELETE FROM attestations WHERE sequence>1; DELETE FROM commits WHERE sequence>1;",
            );
        }
        let selected = frontier(&f);
        let c = rusqlite::Connection::open(&src).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        let id0 = store::ciphertext_cid(&f.requests[0]).to_string();
        c.execute("DELETE FROM objects WHERE cid=?", [&id0])
            .unwrap();
        let id1 = store::ciphertext_cid(&f.requests[1]).to_string();
        c.execute("UPDATE objects SET bytes=x'' WHERE cid=?", [&id1])
            .unwrap();
        if kind == 0 {
            let staged = store::ciphertext_cid(b"staged original").to_string();
            c.execute(
                "INSERT INTO objects VALUES(?1,?2)",
                rusqlite::params![staged, b"staged original".as_slice()],
            )
            .unwrap();
        }
        drop(c);
        let before = std::fs::read(&src).unwrap();
        let result = bundle::create(Creation {
            source: &src,
            destination: &dst,
            context: context(&f, &observer),
            frontier: selected.clone(),
            observer: &observer,
            sampled_at: 500,
            budget: budget(),
            output_bytes: 16 * 1024 * 1024,
        })
        .unwrap();
        assert_eq!(result.replay().member().frontier(), &selected);
        assert_eq!(result.replay().latest().sequence, 2);
        let oracle = std::process::Command::new(
            std::env::var_os("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|| "python3".into()),
        )
        .args(["-B", ".design/tools/recovery_creation_oracle.py"])
        .arg(&dst)
        .output()
        .unwrap();
        assert!(
            oracle.status.success(),
            "{}",
            String::from_utf8_lossy(&oracle.stderr)
        );
        let oracle: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
        assert_eq!(
            oracle["member"],
            service::hex(result.replay().member().commitment())
        );
        assert_eq!(
            oracle["losses"].as_array().unwrap().len(),
            result.replay().member().losses().len()
        );

        assert!(result
            .replay()
            .member()
            .losses()
            .iter()
            .any(|v| v.cid.to_string() == id0));
        assert_eq!(std::fs::read(&src).unwrap(), before);
        let source = rusqlite::Connection::open(&src).unwrap();
        let target = rusqlite::Connection::open(&dst).unwrap();
        for (table, target_table, columns) in [
            ("objects", "member_objects", "cid,bytes"),
            ("commits", "member_records", "sequence,manifest,receipt"),
        ] {
            let read = |conn: &rusqlite::Connection, table: &str| {
                let mut stmt = conn
                    .prepare(&format!("SELECT {columns} FROM {table} ORDER BY 1"))
                    .unwrap();
                let n = stmt.column_count();
                let rows = stmt
                    .query_map([], |r| {
                        (0..n)
                            .map(|i| r.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap();
                rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
            };
            assert_eq!(read(&source, table), read(&target, target_table));
        }
        let reopened = bundle::inspect(
            &dst,
            context(&f, &observer),
            Some(result.replay().latest()),
            budget(),
        )
        .unwrap();
        assert_eq!(reopened.replay().latest(), result.replay().latest());
        assert!(store::Ledger::verify_file(&dst).is_err());
    }
}
#[test]
fn creation_refuses_stale_pins_invalid_physical_types_extra_proofs_and_existing_outputs() {
    for mode in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), Profile::Admitted);
        let src = f.root.join("archive.sqlite");
        let dst = dir.path().join("bundle.sqlite");
        let observer = identity(10);
        let mut request = create(&f, &src, &dst, &observer);
        match mode {
            0 => request.frontier = Frontier::default(),
            1 => request.context.archive = [91; 32],
            2 => request.context.observer = identity(11).did().into(),
            3 => edit(
                &src,
                "UPDATE objects SET bytes='' WHERE cid=(SELECT cid FROM objects LIMIT 1)",
            ),
            4 => edit(
                &src,
                "INSERT INTO attestations SELECT 9,envelope FROM attestations WHERE sequence=1",
            ),
            5 => std::fs::write(&dst, b"owner output must survive").unwrap(),
            6 => request.budget.cancelled.store(true, Ordering::Relaxed),
            7 => request.budget.acquired_bytes = 1,
            _ => unreachable!(),
        }
        let before = std::fs::read(&src).unwrap();
        assert!(bundle::create(request).is_err(), "mode {mode}");
        assert_eq!(std::fs::read(&src).unwrap(), before);
        if mode == 5 {
            assert_eq!(std::fs::read(&dst).unwrap(), b"owner output must survive");
        } else {
            assert!(!dst.exists());
        }
    }
}
#[test]
fn source_derived_columns_do_not_replace_authoritative_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let dst = dir.path().join("bundle.sqlite");
    let observer = identity(10);
    let request = create(&f, &src, &dst, &observer);
    edit(
        &src,
        "UPDATE commits SET writer='broken-derived-cache',scope=x'01'; DELETE FROM bindings;",
    );
    let before = std::fs::read(&src).unwrap();
    let result = bundle::create(request).unwrap();
    assert_eq!(result.replay().member().frontier().through, 3);
    assert!(result.replay().member().losses().is_empty());
    assert_eq!(std::fs::read(&src).unwrap(), before);
}
#[test]
fn precommit_cancellation_retains_unrecognized_artifact_and_postcommit_cancellation_is_uncertain() {
    for after in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), Profile::Admitted);
        let src = f.root.join("archive.sqlite");
        let dst = dir.path().join("bundle.sqlite");
        let observer = identity(10);
        let request = create(&f, &src, &dst, &observer);
        let cancel = request.budget.cancelled.clone();
        let result = bundle::create_observed(request, &mut |point| {
            if point
                == if after {
                    CreationBoundary::AfterCommit
                } else {
                    CreationBoundary::BeforeCommit
                }
            {
                cancel.store(true, Ordering::Relaxed)
            }
        });
        assert!(dst.exists());
        if after {
            match result {
                Err(CreationError::Uncertain { checkpoint, .. }) => {
                    let i =
                        bundle::inspect(&dst, context(&f, &observer), Some(&checkpoint), budget())
                            .unwrap();
                    assert_eq!(i.replay().latest(), &checkpoint);
                }
                _ => panic!("must report uncertain commit"),
            }
        } else {
            assert!(matches!(result, Err(CreationError::Refused(_))));
            assert!(bundle::inspect(&dst, context(&f, &observer), None, budget()).is_err());
        }
    }
}
#[cfg(unix)]
#[test]
fn creation_rejects_all_participant_aliases_before_sqlite_opens() {
    for mode in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), Profile::Admitted);
        let src = f.root.join("archive.sqlite");
        let dst = if mode == 0 {
            f.root.join("archive.sqlite-wal")
        } else {
            dir.path().join("bundle.sqlite")
        };
        let observer = identity(10);
        let request = create(&f, &src, &dst, &observer);
        match mode {
            1 => std::fs::hard_link(&src, &dst).unwrap(),
            2 => std::os::unix::fs::symlink(&src, &dst).unwrap(),
            3 => {
                let wal = f.root.join("archive.sqlite-wal");
                // Read-only inventory may leave an empty WAL participant on
                // Linux. Replace only that verified-empty synthetic fixture.
                if wal.exists() {
                    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
                    std::fs::remove_file(&wal).unwrap();
                }
                std::fs::hard_link(&src, &wal).unwrap();
            }
            _ => {}
        }
        let before = std::fs::read(&src).unwrap();
        assert!(bundle::create(request).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), before);
    }
}

#[test]
#[ignore = "subprocess-only abrupt-death fixture"]
fn creation_crash_child() {
    let root = std::env::var_os("KAN_CREATION_CRASH_ROOT").expect("explicit synthetic root");
    let root = PathBuf::from(root);
    let wanted = std::env::var("KAN_CREATION_CRASH_POINT").unwrap();
    let f = fixture(&root, Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let dst = root.join("bundle.sqlite");
    let observer = identity(10);
    std::fs::write(root.join("source-before"), std::fs::read(&src).unwrap()).unwrap();
    let _ = bundle::create_observed(create(&f, &src, &dst, &observer), &mut |point| {
        if format!("{point:?}") == wanted {
            std::fs::write(root.join("at-boundary"), wanted.as_bytes()).unwrap();
            loop {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });
    panic!("requested boundary not reached")
}
#[test]
fn abrupt_death_never_publishes_a_partial_created_bundle() {
    for point in [
        CreationBoundary::Reserved,
        CreationBoundary::MemberInserted,
        CreationBoundary::HistoryInserted,
        CreationBoundary::MarkersSet,
        CreationBoundary::BeforeCommit,
        CreationBoundary::AfterCommit,
        CreationBoundary::Synced,
        CreationBoundary::Reopened,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "creation_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KAN_CREATION_CRASH_ROOT", dir.path())
            .env("KAN_CREATION_CRASH_POINT", format!("{point:?}"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(10);
        while !dir.path().join("at-boundary").exists() {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "child failed before {point:?}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if std::time::Instant::now() >= end {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("boundary timeout {point:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert_eq!(
            std::fs::read(dir.path().join("archive/archive.sqlite")).unwrap(),
            std::fs::read(dir.path().join("source-before")).unwrap()
        );
        let ctx = Context {
            bundle: [31; 32],
            profile: 2,
            archive: [2; 32],
            scope: [1; 32],
            issuer: identity(8).did().into(),
            observer: identity(10).did().into(),
        };
        let out = dir.path().join("bundle.sqlite");
        assert!(out.exists());
        let inspected = bundle::inspect(&out, ctx, None, budget());
        if matches!(
            point,
            CreationBoundary::AfterCommit | CreationBoundary::Synced | CreationBoundary::Reopened
        ) {
            let i = inspected.unwrap();
            assert_eq!(i.replay().member().frontier().through, 3);
            assert_eq!(i.replay().latest().sequence, 1);
        } else {
            assert!(
                inspected.is_err(),
                "recognized incomplete state at {point:?}"
            );
            // A hot journal may refuse read-only recognition. If SQLite can
            // read a committed header, it must not advertise KNB1 yet.
            if let Ok(db) = rusqlite::Connection::open_with_flags(
                &out,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                if let Ok(app) = db.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0)) {
                    assert_ne!(
                        app, 0x4b4e4231,
                        "recognized incomplete publication at {point:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn output_page_limit_retains_failure_without_truncating_source() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let dst = dir.path().join("bundle.sqlite");
    let observer = identity(10);
    let c = rusqlite::Connection::open(&src).unwrap();
    let bytes = vec![b'x'; 300000];
    c.execute(
        "INSERT INTO objects VALUES(?1,?2)",
        rusqlite::params![store::ciphertext_cid(&bytes).to_string(), bytes],
    )
    .unwrap();
    drop(c);
    let mut req = create(&f, &src, &dst, &observer);
    req.output_bytes = 8 * 4096;
    let before = std::fs::read(&src).unwrap();
    assert!(matches!(
        bundle::create(req),
        Err(CreationError::Refused(_))
    ));
    assert!(dst.exists());
    assert!(std::fs::metadata(&dst).unwrap().len() <= 8 * 4096);
    assert_eq!(std::fs::read(&src).unwrap(), before);
    assert!(bundle::inspect(&dst, context(&f, &observer), None, budget()).is_err());
}
#[test]
fn created_loss_history_uses_exact_maximal_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let dst = dir.path().join("bundle.sqlite");
    let observer = identity(10);
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    let mut previous = Some(
        service::append_manifest(&f.requests[2])
            .unwrap()
            .cid()
            .to_string(),
    );
    for n in 3..35 {
        let bytes = request(n, 8, previous);
        let result = archive
            .admit(&bytes, &identity(8), &grant(), 1000 + n as u64)
            .unwrap();
        previous = Some(result.record.manifest.cid().to_string());
    }
    drop(archive);
    let mut req = create(&f, &src, &dst, &observer);
    req.budget.duration = Duration::from_secs(30);
    edit(&src, "DELETE FROM objects");
    let result = bundle::create(req).unwrap();
    assert_eq!(result.replay().member().losses().len(), 35);
    assert_eq!(result.replay().latest().sequence, 3);
    let oracle = std::process::Command::new(
        std::env::var_os("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|| "python3".into()),
    )
    .args(["-B", ".design/tools/recovery_creation_oracle.py"])
    .arg(&dst)
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
}
#[test]
fn complete_bundle_remains_refused_by_standalone_openers_and_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let root = dir.path().join("retained-bundle");
    std::fs::create_dir(&root).unwrap();
    let dst = root.join("archive.sqlite");
    let observer = identity(10);
    bundle::create(create(&f, &src, &dst, &observer)).unwrap();
    let before = std::fs::read(&dst).unwrap();
    assert!(Ledger::open(&root).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(Ledger::resume_initialization(&root).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(store::RecoveryReader::open(&dst).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(attested::Archive::open(&root, f.binding.clone()).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(copied::Archive::open(&root, f.binding.clone()).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(Inventory::open(
        &dst,
        Profile::Admitted,
        f.binding.clone(),
        inventory::Budget {
            items: 100,
            metadata_bytes: 4 * 1024 * 1024,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false))
        }
    )
    .is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
    assert!(PlannedCopy::open(
        &dst,
        Target {
            scope: f.binding.scope,
            issuer: f.binding.issuer.clone()
        },
        f.binding.issuer,
        [44; 32]
    )
    .is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), before);
}

#[test]
fn creation_keeps_the_selected_snapshot_when_source_appends_during_output_work() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let src = f.root.join("archive.sqlite");
    let dst = dir.path().join("bundle.sqlite");
    let observer = identity(10);
    let selected = frontier(&f);
    let result = bundle::create_observed(create(&f, &src, &dst, &observer), &mut |boundary| {
        if boundary == CreationBoundary::Reserved {
            let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
            let bytes = request(3, 8, selected.manifest.as_ref().map(ToString::to_string));
            archive.admit(&bytes, &identity(8), &grant(), 900).unwrap();
        }
    })
    .unwrap();
    assert_eq!(result.replay().member().frontier(), &selected);
    assert_eq!(frontier(&f).through, 4);
}
