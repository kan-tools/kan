use super::*;
use kan::evidence_recovery_replay::Checkpoint;

fn copy_request<'a>(
    source: &'a Path,
    destination: &'a Path,
    expected: &'a Checkpoint,
) -> bundle::BundleCopy<'a> {
    bundle::BundleCopy {
        source,
        destination,
        expected,
        budget: budget(),
        output_bytes: 64 * 1024 * 1024,
    }
}
fn run(
    request: bundle::BundleCopy<'_>,
    physical: bool,
    observe: impl FnMut(bundle::CopyBoundary),
) -> Result<bundle::CopiedBundle, bundle::BundleCopyError> {
    if physical {
        bundle::backup_observed(request, observe)
    } else {
        bundle::rebuild_observed(request, observe)
    }
}
fn oracle(source: &Path, destination: &Path) {
    let output = std::process::Command::new(
        std::env::var_os("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|| "python3".into()),
    )
    .args(["-B", ".design/tools/recovery_copy_oracle.py"])
    .arg(source)
    .arg(destination)
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn check(
    source: &Path,
    destination: &Path,
    pin: &Checkpoint,
    physical: bool,
) -> bundle::CopiedBundle {
    let before = std::fs::read(source).unwrap();
    let result = run(copy_request(source, destination, pin), physical, |_| {}).unwrap();
    assert_eq!(std::fs::read(source).unwrap(), before);
    assert_eq!(
        restoration_row_dump(source),
        restoration_row_dump(destination)
    );
    assert_eq!(result.inspection.replay().latest(), &result.captured);
    oracle(source, destination);
    assert!(
        Ledger::open(destination).is_err(),
        "a bundle copy is never standalone admission"
    );
    result
}

#[test]
fn copies_preserve_all_cells_loss_and_failed_observed_history_for_both_profiles() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_with_staged(dir.path(), profile, true);
        let source = f.root.join("archive.sqlite");
        let path = dir.path().join("bundle.sqlite");
        let observer = identity(10);
        let req = create(&f, &source, &path, &observer);
        let db = rusqlite::Connection::open(&source).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        for (i, bytes) in f.requests.iter().enumerate() {
            let cid = store::ciphertext_cid(bytes).to_string();
            if i == 0 {
                db.execute("DELETE FROM objects WHERE cid=?", [&cid])
                    .unwrap();
            } else {
                db.execute(
                    "UPDATE objects SET bytes=?1 WHERE cid=?2",
                    rusqlite::params![
                        if i == 1 {
                            b"corrupt".as_slice()
                        } else {
                            b"".as_slice()
                        },
                        cid
                    ],
                )
                .unwrap();
            }
        }
        drop(db);
        let created = bundle::create(req).unwrap();
        let initial = created.replay().latest().clone();
        for physical in [false, true] {
            check(
                &path,
                &dir.path().join(format!("loss-{physical}.sqlite")),
                &initial,
                physical,
            );
        }
        let mut current = initial.clone();
        for bytes in &f.requests {
            let cid = store::ciphertext_cid(bytes);
            current = bundle::restore(restoration(&path, &current, &observer, &cid, bytes))
                .unwrap()
                .inspection
                .replay()
                .latest()
                .clone();
        }
        let output = dir.path().join("published.sqlite");
        let req = publication(&path, &current, &observer, &output);
        let cancelled = req.budget.cancelled.clone();
        assert!(bundle::publish_observed(req, |phase| {
            if phase == bundle::PublicationBoundary::IntentReopened {
                cancelled.store(true, Ordering::Relaxed)
            }
        })
        .is_err());
        let pending =
            bundle::inspect(&path, initial.context.clone(), Some(&initial), budget()).unwrap();
        bundle::record_publication_failure(bundle::PublicationFailure {
            path: &path,
            expected: pending.replay().latest(),
            observer: &observer,
            attempt: [42; 16],
            reason: bundle::PublicationFailureReason::Io,
            sampled_at: 501,
            budget: budget(),
            bundle_bytes: 64 * 1024 * 1024,
        })
        .unwrap();
        let mut req = publication(&path, &initial, &observer, &output);
        req.mode = bundle::PublicationMode::Resume;
        let published = bundle::publish(req).unwrap();
        for physical in [false, true] {
            let copy = check(
                &path,
                &dir.path().join(format!("history-{physical}.sqlite")),
                &initial,
                physical,
            );
            assert_eq!(copy.captured, *published.inspection.replay().latest());
            assert_eq!(copy.inspection.replay().attempts()[0].failure_count, 1);
            assert!(copy.inspection.replay().attempts()[0]
                .observed_at_sequence
                .is_some());
        }
    }
}

#[test]
fn copies_reject_foreign_pins_conflicts_aliases_modes_and_budget_exhaustion() {
    for physical in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (_, path, pin) = lost_bundle(dir.path());
        let before = std::fs::read(&path).unwrap();
        let output = dir.path().join("copy.sqlite");
        let mut wrong = pin.clone();
        wrong.statement = store::ciphertext_cid(b"foreign checkpoint");
        assert!(run(copy_request(&path, &output, &wrong), physical, |_| {}).is_err());
        assert!(!output.exists());
        wrong = pin.clone();
        wrong.context.bundle[0] ^= 1;
        assert!(run(copy_request(&path, &output, &wrong), physical, |_| {}).is_err());
        assert!(run(copy_request(&path, &path, &pin), physical, |_| {}).is_err());
        assert!(run(
            copy_request(&path, &dir.path().join("bundle.sqlite-wal"), &pin),
            physical,
            |_| {}
        )
        .is_err());
        for kind in 0..4 {
            let mut req = copy_request(&path, &output, &pin);
            match kind {
                0 => req.budget.items = 1,
                1 => req.budget.acquired_bytes = 1,
                2 => req.budget.duration = Duration::from_nanos(1),
                _ => req.budget.cancelled.store(true, Ordering::Relaxed),
            }
            assert!(run(req, physical, |_| {}).is_err());
            assert!(!output.exists());
        }
        std::fs::write(&output, b"retained conflict").unwrap();
        assert!(run(copy_request(&path, &output, &pin), physical, |_| {}).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"retained conflict");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        edit(&path, "PRAGMA journal_mode=WAL;");
        assert!(run(
            copy_request(&path, &dir.path().join("wal-refused.sqlite"), &pin),
            physical,
            |_| {}
        )
        .is_err());
        assert!(!dir.path().join("wal-refused.sqlite").exists());
    }
}

#[test]
fn copies_hold_one_snapshot_against_late_source_append() {
    for physical in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (f, source, pin) = lost_bundle(dir.path());
        let output = dir.path().join("copy.sqlite");
        let observer = identity(10);
        let cid = store::ciphertext_cid(&f.requests[0]);
        let mut attempted = false;
        let result = run(copy_request(&source, &output, &pin), physical, |phase| {
            if phase == bundle::CopyBoundary::Acquired {
                let error = bundle::restore(restoration(&source, &pin, &observer, &cid, &f.requests[0])).err().expect("source snapshot must block a competing commit");
                assert!(matches!(error, bundle::RestorationError::Uncertain { ref cause, .. }
                    if matches!(**cause, bundle::Error::Sql(rusqlite::Error::SqliteFailure(ref e,_)) if e.code==rusqlite::ErrorCode::DatabaseBusy)), "{error:?}");
                attempted = true;
            }
        }).unwrap();
        assert!(attempted);
        assert_eq!(result.captured, pin);
        oracle(&source, &output);
        let restored =
            bundle::restore(restoration(&source, &pin, &observer, &cid, &f.requests[0])).unwrap();
        assert_eq!(
            restored.inspection.replay().latest().sequence,
            pin.sequence + 1
        );
        assert_eq!(
            bundle::inspect(&output, pin.context.clone(), Some(&pin), budget())
                .unwrap()
                .replay()
                .latest(),
            &pin
        );
    }
}

#[test]
fn copies_preserve_interrupted_artifacts_and_require_current_output_cells() {
    for physical in [false, true] {
        for phase in [
            bundle::CopyBoundary::Reserved,
            bundle::CopyBoundary::Committed,
            bundle::CopyBoundary::Synced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (_, source, pin) = lost_bundle(dir.path());
            let output = dir.path().join("copy.sqlite");
            let req = copy_request(&source, &output, &pin);
            let cancelled = req.budget.cancelled.clone();
            let error = run(req, physical, |p| {
                if p == phase {
                    cancelled.store(true, Ordering::Relaxed)
                }
            })
            .err()
            .unwrap();
            if phase == bundle::CopyBoundary::Reserved {
                assert!(matches!(error, bundle::BundleCopyError::Incomplete { .. }));
            } else {
                assert!(matches!(error, bundle::BundleCopyError::Uncertain { .. }));
            }
            assert!(output.exists());
            let before = std::fs::read(&output).unwrap();
            assert!(run(copy_request(&source, &output, &pin), physical, |_| {}).is_err());
            assert_eq!(std::fs::read(&output).unwrap(), before);
        }
        let dir = tempfile::tempdir().unwrap();
        let (_, source, pin) = lost_bundle(dir.path());
        let output = dir.path().join("changed.sqlite");
        let result = run(copy_request(&source, &output, &pin), physical, |p| {
            if p == bundle::CopyBoundary::Synced {
                edit(&output,"DELETE FROM observations WHERE sequence=(SELECT max(sequence) FROM observations);");
            }
        });
        assert!(matches!(
            result,
            Err(bundle::BundleCopyError::Uncertain { .. })
        ));
        assert!(output.exists());
    }
}

#[test]
fn copies_enforce_output_page_ceiling_before_reporting_success() {
    for physical in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (_, source, pin) = complete_publication_bundle(dir.path(), Profile::Copied);
        let output = dir.path().join("small.sqlite");
        let mut req = copy_request(&source, &output, &pin);
        req.output_bytes = 8 * 4096;
        assert!(run(req, physical, |_| {}).is_err());
        if physical {
            assert!(
                !output.exists(),
                "physical source page count must be checked before reservation"
            );
        } else {
            assert!(std::fs::metadata(&output).unwrap().len() <= 8 * 4096);
        }
    }
}

#[test]
fn logical_copy_actual_commit_failure_is_uncertain_and_retained() {
    let dir = tempfile::tempdir().unwrap();
    let (_, source, pin) = lost_bundle(dir.path());
    let output = dir.path().join("busy.sqlite");
    let mut reader = None;
    let error = bundle::rebuild_observed(copy_request(&source, &output, &pin), |phase| {
        if phase == bundle::CopyBoundary::BeforeCommit {
            let conn = rusqlite::Connection::open_with_flags(
                &output,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            conn.execute_batch("BEGIN;").unwrap();
            let _: i64 = conn
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
                .unwrap();
            reader = Some(conn);
        }
    })
    .err()
    .unwrap();
    assert!(
        matches!(error, bundle::BundleCopyError::Uncertain { ref cause, ref checkpoint, .. }
        if **checkpoint == pin && matches!(**cause, bundle::Error::Sql(rusqlite::Error::SqliteFailure(ref e,_))
            if e.code==rusqlite::ErrorCode::DatabaseBusy)),
        "{error:?}"
    );
    drop(reader);
    assert!(output.exists());
    let db =
        rusqlite::Connection::open_with_flags(&output, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        db.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    check(&source, &dir.path().join("fresh.sqlite"), &pin, false);
}

#[test]
#[ignore = "explicit synthetic bundle copy crash child"]
fn copy_crash_child() {
    let root = PathBuf::from(std::env::var_os("KAN_BUNDLE_COPY_CRASH_ROOT").unwrap());
    let wanted = std::env::var("KAN_BUNDLE_COPY_CRASH_PHASE").unwrap();
    let physical = std::env::var("KAN_BUNDLE_COPY_PHYSICAL").unwrap() == "true";
    let (_, source, pin) = lost_bundle(&root);
    let _ = run(
        copy_request(&source, &root.join("copy.sqlite"), &pin),
        physical,
        |p| {
            if format!("{p:?}") == wanted {
                std::fs::write(root.join("at-copy-boundary"), wanted.as_bytes()).unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        },
    );
    panic!("requested copy boundary not reached");
}

#[test]
fn copy_abrupt_death_retains_honest_outputs_and_source_history() {
    for physical in [false, true] {
        let phases = if physical {
            vec![
                "Acquired",
                "Reserved",
                "BeforeCommit",
                "CopyStep",
                "Committed",
                "Synced",
                "Reopened",
            ]
        } else {
            vec![
                "Acquired",
                "Reserved",
                "RowsInserted",
                "BeforeCommit",
                "Committed",
                "Synced",
                "Reopened",
            ]
        };
        for phase in phases {
            let dir = tempfile::tempdir().unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bundle_copy_tests::copy_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("KAN_BUNDLE_COPY_CRASH_ROOT", dir.path())
                .env("KAN_BUNDLE_COPY_CRASH_PHASE", phase)
                .env("KAN_BUNDLE_COPY_PHYSICAL", physical.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !dir.path().join("at-copy-boundary").exists() {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("copy child exited {status} at {phase}");
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("copy child timeout {phase}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            child.kill().unwrap();
            child.wait().unwrap();
            let source = dir.path().join("bundle.sqlite");
            let output = dir.path().join("copy.sqlite");
            let source_rows = restoration_row_dump(&source);
            if output.exists() {
                // Explicit rollback recovery of this disposable crash fixture.
                let db = rusqlite::Connection::open(&output).unwrap();
                let marker: i64 = db
                    .query_row("PRAGMA application_id", [], |r| r.get(0))
                    .unwrap();
                drop(db);
                if ["Committed", "Synced", "Reopened"].contains(&phase) {
                    assert_eq!(marker, 0x4b4e4231);
                    oracle(&source, &output);
                } else {
                    assert_eq!(marker, 0, "partial output recognized at {phase}");
                }
            } else {
                assert_eq!(phase, "Acquired");
            }
            assert_eq!(restoration_row_dump(&source), source_rows);
        }
    }
}
