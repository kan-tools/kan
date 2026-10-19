use super::*;

#[test]
fn observed_retry_distinguishes_recreated_output_from_reused_observation() {
    let dir = tempfile::tempdir().unwrap();
    let (_, path, pin) = complete_publication_bundle(dir.path(), Profile::Admitted);
    let observer = identity(10);
    let output = dir.path().join("output.sqlite");
    let first = bundle::publish(publication(&path, &pin, &observer, &output)).unwrap();
    assert!(first.output_created && !first.duplicate);
    let before = restoration_row_dump(&path);
    // Disposable fixture: simulate explicit removal/loss of this output.
    std::fs::remove_file(&output).unwrap();
    let mut req = publication(&path, &pin, &observer, &output);
    req.mode = bundle::PublicationMode::Resume;
    let recreated = bundle::publish(req).unwrap();
    assert!(recreated.output_created && recreated.duplicate);
    assert_eq!(recreated.observation.bytes(), first.observation.bytes());
    assert_eq!(restoration_row_dump(&path), before);
    publication_oracle(&path, &output);
    let mut req = publication(&path, &pin, &observer, &output);
    req.mode = bundle::PublicationMode::Resume;
    let retried = bundle::publish(req).unwrap();
    assert!(!retried.output_created && retried.duplicate);
    assert_eq!(restoration_row_dump(&path), before);
}

#[test]
fn publication_preserves_another_attempt_appended_during_output_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (_, path, pin) = complete_publication_bundle(dir.path(), Profile::Admitted);
    let observer = identity(10);
    let output = dir.path().join("output.sqlite");
    let other = dir.path().join("other.sqlite");
    let initial_rows = restoration_row_dump(&path);
    let mut nested = None;
    let outer = bundle::publish_observed(publication(&path, &pin, &observer, &output), |phase| {
        if phase == bundle::PublicationBoundary::OutputVerified {
            let current =
                bundle::inspect(&path, pin.context.clone(), Some(&pin), budget()).unwrap();
            let mut req = publication(&path, current.replay().latest(), &observer, &other);
            req.attempt = [43; 16];
            nested = Some(bundle::publish(req).unwrap());
        }
    })
    .unwrap();
    let nested = nested.expect("interleaved publication ran");
    let replay = outer.inspection.replay();
    assert_eq!(replay.latest().sequence, pin.sequence + 4);
    assert_eq!(replay.attempts().len(), 2);
    let one = replay.attempts().iter().find(|a| a.id == [42; 16]).unwrap();
    let two = replay.attempts().iter().find(|a| a.id == [43; 16]).unwrap();
    assert_eq!(one.observed_at_sequence, Some(pin.sequence + 4));
    assert_eq!(two.observed_at_sequence, Some(pin.sequence + 3));
    let rows = restoration_row_dump(&path);
    for original in initial_rows {
        assert!(rows.contains(&original), "original row lost");
    }
    let c =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let bytes: Vec<u8> = c
        .query_row(
            "SELECT envelope FROM observations WHERE sequence=?",
            [pin.sequence as i64 + 3],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes, nested.observation.bytes());
    drop(c);
    publication_oracle(&path, &output);
}

#[test]
fn failure_event_real_commit_busy_is_uncertain_and_stale_pin_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_, path, pin) = complete_publication_bundle(dir.path(), Profile::Admitted);
    let observer = identity(10);
    let output = dir.path().join("output.sqlite");
    let req = publication(&path, &pin, &observer, &output);
    let cancelled = req.budget.cancelled.clone();
    assert!(bundle::publish_observed(req, |phase| {
        if phase == bundle::PublicationBoundary::IntentReopened {
            cancelled.store(true, Ordering::Relaxed);
        }
    })
    .is_err());
    let current = bundle::inspect(&path, pin.context.clone(), Some(&pin), budget()).unwrap();
    let head = current.replay().latest().clone();
    let before = restoration_row_dump(&path);
    let fail = |expected| {
        bundle::record_publication_failure(bundle::PublicationFailure {
            path: &path,
            expected,
            observer: &observer,
            attempt: [42; 16],
            reason: bundle::PublicationFailureReason::Verification,
            sampled_at: 400,
            budget: budget(),
            bundle_bytes: 64 * 1024 * 1024,
        })
    };
    assert!(matches!(
        fail(&pin),
        Err(bundle::PublicationFailureError::Refused(
            bundle::Error::Invalid("stale failure checkpoint")
        ))
    ));
    assert_eq!(restoration_row_dump(&path), before);
    let held =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    held.execute_batch("BEGIN;").unwrap();
    let _: i64 = held
        .query_row("SELECT count(*) FROM observations", [], |r| r.get(0))
        .unwrap();
    let error = fail(&head)
        .err()
        .expect("shared reader must block actual COMMIT");
    assert!(
        matches!(&error,bundle::PublicationFailureError::Uncertain {checkpoint,cause,..}
        if checkpoint.sequence==head.sequence+1 && matches!(**cause,bundle::Error::Sql(rusqlite::Error::SqliteFailure(ref e,_)) if e.code==rusqlite::ErrorCode::DatabaseBusy)),
        "{error:?}"
    );
    drop(held);
    assert_eq!(restoration_row_dump(&path), before);
    let retry = fail(&head).unwrap();
    assert_eq!(
        retry.inspection.replay().latest().sequence,
        head.sequence + 1
    );
    assert_eq!(retry.inspection.replay().attempts()[0].failure_count, 1);
}

#[test]
fn new_publication_with_stale_pin_and_fresh_destination_refuses_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (_, path, pin) = complete_publication_bundle(dir.path(), Profile::Admitted);
    let observer = identity(10);
    let output = dir.path().join("output.sqlite");
    bundle::publish(publication(&path, &pin, &observer, &output)).unwrap();
    let before = std::fs::read(&path).unwrap();
    let fresh = dir.path().join("fresh.sqlite");
    let mut req = publication(&path, &pin, &observer, &fresh);
    req.attempt = [43; 16];
    assert!(matches!(
        bundle::publish(req),
        Err(bundle::PublicationError::Refused(bundle::Error::Invalid(
            "stale publication checkpoint"
        )))
    ));
    assert!(!fresh.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn publication_uses_restored_bytes_over_corrupt_present_originals_in_both_profiles() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture_with_staged(dir.path(), profile, profile == Profile::Copied);
        let source = f.root.join("archive.sqlite");
        let good = if profile == Profile::Admitted {
            f.requests[1].clone()
        } else {
            b"staged original".to_vec()
        };
        let cid = store::ciphertext_cid(&good);
        let c = rusqlite::Connection::open(&source).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        assert_eq!(
            c.execute(
                "UPDATE objects SET bytes=? WHERE cid=?",
                rusqlite::params![b"corrupt".as_slice(), cid.to_string()]
            )
            .unwrap(),
            1
        );
        drop(c);
        let path = dir.path().join("bundle.sqlite");
        let observer = identity(10);
        let created = bundle::create(create(&f, &source, &path, &observer)).unwrap();
        let restored = bundle::restore(restoration(
            &path,
            created.replay().latest(),
            &observer,
            &cid,
            &good,
        ))
        .unwrap();
        let output = dir.path().join("output.sqlite");
        bundle::publish(publication(
            &path,
            restored.inspection.replay().latest(),
            &observer,
            &output,
        ))
        .unwrap();
        let c = rusqlite::Connection::open_with_flags(
            &output,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let bytes: Vec<u8> = c
            .query_row(
                "SELECT bytes FROM objects WHERE cid=?",
                [cid.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bytes, good);
        drop(c);
        publication_oracle(&path, &output);
    }
}
