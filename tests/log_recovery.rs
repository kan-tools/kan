//! `.design/v0.7-milestone.md` REQ-4, recovery half (AC-5).
//!
//! PR 3 stopped kan *creating* a damaged log: blocks are fsynced before the
//! root that points at them, and `HEAD` is replaced by atomic rename. That
//! does nothing for a log damaged before v0.7, or damaged by something
//! outside kan — a full disk, power loss on a filesystem without ordering
//! guarantees, a backup tool truncating a file, a killed `cp`.
//!
//! In every one of those, the claims are intact on disk and were unreachable:
//! `open_or_create` had no fallback, so reads *and* writes both failed. For a
//! tool whose one non-negotiable invariant is that no operation destroys a
//! subject, bricking on a torn byte is the wrong place to stop.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
};

fn content(identity: &Identity, text: &str) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from("work")),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

/// Build a log with `n` claims and hand back its directory.
async fn seeded(n: usize) -> (tempfile::TempDir, Identity, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();
    let log_dir = dir.path().join("log");
    let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
    for i in 0..n {
        log.append(content(&identity, &format!("claim-{i}")), &identity)
            .await
            .unwrap();
    }
    (dir, identity, log_dir)
}

/// AC-5: a `HEAD` lost to a torn write must not brick the log. Every claim is
/// still in the CAR; only the pointer to them was lost.
#[tokio::test]
async fn a_partially_written_head_is_recovered() {
    let (_dir, identity, log_dir) = seeded(3).await;

    // Exactly the damage demonstrated on the real binary: a truncated CID.
    std::fs::write(log_dir.join("HEAD"), "bafyreig").unwrap();

    let mut log = Log::open_or_create(&log_dir, &identity)
        .await
        .expect("a damaged HEAD must be recovered, not fatal");
    assert_eq!(
        log.iter_all().await.unwrap().len(),
        3,
        "every claim was intact in the CAR and must come back"
    );

    // HEAD on disk is *deliberately* still broken: a read command must not
    // write to the log. Rewriting it off the write lock is what let a
    // transient torn read roll a healthy log back permanently.
    let head_after_read = std::fs::read_to_string(log_dir.join("HEAD")).unwrap();
    assert_eq!(
        head_after_read.trim(),
        "bafyreig",
        "opening for a read must leave HEAD exactly as it found it"
    );

    // The next *write* repairs it, under the lock.
    log.append(content(&identity, "a write repairs HEAD"), &identity)
        .await
        .unwrap();
    let head = std::fs::read_to_string(log_dir.join("HEAD")).unwrap();
    assert!(
        head.trim().parse::<atproto_dasl::Cid>().is_ok(),
        "the first write after a recovery must persist the recovered root"
    );
    drop(log);
    let mut reopened = Log::open_or_create(&log_dir, &identity).await.unwrap();
    assert_eq!(reopened.iter_all().await.unwrap().len(), 4);
}

/// AC-5: a missing `HEAD` is the same story.
#[tokio::test]
async fn a_missing_head_is_recovered() {
    let (_dir, identity, log_dir) = seeded(3).await;
    std::fs::remove_file(log_dir.join("HEAD")).unwrap();

    let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
    assert_eq!(log.iter_all().await.unwrap().len(), 3);
}

/// AC-5: a truncated CAR tail — a crash mid-append. The damaged block is
/// dropped; everything written before it survives, and the log stays
/// writable afterwards.
#[tokio::test]
async fn a_truncated_car_tail_keeps_every_intact_claim() {
    let (_dir, identity, log_dir) = seeded(5).await;
    let car = log_dir.join("repo.car");

    let bytes = std::fs::read(&car).unwrap();
    std::fs::write(&car, &bytes[..bytes.len() - 40]).unwrap();
    // HEAD now names a commit whose blocks are partly gone, which is exactly
    // what a crash mid-append leaves behind.

    let mut log = Log::open_or_create(&log_dir, &identity)
        .await
        .expect("a torn CAR tail must not brick the log");
    let recovered = log.iter_all().await.unwrap().len();
    assert!(
        recovered >= 4,
        "only the damaged tail may be lost, not the whole file -- recovered {recovered} of 5"
    );

    // And the log must still be usable, not merely readable.
    log.append(content(&identity, "after-recovery"), &identity)
        .await
        .expect("a recovered log must still accept appends");

    // **Reopen from disk.** Asserting against the same in-memory `Log` here
    // is what made the original version of this test unable to fail: the MST
    // is in RAM, so the count is +1 by construction whether or not the block
    // ever reached a readable position in the file. The defect it missed was
    // that `persist_new_blocks` appends *past* the damaged region, so every
    // post-recovery write was unreachable to the tolerant reader --
    // silently, permanently, at exit 0.
    drop(log);
    let mut reopened = Log::open_or_create(&log_dir, &identity).await.unwrap();
    let after = reopened.iter_all().await.unwrap();
    assert_eq!(
        after.len(),
        recovered + 1,
        "an append after recovery must survive a reopen -- otherwise the log \
         is a write black hole that reports success"
    );
    assert!(
        after.iter().any(|(_, s)| matches!(
            &s.claim.content.body,
            ClaimBody::Observation { text } if text == "after-recovery"
        )),
        "the specific post-recovery claim must be readable back"
    );

    // And it keeps working: several more appends, all still there.
    for i in 0..3 {
        reopened
            .append(content(&identity, &format!("later-{i}")), &identity)
            .await
            .unwrap();
    }
    drop(reopened);
    let mut again = Log::open_or_create(&log_dir, &identity).await.unwrap();
    assert_eq!(again.iter_all().await.unwrap().len(), recovered + 4);
}

/// A healthy log must not be touched by any of this: recovery is a fallback,
/// not a rewrite that runs on every open.
#[tokio::test]
async fn an_undamaged_log_is_left_exactly_as_it_was() {
    let (_dir, identity, log_dir) = seeded(4).await;
    let head_before = std::fs::read_to_string(log_dir.join("HEAD")).unwrap();
    let car_before = std::fs::read(log_dir.join("repo.car")).unwrap();

    let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
    assert_eq!(log.iter_all().await.unwrap().len(), 4);

    assert_eq!(
        std::fs::read_to_string(log_dir.join("HEAD")).unwrap(),
        head_before
    );
    assert_eq!(std::fs::read(log_dir.join("repo.car")).unwrap(), car_before);
}

/// D3: a read must never modify the log, even when it recovers.
///
/// The recovery path runs on every open, including `kan show`. Rewriting
/// `HEAD` from there — off the write lock and non-atomically — turned a
/// transient torn read (CAR loaded before `HEAD`, an append landing between)
/// into a permanent rollback that stranded every claim written since.
#[tokio::test]
async fn reading_a_recovered_log_does_not_write_to_it() {
    let (_dir, identity, log_dir) = seeded(3).await;
    std::fs::write(log_dir.join("HEAD"), "bafyreig").unwrap();

    let before: Vec<(std::path::PathBuf, Vec<u8>, std::time::SystemTime)> =
        std::fs::read_dir(&log_dir)
            .unwrap()
            .flatten()
            .map(|e| {
                let p = e.path();
                let bytes = std::fs::read(&p).unwrap_or_default();
                let mtime = e.metadata().unwrap().modified().unwrap();
                (p, bytes, mtime)
            })
            .collect();

    // Several reads, including ones that fully enumerate.
    for _ in 0..3 {
        let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
        assert_eq!(log.iter_all().await.unwrap().len(), 3);
    }

    for (path, bytes, mtime) in before {
        assert_eq!(
            std::fs::read(&path).unwrap_or_default(),
            bytes,
            "{} was modified by a read",
            path.display()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            mtime,
            "{} was rewritten by a read",
            path.display()
        );
    }
}
