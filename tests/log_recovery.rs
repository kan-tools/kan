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
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
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

    // HEAD is repaired on disk, not just papered over in memory.
    let head = std::fs::read_to_string(log_dir.join("HEAD")).unwrap();
    assert!(head.trim().parse::<atproto_dasl::Cid>().is_ok());
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
    assert_eq!(log.iter_all().await.unwrap().len(), recovered + 1);
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
