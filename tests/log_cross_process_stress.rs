//! Permanent regression guard for the incremental-append writer (ADR-13):
//! unlike `tests/log_stress.rs` (one long-lived `Log`, one fresh reopen at
//! the end), this simulates the *real* kan usage pattern — a brand-new
//! `Log` instance per append, exactly what happens across separate `kan
//! observe` CLI invocations. This is the actual risk surface for
//! `persist_new_blocks`'s hand-rolled CAR block appending: does the
//! file-is-new/header-once logic behave correctly when every single append
//! comes from a fresh process, not just fresh within one long-lived object.

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
};

fn content(author: &AuthorId, i: usize) -> ClaimContent {
    ClaimContent {
        author: author.clone(),
        workspace: Anchor::Workspace("cross-process-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(format!("subject-{i}"))),
        body: ClaimBody::Observation {
            text: format!("observation number {i}"),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

#[tokio::test]
async fn survives_many_separate_log_instances_appending_in_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };

    const N: usize = 50;
    let mut cids = Vec::with_capacity(N);

    for i in 0..N {
        let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
        let cid = log.append(content(&author, i), &identity).await.unwrap();
        cids.push(cid);
        drop(log);

        if (i + 1) % 10 == 0 {
            let mut checker = Log::open_or_create(&log_dir, &identity).await.unwrap();
            for (j, cid) in cids.iter().enumerate() {
                assert!(
                    checker.get(cid.clone()).await.unwrap().is_some(),
                    "claim #{j} missing after {} separate-instance appends",
                    i + 1
                );
            }
            let all = checker.iter_all().await.unwrap();
            assert_eq!(
                all.len(),
                i + 1,
                "iter_all should match the number of appends so far"
            );
        }
    }
}
