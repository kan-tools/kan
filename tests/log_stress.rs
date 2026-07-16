//! Permanent regression guard for the class of bug that caused ADR-12's
//! `atrium-repo` -> `atproto-repo` switch (`docs/DECISIONS.md` ADR-11):
//! `atrium-repo`'s MST silently lost previously-appended entries at ordinary
//! scale (~24% of runs within 20 sequential inserts). This test appends a
//! meaningful number of real claims through the real `Log` API and checks
//! every one is still reachable — both from the live `Log` and from a fresh
//! `Log::open_or_create` over the same on-disk CAR file.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
};

fn content(author: &AuthorId, i: usize) -> ClaimContent {
    ClaimContent {
        author: author.clone(),
        workspace: Anchor::Workspace("stress-test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(format!("subject-{i}"))),
        body: ClaimBody::Observation {
            text: format!("observation number {i}"),
        },
        cites: vec![],
        artifacts: vec![],
    }
}

#[tokio::test]
async fn no_claim_goes_missing_across_a_long_append_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    // Large enough to be a meaningful regression guard (atrium-repo lost
    // data in ~24% of runs by n=20) while staying fast: this test checks
    // full reachability after *every* append (O(n^2)), compounded by
    // Log::append's own O(n)-per-append full-CAR-rewrite (ADR-12).
    const N: usize = 60;
    let mut cids = Vec::with_capacity(N);
    for i in 0..N {
        let cid = log.append(content(&author, i), &identity).await.unwrap();
        cids.push(cid);

        // Check every prior claim is still reachable after every single
        // append, not just at the end — this is exactly the check that
        // caught atrium-repo losing data mid-sequence.
        for (j, prior) in cids.iter().enumerate() {
            assert!(
                log.get(prior.clone()).await.unwrap().is_some(),
                "claim #{j} became unreachable after appending #{i}"
            );
        }
    }

    // And from a completely fresh Log instance over the same on-disk file.
    drop(log);
    let mut reopened = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    for (i, cid) in cids.iter().enumerate() {
        assert!(
            reopened.get(cid.clone()).await.unwrap().is_some(),
            "claim #{i} missing after reopening the log"
        );
    }

    let all = reopened.iter_all().await.unwrap();
    assert_eq!(
        all.len(),
        N,
        "iter_all should enumerate every appended claim"
    );
}
