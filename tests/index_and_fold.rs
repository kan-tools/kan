//! M2 acceptance criteria from `.design/kan-spine.md`: AC-3 (local-only
//! smell-test fixture), AC-6 (index is a disposable projection).

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    fold::{self, TrustBase},
    sign::Identity,
    store::{index::Index, log::Log},
};

fn solo(did: &str) -> TrustBase {
    TrustBase::solo(AuthorId {
        did: did.to_string(),
        agent: None,
    })
}

fn content(did: &str, subject: &str, body: ClaimBody) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: did.to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

fn observation(text: &str) -> ClaimBody {
    ClaimBody::Observation {
        text: text.to_string(),
    }
}

/// AC-3: one log, no SameAs, all subjects Local -> trivial latest-wins view,
/// contest stage never entered (this is CLAUDE.md's smell test — SoloTrust
/// never produces Contested).
#[tokio::test]
async fn ac3_local_only_smell_test() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    log.append(
        content(&identity.did(), "issue-1", observation("first look")),
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(&identity.did(), "issue-1", observation("second look")),
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(&identity.did(), "issue-2", observation("unrelated")),
        &identity,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &solo(&identity.did()));

    assert_eq!(view.classes.len(), 2);
    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    assert_eq!(issue1.claims.len(), 2);
    // Chronological: "first look" then "second look" — no contest, nothing
    // superseded, both simply present (latest-wins is a read-time concern for
    // callers, not something the trivial fold collapses away).
    assert_eq!(issue1.claims[0].1.content.body, observation("first look"));
    assert_eq!(issue1.claims[1].1.content.body, observation("second look"));
}

/// Retracting a Retraction restores the original claim to the live set, with
/// no special-cased "undo" path (ADR-6).
#[tokio::test]
async fn retract_a_retraction_restores_the_original() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    let original = log
        .append(
            content(&identity.did(), "issue-1", observation("flaky test")),
            &identity,
        )
        .await
        .unwrap();
    let retraction = log
        .append(
            content(
                &identity.did(),
                "issue-1",
                ClaimBody::Retraction {
                    supersedes: original.clone(),
                },
            ),
            &identity,
        )
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims.clone(), &solo(&identity.did()));
    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    // Only the (live) retraction claim itself remains; the original is excluded.
    assert_eq!(issue1.claims.len(), 1);
    assert_eq!(issue1.claims[0].0, retraction);

    // Now retract the retraction.
    log.append(
        content(
            &identity.did(),
            "issue-1",
            ClaimBody::Retraction {
                supersedes: retraction.clone(),
            },
        ),
        &identity,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &solo(&identity.did()));
    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    let live_cids: Vec<_> = issue1.claims.iter().map(|(cid, _)| cid.clone()).collect();
    assert!(
        live_cids.contains(&original),
        "original claim should be live again"
    );
    assert!(
        !live_cids.contains(&retraction),
        "the undone retraction should not be live"
    );
}

/// AC-6: the SQLite index is a pure disposable projection — delete it,
/// rebuild from the log, get the same claims back.
#[tokio::test]
async fn ac6_index_is_disposable() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    log.append(
        content(&identity.did(), "issue-1", observation("a")),
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(&identity.did(), "issue-2", observation("b")),
        &identity,
    )
    .await
    .unwrap();

    let index_path = dir.path().join("index.sqlite");
    let claims_from_log = log.iter_all().await.unwrap();

    let mut index = Index::open(&index_path).unwrap();
    index
        .rebuild(&claims_from_log, &[], log.current_root().as_ref())
        .unwrap();
    assert_eq!(index.len().unwrap(), 2);
    let first_pass = index.all_stored_claims().unwrap();

    // Delete the index file entirely and rebuild from the log alone.
    drop(index);
    std::fs::remove_file(&index_path).unwrap();

    let mut index = Index::open(&index_path).unwrap();
    assert!(index.is_empty().unwrap());
    index
        .rebuild(&claims_from_log, &[], log.current_root().as_ref())
        .unwrap();
    let second_pass = index.all_stored_claims().unwrap();

    assert_eq!(first_pass.len(), second_pass.len());
    for ((cid_a, a), (cid_b, b)) in first_pass.iter().zip(second_pass.iter()) {
        assert_eq!(cid_a, cid_b);
        assert_eq!(a.claim.content, b.claim.content);
        assert_eq!(a.rev, b.rev);
    }

    // And the fold over the rebuilt index's claims matches the fold over the
    // log directly.
    let view_from_index = fold::fold(second_pass, &solo(&identity.did()));
    let view_from_log = fold::fold(claims_from_log, &solo(&identity.did()));
    assert_eq!(view_from_index.classes.len(), view_from_log.classes.len());
}
