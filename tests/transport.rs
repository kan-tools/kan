//! `.design/v0.5-milestone.md` AC-3/AC-4: `LocalOnly` (`kan::transport`) is
//! proven equivalent to today's direct `Log::append` usage, and its
//! `subscribe` returns an honestly-empty stream rather than a stub.

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
    transport::{LocalOnly, Transport},
};
use tokio_stream::StreamExt;

fn content(author: &AuthorId) -> ClaimContent {
    ClaimContent {
        author: author.clone(),
        workspace: Anchor::Workspace("transport-test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from("transport-test-subject")),
        body: ClaimBody::Observation {
            text: "observation used to prove LocalOnly::publish matches Log::append".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

/// AC-3 / REQ-6: `crate::cid::content_cid` is a pure function of
/// `ClaimContent` alone, so appending identical content once directly
/// through `Log::append` and once through `LocalOnly::publish` (in two
/// independent temp-dir logs) must yield identical CIDs — proof that
/// `publish` doesn't alter, wrap, or reorder the content before handing it
/// to `Log::append`.
#[tokio::test]
async fn local_only_publish_matches_log_append_directly() {
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };

    // `recorded_at` is content, so `append` stamping it means two logs can no
    // longer be compared by handing them the *same* unstamped content — each
    // would stamp a different microsecond and the CIDs would differ for a
    // reason that has nothing to do with what this test is proving. Pinning
    // it makes the comparison meaningful again, and exercises `append`'s
    // `get_or_insert`: a caller-supplied time is honored, never rewritten.
    let pinned = |author: &AuthorId| ClaimContent {
        recorded_at: Some(1_700_000_000_000_000),
        ..content(author)
    };

    let direct_dir = tempfile::tempdir().unwrap();
    let mut direct_log = Log::open_or_create(&direct_dir.path().join("log"), &identity)
        .await
        .unwrap();
    let direct_cid = direct_log.append(pinned(&author), &identity).await.unwrap();

    let via_transport_dir = tempfile::tempdir().unwrap();
    let via_transport_log = Log::open_or_create(&via_transport_dir.path().join("log"), &identity)
        .await
        .unwrap();
    let mut local_only = LocalOnly::new(via_transport_log);
    let via_transport_cid = local_only
        .publish(pinned(&author), &identity)
        .await
        .unwrap();

    assert_eq!(
        direct_cid, via_transport_cid,
        "LocalOnly::publish should produce the same content CID as calling \
         Log::append directly for identical content"
    );
}

/// AC-4 / REQ-3: `LocalOnly::subscribe` on a freshly-created log returns an
/// honestly-empty stream — no panic, no hang — since a single local log has
/// no other author to subscribe to.
#[tokio::test]
async fn local_only_subscribe_is_honestly_empty() {
    let identity = Identity::generate();
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    let local_only = LocalOnly::new(log);

    let mut stream = local_only.subscribe(&[identity.did()]).await.unwrap();
    assert!(
        stream.next().await.is_none(),
        "LocalOnly::subscribe should yield nothing, not stub behavior"
    );
}
