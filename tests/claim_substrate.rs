//! M1 acceptance criteria from `.design/kan-spine.md`: AC-1 (CID determinism),
//! AC-2 (tamper detection), plus a round trip through the log proving a
//! written claim reads back byte-identical and signature-valid.

use kan::{
    cid,
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign,
    sign::Identity,
    store::log::Log,
};

fn sample_content(author_did: String, text: &str) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: author_did,
            agent: None,
        },
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from("some-subject")),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
    }
}

#[test]
fn ac1_content_cid_is_deterministic() {
    let identity = Identity::generate();
    let content = sample_content(identity.did(), "the sky is blue");

    let cid_a = cid::content_cid(&content).unwrap();
    let cid_b = cid::content_cid(&content).unwrap();
    assert_eq!(cid_a, cid_b);

    // A differently-constructed but equal-content claim must hash the same.
    let content_again = sample_content(identity.did(), "the sky is blue");
    assert_eq!(cid_a, cid::content_cid(&content_again).unwrap());
}

#[test]
fn ac1_different_content_different_cid() {
    let identity = Identity::generate();
    let a = sample_content(identity.did(), "the sky is blue");
    let b = sample_content(identity.did(), "the sky is grey");
    assert_ne!(cid::content_cid(&a).unwrap(), cid::content_cid(&b).unwrap());
}

#[test]
fn ac2_tampering_invalidates_the_signature() {
    let identity = Identity::generate();
    let content = sample_content(identity.did(), "the sky is blue");

    let original_cid = cid::content_cid(&content).unwrap();
    let sig = identity.sign(&original_cid.to_bytes()).unwrap();

    // The signature verifies against the CID it was actually made over.
    assert!(sign::verify(
        &identity.did(),
        &original_cid.to_bytes(),
        &sig
    ));

    // Tamper with the content: the recomputed CID differs from the signed one,
    // and the old signature does not verify against the new CID.
    let tampered = sample_content(identity.did(), "the sky is green");
    let tampered_cid = cid::content_cid(&tampered).unwrap();
    assert_ne!(original_cid, tampered_cid);
    assert!(!sign::verify(
        &identity.did(),
        &tampered_cid.to_bytes(),
        &sig
    ));
}

#[tokio::test]
async fn log_round_trip_reads_back_a_verified_claim() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    let content = sample_content(identity.did(), "observed: the build is green");
    let claim_cid = log.append(content.clone(), &identity).await.unwrap();

    let fetched = log
        .get(claim_cid.clone())
        .await
        .unwrap()
        .expect("claim should be present");
    assert_eq!(fetched.content, content);
    assert!(sign::verify(
        &identity.did(),
        &claim_cid.to_bytes(),
        &fetched.sig
    ));
}

#[tokio::test]
async fn log_reopens_and_preserves_prior_claims() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("log");
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    let claim_cid = {
        let mut log = Log::open_or_create(&log_path, &identity).await.unwrap();
        log.append(sample_content(identity.did(), "first claim"), &identity)
            .await
            .unwrap()
    };

    // Reopen as a fresh Log instance, backed by the same on-disk CAR file.
    let mut log = Log::open_or_create(&log_path, &identity).await.unwrap();
    let fetched = log
        .get(claim_cid)
        .await
        .unwrap()
        .expect("claim should survive reopen");
    assert_eq!(
        fetched.content.body,
        ClaimBody::Observation {
            text: "first claim".to_string()
        }
    );
}
