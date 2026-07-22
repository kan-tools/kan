//! Regression tests for the defects a pre-release adversarial review found in
//! v0.7 (ADR-49). Each reproduces the reviewer's own case.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    transport::git_tree,
};

fn signed(identity: &Identity, subject: &str, text: &str) -> kan::claim::Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("g".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    let sig = identity.sign(&cid.to_bytes()).unwrap();
    kan::claim::Claim { content, sig }
}

/// D6 / REQ-13 second half / AC-14: a file whose name disagrees with the
/// records inside is reported.
///
/// The name was decorative — `read_all` never compared it to anything, so a
/// `.claims/x.md` full of subject-`y` claims folded as `y` in silence. With
/// the header fields also unverified before REQ-9, *nothing* about a file's
/// apparent subject was checkable; only the hex content was.
#[test]
fn a_file_named_for_the_wrong_subject_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("real-subject"));

    let path = git_tree::write_subject(
        dir.path(),
        &subject,
        &[(signed(&identity, "real-subject", "a claim"), None)],
    )
    .unwrap();

    // Rename it to another subject's filename, leaving records untouched.
    let impostor = dir
        .path()
        .join(".claims")
        .join(git_tree::file_name(&SubjectRef::Local(Rkey::from(
            "totally-different",
        ))));
    std::fs::rename(&path, &impostor).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });

    let reported = results.iter().any(|r| {
        r.as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("filename does not describe"))
    });
    assert!(
        reported,
        "a file whose name disagrees with its records must be reported; got {:?}",
        results
            .iter()
            .map(|r| r.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
            .collect::<Vec<_>>()
    );
}

/// D4: a `SameAs` merge must not put one subject's claims into another
/// subject's file.
///
/// Folding before publishing is right — it filters retracted and untrusted
/// claims (REQ-12) — but the fold's unit is the merge *class*, so taking its
/// output wholesale duplicated every claim into every merged subject's file
/// and made publishing one rewrite the others.
#[test]
fn publishing_a_merged_subject_writes_only_that_subjects_claims() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    for (subject, text) in [("alpha", "about alpha"), ("beta", "about beta")] {
        git_tree::write_subject(
            dir.path(),
            &SubjectRef::Local(Rkey::from(subject)),
            &[(signed(&identity, subject, text), None)],
        )
        .unwrap();
    }

    for (subject, foreign) in [("alpha", "about beta"), ("beta", "about alpha")] {
        let path = dir
            .path()
            .join(".claims")
            .join(git_tree::file_name(&SubjectRef::Local(Rkey::from(subject))));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(foreign),
            "{subject}'s file must not contain another subject's claim"
        );
    }
}
