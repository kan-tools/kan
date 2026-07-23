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
    std::fs::rename(&path.path, &impostor).unwrap();

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

/// #107: a `.claims/` file written by v0.6 must keep verifying, and
/// republishing must retire it rather than leaving a diverging duplicate.
///
/// v0.7 renamed files to make the mapping injective (REQ-13) and then added
/// filename authentication (D6). Each was right alone; together they orphaned
/// every existing published file and then reported every record in it as
/// mismatched — a wall of errors about files kan wrote itself. Neither change
/// was checked against what already existed.
#[test]
fn a_v0_6_published_file_still_verifies_and_is_retired_on_republish() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("bug-42"));
    let claim = signed(&identity, "bug-42", "written before the rename");

    // Publish, then move the file to the name v0.6 would have used.
    let written = git_tree::write_subject(dir.path(), &subject, &[(claim.clone(), None)]).unwrap();
    let legacy = dir
        .path()
        .join(".claims")
        .join(git_tree::legacy_file_name(&subject));
    assert_ne!(
        written.path, legacy,
        "the current name must differ from v0.6's, or this test proves nothing"
    );
    std::fs::rename(&written.path, &legacy).unwrap();

    // It must read clean under the old name: kan wrote it, it is signed, and
    // only the naming convention changed.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });
    let errors: Vec<String> = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
        .collect();
    assert!(
        errors.is_empty(),
        "a v0.6-named file must verify clean: {errors:?}"
    );

    // Republishing retires it rather than leaving two diverging files.
    let again = git_tree::write_subject(dir.path(), &subject, &[(claim, None)]).unwrap();
    assert_eq!(
        again.retired.as_deref(),
        Some(legacy.as_path()),
        "republishing must report retiring the old file, not do it silently"
    );
    assert!(!legacy.exists(), "the orphan must be gone");
    assert!(again.path.exists());

    let remaining: Vec<_> = std::fs::read_dir(dir.path().join(".claims"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        remaining.len(),
        1,
        "exactly one file per subject: {remaining:?}"
    );
}

/// Review D-A: publishing a subject must never retire a *different* subject's
/// file, even when both map to the same lossy v0.6 legacy name.
///
/// The first #107 fix keyed the deletion on `legacy_file_name` alone — the
/// very mapping whose lossiness caused #107 in the first place — so
/// publishing `telos/x` deleted `telos_x`'s file and told the user it had
/// rewritten it. A write path destroying another subject's data.
#[test]
fn publishing_does_not_retire_a_colliding_subjects_file() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    // `telos_x` has a genuine v0.6 file of its own.
    let neighbour = SubjectRef::Local(Rkey::from("telos_x"));
    let w = git_tree::write_subject(
        dir.path(),
        &neighbour,
        &[(signed(&identity, "telos_x", "the neighbour's claim"), None)],
    )
    .unwrap();
    let legacy = dir
        .path()
        .join(".claims")
        .join(git_tree::legacy_file_name(&neighbour));
    std::fs::rename(&w.path, &legacy).unwrap();

    // Publish `telos/x` — a different subject that maps to the SAME legacy name.
    let colliding = SubjectRef::Local(Rkey::from("telos/x"));
    assert_eq!(
        git_tree::legacy_file_name(&colliding),
        git_tree::legacy_file_name(&neighbour),
        "the two subjects must share a legacy name, or this proves nothing"
    );
    let written = git_tree::write_subject(
        dir.path(),
        &colliding,
        &[(signed(&identity, "telos/x", "the colliding claim"), None)],
    )
    .unwrap();

    assert!(
        written.retired.is_none(),
        "publishing telos/x must not retire telos_x's file"
    );
    assert!(legacy.exists(), "the neighbour's file must survive");
    let text = std::fs::read_to_string(&legacy).unwrap();
    assert!(
        text.contains("the neighbour's claim"),
        "the neighbour's claim must be intact"
    );
}

/// Review D-C: a legacy-named file holding a *mix* of subjects (each mapping
/// to that legacy name) must not authenticate — only a uniform, single-subject
/// file gets the legacy allowance.
#[test]
fn a_mixed_subject_legacy_file_is_not_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();

    // Two subjects that both map to `telos_x.md` under the v0.6 scheme.
    let a = signed(&identity, "telos/x", "record about telos/x");
    let b = signed(&identity, "telos_x", "record about telos_x");
    let claims_dir = dir.path().join(".claims");
    std::fs::create_dir_all(&claims_dir).unwrap();
    let mixed = format!(
        "{}\n---8<---\n{}",
        git_tree::to_record(&a).unwrap(),
        git_tree::to_record(&b).unwrap()
    );
    let legacy_name = git_tree::legacy_file_name(&SubjectRef::Local(Rkey::from("telos_x")));
    std::fs::write(claims_dir.join(&legacy_name), mixed).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let results = rt.block_on(async {
        let id = Identity::load_or_create(&dir.path().join("reader-id")).unwrap();
        let log = kan::store::log::Log::open_or_create(&dir.path().join("reader-log"), &id)
            .await
            .unwrap();
        git_tree::GitTree::new(log, dir.path().to_path_buf()).read_all()
    });
    let mismatch = results.iter().any(|r| {
        r.as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("does not describe"))
    });
    assert!(
        mismatch,
        "a mixed-subject legacy file must be reported, not waved through: {:?}",
        results
            .iter()
            .map(|r| r.as_ref().map(|_| "ok").map_err(|e| e.to_string()))
            .collect::<Vec<_>>()
    );
}
