//! Library-level coverage for `v0.2` write-surface behavior that the CLI's
//! single-identity-per-repo model can't exercise end to end: `retract`'s
//! cross-author rejection (AC-3's second half) needs a genuinely different
//! signing identity, not just a hand-typed `AuthorId`, so a real second
//! `Identity` signs the "other author"'s claim here — mirroring
//! `tests/index_and_fold.rs`'s "hand-construct a `ClaimContent`" pattern,
//! plus a real second keypair so the claim actually verifies.

use std::process::Command;

use kan::{
    actions,
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    git::GitSubstrate,
    sign::Identity,
    store::{index::Index, log::Log},
    workspace::Workspace,
};

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    dir
}

/// AC-3 (second half): a `Retraction` targeting a claim authored by a
/// genuinely different identity is rejected at write time, before anything
/// is appended to the log.
#[tokio::test]
async fn retract_rejects_another_authors_claim_at_write_time() {
    let dir = git_repo();
    let identity = Identity::load_or_create(&dir.path().join(".kan/identity")).unwrap();
    let mut log = Log::open_or_create(&dir.path().join(".kan/log"), &identity)
        .await
        .unwrap();
    let git = GitSubstrate::open(dir.path()).unwrap();
    let anchor = Anchor::Workspace(git.genesis().unwrap());

    // A genuinely different signing identity -- the only way a second
    // author's claim can land in one log today, since no CLI path
    // constructs one yet (REQ-11..13, not this milestone slice).
    let other_identity = Identity::generate();
    let other_cid = log
        .append(
            ClaimContent {
                author: AuthorId {
                    did: other_identity.did(),
                    agent: None,
                },
                workspace: anchor.clone(),
                subject: SubjectRef::Local(Rkey::from("bug-42")),
                body: ClaimBody::Observation {
                    text: "not mine".to_string(),
                },
                cites: vec![],
                artifacts: vec![],
            },
            &other_identity,
        )
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let mut index = Index::open(&dir.path().join(".kan/index.sqlite")).unwrap();
    index.rebuild(&claims, log.current_root().as_ref()).unwrap();

    let mut ws = Workspace {
        root: dir.path().to_path_buf(),
        identity,
        log,
        index,
        anchor,
        git,
    };

    match actions::retract(&mut ws, &other_cid.to_string(), None).await {
        Err(actions::Error::NotYourClaim(_)) => {}
        other => panic!(
            "expected NotYourClaim, got {}",
            match other {
                Ok(_) => "Ok(..)".to_string(),
                Err(e) => e.to_string(),
            }
        ),
    }

    // REQ-5: the cross-author error message now points at `kan reject` by
    // name.
    match actions::retract(&mut ws, &other_cid.to_string(), None).await {
        Err(e) => assert!(
            e.to_string().contains("kan reject"),
            "expected the NotYourClaim error to mention `kan reject`, got: {e}"
        ),
        Ok(_) => panic!("expected an error"),
    }

    // Nothing was written: the subject still shows only the original claim.
    let claims = ws.log.iter_all().await.unwrap();
    assert_eq!(claims.len(), 1);
}

/// AC-3: `kan reject <cid>` on another author's claim writes a live
/// `Rejects{claim}` claim. Needs a genuinely different signing identity, the
/// same reason `retract_rejects_another_authors_claim_at_write_time` does.
#[tokio::test]
async fn reject_writes_a_rejects_claim_against_another_authors_claim() {
    let dir = git_repo();
    let identity = Identity::load_or_create(&dir.path().join(".kan/identity")).unwrap();
    let mut log = Log::open_or_create(&dir.path().join(".kan/log"), &identity)
        .await
        .unwrap();
    let git = GitSubstrate::open(dir.path()).unwrap();
    let anchor = Anchor::Workspace(git.genesis().unwrap());

    let other_identity = Identity::generate();
    let other_cid = log
        .append(
            ClaimContent {
                author: AuthorId {
                    did: other_identity.did(),
                    agent: None,
                },
                workspace: anchor.clone(),
                subject: SubjectRef::Local(Rkey::from("bug-42")),
                body: ClaimBody::Observation {
                    text: "not mine".to_string(),
                },
                cites: vec![],
                artifacts: vec![],
            },
            &other_identity,
        )
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let mut index = Index::open(&dir.path().join(".kan/index.sqlite")).unwrap();
    index.rebuild(&claims, log.current_root().as_ref()).unwrap();

    let mut ws = Workspace {
        root: dir.path().to_path_buf(),
        identity,
        log,
        index,
        anchor,
        git,
    };

    let result = actions::reject(&mut ws, &other_cid.to_string(), None)
        .await
        .unwrap();
    assert_eq!(result.kind, kan::claim::ClaimKind::Rejects);
}

/// AC-3 (second half, library-level counterpart to the CLI test): rejecting
/// your own claim errors, mentioning `kan retract`.
#[tokio::test]
async fn reject_refuses_the_callers_own_claim() {
    let dir = git_repo();
    let identity = Identity::load_or_create(&dir.path().join(".kan/identity")).unwrap();
    let mut log = Log::open_or_create(&dir.path().join(".kan/log"), &identity)
        .await
        .unwrap();
    let git = GitSubstrate::open(dir.path()).unwrap();
    let anchor = Anchor::Workspace(git.genesis().unwrap());

    let cid = log
        .append(
            ClaimContent {
                author: AuthorId {
                    did: identity.did(),
                    agent: None,
                },
                workspace: anchor.clone(),
                subject: SubjectRef::Local(Rkey::from("bug-42")),
                body: ClaimBody::Observation {
                    text: "mine".to_string(),
                },
                cites: vec![],
                artifacts: vec![],
            },
            &identity,
        )
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let mut index = Index::open(&dir.path().join(".kan/index.sqlite")).unwrap();
    index.rebuild(&claims, log.current_root().as_ref()).unwrap();

    let mut ws = Workspace {
        root: dir.path().to_path_buf(),
        identity,
        log,
        index,
        anchor,
        git,
    };

    match actions::reject(&mut ws, &cid.to_string(), None).await {
        Err(e @ actions::Error::CantRejectOwnClaim(_)) => {
            assert!(e.to_string().contains("kan retract"));
        }
        other => panic!(
            "expected CantRejectOwnClaim, got {}",
            match other {
                Ok(_) => "Ok(..)".to_string(),
                Err(e) => e.to_string(),
            }
        ),
    }
}
