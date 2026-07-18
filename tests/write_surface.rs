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
    index.rebuild(&claims).unwrap();

    let mut ws = Workspace {
        identity,
        log,
        index,
        anchor,
        git,
    };

    match actions::retract(&mut ws, &other_cid.to_string()).await {
        Err(actions::Error::NotYourClaim(_)) => {}
        other => panic!(
            "expected NotYourClaim, got {}",
            match other {
                Ok(_) => "Ok(..)".to_string(),
                Err(e) => e.to_string(),
            }
        ),
    }

    // Nothing was written: the subject still shows only the original claim.
    let claims = ws.log.iter_all().await.unwrap();
    assert_eq!(claims.len(), 1);
}
