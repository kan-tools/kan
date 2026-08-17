//! Cold review of the F1/F2 branch, performance regression guard.
//!
//! The F9 fix routed `kan show`/`kan context` through `superseded_status_cids`,
//! which classified a subject under computed edges. Its first cut ran the
//! default provider union over EVERY claim in the class, spawning `O(k²)`
//! `git merge-base` subprocesses in `k` = distinct commit anchors — ~12 s on
//! a 50-commit subject, on the agent-facing read path. kan#202 completes the
//! repair: `state::classify_with` requests `GitAncestry` only after live
//! Status positions disagree, and only over those positions.
//!
//! This older elapsed-time regression remains as a large narrative-class
//! control. `tests/status_ancestry_demand.rs` carries the exact subprocess
//! assertions: zero for no/single/agreeing positions, pairs-among-live for a
//! disagreement.

use std::process::Command;
use std::time::Instant;

use kan::{
    actions,
    claim::{
        Anchor, ArtifactRef, AuthorId, ClaimBody, ClaimContent, Rkey, StatusValue, SubjectRef,
    },
    git::GitSubstrate,
    sign::Identity,
    store::{index::Index, log::Log},
    workspace::Workspace,
};

fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .expect("git failed");
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[tokio::test]
async fn show_of_a_many_commit_subject_stays_fast() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["commit", "-q", "--allow-empty", "-m", "0"]);

    let identity = Identity::generate();
    identity.save(&dir.path().join(".kan/identity")).unwrap();
    let mut log = Log::open_or_create(&dir.path().join(".kan/log"), &identity)
        .await
        .unwrap();
    let gitsub = GitSubstrate::open(dir.path()).unwrap();
    let anchor = Anchor::Workspace(gitsub.genesis().unwrap());
    let who = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let mk = |body: ClaimBody, sha: String| ClaimContent {
        author: who.clone(),
        workspace: anchor.clone(),
        subject: SubjectRef::Local(Rkey::from("subj")),
        body,
        cites: vec![],
        artifacts: vec![ArtifactRef::Commit(sha)],
        recorded_at: None,
    };

    // 50 narrative claims, each anchored to its own commit — the k that used
    // to drive the O(k²) fan-out.
    const N: usize = 50;
    for i in 0..N {
        git(
            dir.path(),
            &["commit", "-q", "--allow-empty", "-m", &format!("c{i}")],
        );
        let sha = git(dir.path(), &["rev-parse", "HEAD"]);
        log.append(
            mk(
                ClaimBody::Observation {
                    text: format!("note {i}"),
                },
                sha,
            ),
            &identity,
        )
        .await
        .unwrap();
    }
    // Two same-author status claims collapse to one live position before any
    // ancestry provider is requested.
    let last = git(dir.path(), &["rev-parse", "HEAD"]);
    for value in [StatusValue::Blocked, StatusValue::Resolved] {
        log.append(mk(ClaimBody::Status { value }, last.clone()), &identity)
            .await
            .unwrap();
    }

    let claims = log.iter_all().await.unwrap();
    let mut index = Index::open(&dir.path().join(".kan/index.sqlite")).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();
    let overlay = Log::open_or_create(&dir.path().join(".kan/overlay"), &identity)
        .await
        .unwrap();
    let ws = Workspace::from_parts(
        dir.path().to_path_buf(),
        identity,
        log,
        overlay,
        index,
        anchor,
        gitsub,
        Default::default(),
    );
    let trust = ws.local_trust().unwrap();

    let start = Instant::now();
    let out = actions::show(&ws, "subj", &trust, None).unwrap();
    let elapsed = start.elapsed();

    assert!(out.contains("subj"), "show should render the subject");
    // Generous by design: the narrowed read is well under a second; the
    // O(k²) fan-out this guards against measured ~12 s at this commit count.
    assert!(
        elapsed.as_secs() < 6,
        "kan show of a {N}-commit subject took {elapsed:?} -- the status \
         classification is fanning out git subprocesses before it knows \
         ancestry is needed"
    );
}
