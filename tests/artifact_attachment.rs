//! AC-6: every write verb's resulting claim carries `artifacts:
//! [Commit(<current HEAD sha>)]` with no flag needed; `--file` attaches
//! `FileAt`/`LineRangeAt` on top when given. Asserted at the library level
//! (inspecting `ClaimContent::artifacts` directly) rather than through the
//! CLI subprocess harness `tests/cli.rs` uses elsewhere, since `kan show`
//! doesn't render artifacts today — this is the most direct way to check
//! them without adding unrelated display surface.

use std::{path::PathBuf, process::Command};

use kan::{
    actions,
    claim::{Anchor, ArtifactRef, Span},
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

fn head_sha(dir: &std::path::Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

async fn open_workspace(dir: &std::path::Path) -> Workspace {
    let identity = Identity::load_or_create(&dir.join(".kan/identity")).unwrap();
    let log = Log::open_or_create(&dir.join(".kan/log"), &identity)
        .await
        .unwrap();
    let index = Index::open(&dir.join(".kan/index.sqlite")).unwrap();
    let git = GitSubstrate::open(dir).unwrap();
    let anchor = Anchor::Workspace(git.genesis().unwrap());
    Workspace {
        root: dir.to_path_buf(),
        identity,
        log,
        index,
        anchor,
        git,
    }
}

#[tokio::test]
async fn observe_auto_attaches_the_head_commit_with_no_flag() {
    let dir = git_repo();
    let sha = head_sha(dir.path());
    let mut ws = open_workspace(dir.path()).await;

    let result = actions::observe(
        &mut ws,
        "x".to_string(),
        None,
        vec![],
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let stored = ws
        .log
        .get_stored(result.narrative.cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.claim.content.artifacts,
        vec![ArtifactRef::Commit(sha)]
    );
}

#[tokio::test]
async fn file_flag_attaches_file_at_on_top_of_the_automatic_commit() {
    let dir = git_repo();
    let sha = head_sha(dir.path());
    let mut ws = open_workspace(dir.path()).await;

    let result = actions::observe(
        &mut ws,
        "x".to_string(),
        None,
        vec![],
        Some("src/foo.rs".to_string()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let stored = ws
        .log
        .get_stored(result.narrative.cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.claim.content.artifacts,
        vec![
            ArtifactRef::Commit(sha.clone()),
            ArtifactRef::FileAt(PathBuf::from("src/foo.rs"), sha),
        ]
    );
}

#[tokio::test]
async fn file_flag_with_a_line_range_attaches_line_range_at() {
    let dir = git_repo();
    let sha = head_sha(dir.path());
    let mut ws = open_workspace(dir.path()).await;

    let result = actions::observe(
        &mut ws,
        "x".to_string(),
        None,
        vec![],
        Some("src/foo.rs:10-20".to_string()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let stored = ws
        .log
        .get_stored(result.narrative.cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.claim.content.artifacts,
        vec![
            ArtifactRef::Commit(sha.clone()),
            ArtifactRef::LineRangeAt(
                PathBuf::from("src/foo.rs"),
                sha,
                Span { start: 10, end: 20 }
            ),
        ]
    );
}

/// A malformed range suffix falls back to treating the whole string as the
/// path, rather than erroring — a colon can legitimately appear in a path.
#[tokio::test]
async fn file_flag_with_an_unparseable_range_falls_back_to_the_whole_path() {
    let dir = git_repo();
    let sha = head_sha(dir.path());
    let mut ws = open_workspace(dir.path()).await;

    let result = actions::observe(
        &mut ws,
        "x".to_string(),
        None,
        vec![],
        Some("src/foo.rs:not-a-range".to_string()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let stored = ws
        .log
        .get_stored(result.narrative.cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.claim.content.artifacts,
        vec![
            ArtifactRef::Commit(sha.clone()),
            ArtifactRef::FileAt(PathBuf::from("src/foo.rs:not-a-range"), sha),
        ]
    );
}

/// `kan resolve`'s pair-write: `--file` applies to the narrative
/// (`Resolution`) claim only — the paired `Status` claim gets just the
/// automatic commit anchor, since it isn't "about" the file the way the
/// narrative claim is.
#[tokio::test]
async fn resolve_applies_file_only_to_the_narrative_claim() {
    let dir = git_repo();
    let sha = head_sha(dir.path());
    let mut ws = open_workspace(dir.path()).await;

    let result = actions::resolve(
        &mut ws,
        "bug-42",
        "fixed",
        vec![],
        Some("src/foo.rs".to_string()),
        None,
        None,
    )
    .await
    .unwrap();

    let narrative = ws
        .log
        .get_stored(result.narrative.cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        narrative.claim.content.artifacts,
        vec![
            ArtifactRef::Commit(sha.clone()),
            ArtifactRef::FileAt(PathBuf::from("src/foo.rs"), sha.clone()),
        ]
    );

    let status = ws.log.get_stored(result.status.cid).await.unwrap().unwrap();
    assert_eq!(
        status.claim.content.artifacts,
        vec![ArtifactRef::Commit(sha)]
    );
}
