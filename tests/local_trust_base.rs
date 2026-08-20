//! `.design/identity-surface.md` REQ-1/6/7 — `TrustBase::Local` as the base
//! every read folds under when no `--trust` argument is given.
//!
//! AC-2, AC-8 and AC-10 are pinned where their subject matter already lives
//! (`tests/multi_role.rs`, `tests/trust_surface.rs`, `tests/identity_adopt.rs`
//! — each of which previously asserted the `Solo` default and now asserts its
//! replacement). This file carries the two that had nowhere to go: the legacy
//! `agent` author (AC-5) and the boundary between the log and the overlay
//! (AC-6).

use std::process::Command;

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    fold::{self, TrustBase},
    sign::Identity,
    store::{index::Index, log::Log},
};

fn content(author: AuthorId, subject: &str, text: &str) -> ClaimContent {
    ClaimContent {
        author,
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

fn texts(view: &fold::FoldedView, subject: &str) -> Vec<String> {
    view.subject(&SubjectRef::Local(Rkey::from(subject)))
        .map(|c| {
            c.claims
                .iter()
                .filter_map(|(_, claim)| match &claim.content.body {
                    ClaimBody::Observation { text } => Some(text.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// AC-5 / REQ-7: a log holding claims under `AuthorId { did: D, agent:
/// Some(h) }` **and** under `{ did: D, agent: None }` returns all of them
/// under the default read, with no `--trust` argument and no adopt step.
///
/// This is #136. `KAN_AGENT` (v0.2–v0.6) hashed an environment variable into
/// `AuthorId.agent`, and because `Solo` trusts exactly one whole `AuthorId`,
/// setting it partitioned the log: claims written under one value were
/// invisible to every read under another, each view reporting a
/// complete-looking answer. The variable is gone (v0.7 REQ-6) but the claims
/// it wrote are in real logs forever, and they are not recoverable by
/// retraction — they are somebody's record.
///
/// `Local` reaches them with **no DID-matching special case**: the legacy
/// author is trusted for having written into this log, exactly like any
/// other author. The `Solo` half below is the negative control, and it is
/// what makes this test able to fail — it is the behaviour being replaced.
#[tokio::test]
async fn ac5_legacy_agent_authors_are_visible_under_local() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let did = identity.did();

    let modern = AuthorId {
        did: did.clone(),
        agent: None,
    };
    let legacy = AuthorId {
        did: did.clone(),
        agent: Some(vec![0xde, 0xad, 0xbe, 0xef]),
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    log.append(
        content(legacy.clone(), "work", "written under KAN_AGENT"),
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(modern.clone(), "work", "written after it was removed"),
        &identity,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let mut index = Index::open(&dir.path().join("index.sqlite")).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();

    // Both `AuthorId`s are members: the agent is carried, not collapsed.
    let authors = index.log_authors().unwrap();
    assert_eq!(authors.len(), 2, "expected both author shapes: {authors:?}");
    assert!(
        authors.contains(&legacy),
        "the legacy author is missing: {authors:?}"
    );
    assert!(
        authors.contains(&modern),
        "the modern author is missing: {authors:?}"
    );

    let under_local = fold::fold(
        index.all_stored_claims().unwrap(),
        &TrustBase::local(authors),
    );
    let mut seen = texts(&under_local, "work");
    seen.sort();
    assert_eq!(
        seen,
        vec![
            "written after it was removed".to_string(),
            "written under KAN_AGENT".to_string()
        ],
        "Local dropped a claim that is in this very log"
    );

    // The negative control: the base this replaces still partitions the log,
    // which is both #136 and the proof that the assertion above discriminates.
    let under_solo = fold::fold(
        index.all_stored_claims().unwrap(),
        &TrustBase::solo(modern.clone()),
    );
    assert_eq!(
        texts(&under_solo, "work"),
        vec!["written after it was removed".to_string()],
        "Solo was expected to hide the legacy-agent claim -- if it no longer does, the \
         Local assertion above proves nothing"
    );
}

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

fn kan(dir: &std::path::Path, args: &[&str]) -> (String, String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// AC-6 / REQ-6: a `.claims/` file authored by a DID that has never written
/// to this log is **excluded** from the default read, **disclosed** in
/// `excluded_by_trust`, and **admitted** by naming that DID in `--trust`.
///
/// This is the boundary that keeps `Local` from meaning "everything present"
/// (RQ-2). Foreign claims already arrive without sync — as `.claims/` files
/// committed to the repo and ingested into `.kan/overlay` — so a merged pull
/// request carrying a claims file would otherwise inject a stranger's claims
/// into the maintainer's default view, silently and with the maintainer's own
/// tooling reporting a complete-looking answer.
///
/// The line is not a storage convenience: **the log is what was written
/// *through* this workspace; the overlay is what *arrived at* it as a file.**
#[test]
fn ac6_a_stranger_in_claims_is_excluded_disclosed_and_admissible() {
    let dir = git_repo();

    // This workspace's own claim, written through it, on the same subject --
    // so what follows is about *authorship*, not about an unknown subject.
    let (_, stderr, ok) = kan(dir.path(), &["observe", "shared", "written here"]);
    assert!(ok, "setup write failed: {stderr}");

    // A stranger's record arrives as a committed file. Nobody in this
    // workspace has ever seen this DID.
    let stranger = Identity::generate();
    let stranger_did = stranger.did();
    let subject = SubjectRef::Local(Rkey::from("shared"));
    let content = content(
        AuthorId {
            did: stranger_did.clone(),
            agent: None,
        },
        "shared",
        "arrived as a file",
    );
    let cid = kan::cid::content_cid(&content).unwrap();
    let claim = kan::claim::v1::Claim {
        content,
        sig: stranger.sign(&cid.to_bytes()).unwrap(),
    };
    kan::transport::git_tree::write_subject(dir.path(), &subject, &[(claim, None)]).unwrap();

    let read = |args: &[&str]| -> serde_json::Value {
        let (stdout, stderr, ok) = kan(dir.path(), args);
        assert!(ok, "kan {args:?} failed: {stderr}");
        serde_json::from_str(&stdout).expect("--json did not emit valid JSON")
    };

    let default = read(&["show", "shared", "--json"]);
    assert_eq!(default["trust"]["base"], "Local");
    let default_texts: Vec<&str> = default["claims"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect();
    assert_eq!(
        default_texts,
        vec!["written here"],
        "a stranger's committed claims file entered the default view: {default}"
    );
    assert_eq!(
        default["excluded_by_trust"], 1,
        "the stranger's claim was excluded without being disclosed, which is the \
         difference between a filtered view and an absent one: {default}"
    );
    assert!(
        !default["trust"]["authors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["did"] == stranger_did.as_str()),
        "an overlay author is a member of Local: {default}"
    );

    // Admitted only on an explicit ask, and then it is really there.
    let mine = default["trust"]["authors"][0]["did"]
        .as_str()
        .unwrap()
        .to_string();
    let widened = read(&[
        "show",
        "shared",
        "--json",
        "--trust",
        &mine,
        "--trust",
        &stranger_did,
    ]);
    let widened_texts: Vec<&str> = widened["claims"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect();
    assert_eq!(
        widened_texts.len(),
        2,
        "naming the DID did not admit it: {widened}"
    );
    assert!(widened_texts.contains(&"arrived as a file"));
    assert_eq!(widened["excluded_by_trust"], 0);
}
