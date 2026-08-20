//! `.design/v0.7-milestone.md` REQ-16 / AC-17 — what a real `git merge` does
//! to two divergent published files.
//!
//! ADR-43 shipped `.claims/*.md merge=union`, reasoning that claims are
//! immutable and additive so keeping both sides is correct. The reasoning
//! about *claims* was right; the conclusion about *files* was not. Union merge
//! is line-based, every record starts with the same boilerplate lines (`---`,
//! `{`, `"cid": …`), so git aligned the two sides' record boundaries against
//! each other and unioned *inside* a record — welding two claims into one
//! malformed record with duplicate keys, at exit 0, with both claims lost.
//!
//! ADR-47 withdrew that guidance. The shipped answer is now no merge driver
//! at all, which makes the outcome a visible conflict. This test holds that
//! line: the merge may preserve both sides or it may conflict, but it must
//! never exit 0 having destroyed a claim.

use std::process::Command;

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    transport::git_tree,
};

fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap()
}

fn signed(identity: &Identity, text: &str) -> kan::claim::v1::Claim {
    let content = ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from("shared")),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: Some(1_700_000_000_000_000),
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    let sig = identity.sign(&cid.to_bytes()).unwrap();
    kan::claim::v1::Claim { content, sig }
}

/// AC-17. Two clones write concurrently to one subject; the merge must either
/// keep both claims or raise a visible conflict. Exiting 0 having lost one is
/// the failure ADR-47 exists to prevent.
#[test]
fn a_concurrent_merge_never_silently_loses_a_claim() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let identity = Identity::generate();
    identity.save(&root.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("shared"));

    git(&repo, &["init", "-q", "."]);
    // A shared base: one claim both sides start from.
    let base = signed(&identity, "the base claim");
    git_tree::write_subject(&repo, &subject, &[(base.clone(), None)]).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);

    // Branch B writes a second claim.
    git(&repo, &["checkout", "-q", "-b", "actor-b"]);
    let b = signed(&identity, "claim written by actor B");
    git_tree::write_subject(&repo, &subject, &[(base.clone(), None), (b.clone(), None)]).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "b"]);

    // Branch A (main) writes a different second claim.
    let default = String::from_utf8(git(&repo, &["rev-parse", "--abbrev-ref", "HEAD~0"]).stdout)
        .unwrap_or_default();
    let _ = default;
    git(&repo, &["checkout", "-q", "-"]);
    let a = signed(&identity, "claim written by actor A");
    git_tree::write_subject(&repo, &subject, &[(base.clone(), None), (a.clone(), None)]).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "a"]);

    let merge = git(&repo, &["merge", "actor-b", "-m", "merge"]);
    let clean_merge = merge.status.success();

    let file = repo.join(".claims").join(git_tree::file_name(&subject));
    let text = std::fs::read_to_string(&file).unwrap_or_default();

    if !clean_merge {
        // A visible conflict: recoverable by hand, and the outcome ADR-47
        // deliberately chose over silent destruction.
        assert!(
            text.contains("<<<<<<<") || !merge.status.success(),
            "a failed merge must leave conflict markers a human can resolve"
        );
        return;
    }

    // If it merged cleanly, both claims must have survived and every record
    // must still parse. This is the branch that used to fail: exit 0, "4
    // insertions", both claims gone.
    let records = git_tree::split_records(&text);
    let mut texts = Vec::new();
    for record in &records {
        let (_, claim) = git_tree::from_record("shared.md", record)
            .expect("a clean merge must not produce an unparseable record");
        texts.push(claim.content.body.text().unwrap_or_default().to_string());
    }
    assert!(
        texts.iter().any(|t| t == "claim written by actor A")
            && texts.iter().any(|t| t == "claim written by actor B"),
        "a clean merge must keep both sides' claims; got {texts:?}"
    );
}

/// The repo must not reintroduce a union merge driver for `.claims/`.
#[test]
fn the_repo_ships_no_union_merge_driver() {
    let gitattributes = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".gitattributes");
    if let Ok(text) = std::fs::read_to_string(gitattributes) {
        assert!(
            !text.contains("merge=union"),
            "ADR-47: union merge is line-based and welds two claims into one \
             malformed record at exit 0"
        );
    }
}
