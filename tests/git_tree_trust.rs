//! `.design/v0.7-milestone.md` REQ-9/REQ-10 — trusting a file you did not
//! write.
//!
//! The verification chain caught prose edits, signature swaps and truncation.
//! It did not cover the fields a human actually reads: `author`, `subject`,
//! `kind` and `cites` were documented "derived, ignored on read" and never
//! checked, so each could be an arbitrary lie that verified clean. The whole
//! reason this format exists is review in a PR diff — so those are exactly
//! the fields that must not be able to lie.
//!
//! Deleting a whole record was undetectable by construction.

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
        workspace: Anchor::Workspace("genesis".to_string()),
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

/// AC-10. Every human-readable header field, forged to a valid-looking lie,
/// must be rejected -- and the error must name the field, not fail deeper
/// with something about hex or CIDs.
#[test]
fn each_forged_field_is_rejected_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let record =
        git_tree::to_record(&signed(&identity, "bug-42", "an ordinary observation")).unwrap();

    let cases = [
        ("author", "\"author\": \"did:key:zDnaeVICTIM\"", "author"),
        (
            "subject",
            "\"subject\": \"Local(\\\"other-subject\\\")\"",
            "subject",
        ),
        ("kind", "\"kind\": \"Decision\"", "kind"),
        ("cites", "\"cites\": [\"bafyreifabricated\"]", "cites"),
    ];

    for (field, replacement, expected_in_msg) in cases {
        // Replace the whole line for this field, whatever it currently says.
        let forged: String = record
            .lines()
            .map(|l| {
                if l.trim_start().starts_with(&format!("\"{field}\":")) {
                    let indent: String = l.chars().take_while(|c| c.is_whitespace()).collect();
                    format!("{indent}{replacement},")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let err = git_tree::from_record("f.md", &forged).expect_err(&format!(
            "a forged {field} must be rejected, not verified clean"
        ));
        let msg = err.to_string();
        assert!(
            msg.contains(expected_in_msg),
            "the error for a forged {field} must name it: {msg}"
        );
    }
}

/// AC-11. Deleting a whole record from a published file is reported.
#[test]
fn deleting_a_record_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("bug-42"));

    let claims: Vec<_> = ["first", "second", "third"]
        .iter()
        .map(|t| (signed(&identity, "bug-42", t), None))
        .collect();
    let path = git_tree::write_subject(dir.path(), &subject, &claims).unwrap();

    let text = std::fs::read_to_string(&path.path).unwrap();
    let records = git_tree::split_records(&text);
    assert_eq!(records.len(), 3);

    // Remove the middle record, leaving the rest verifying cleanly.
    let kept = format!("{}\n---8<---\n{}", records[0], records[2]);
    std::fs::write(&path.path, kept).unwrap();

    let results = read_all_at(dir.path());
    let reported = results.iter().any(|r| match r {
        Err(e) => e.to_string().contains("removed from this file"),
        Ok(_) => false,
    });
    assert!(
        reported,
        "removing a record must be reported -- it used to leave the remainder \
         verifying cleanly with nothing to indicate anything was gone"
    );
}

/// An intact file reports nothing.
#[test]
fn an_intact_file_reports_no_missing_records() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load_or_create(&dir.path().join("identity")).unwrap();
    let subject = SubjectRef::Local(Rkey::from("bug-42"));
    let claims: Vec<_> = ["first", "second"]
        .iter()
        .map(|t| (signed(&identity, "bug-42", t), None))
        .collect();
    git_tree::write_subject(dir.path(), &subject, &claims).unwrap();

    let results = read_all_at(dir.path());
    let errors: Vec<String> = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
        .collect();
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    assert_eq!(results.len(), 2);
}

/// `GitTree::read_all` needs a `Log`; build one over a temp dir so these
/// tests exercise the real reader rather than a reimplementation of it.
fn read_all_at(
    root: &std::path::Path,
) -> Vec<Result<(atproto_dasl::Cid, kan::claim::Claim), git_tree::Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let identity = Identity::load_or_create(&root.join("reader-identity")).unwrap();
        let log = kan::store::log::Log::open_or_create(&root.join("reader-log"), &identity)
            .await
            .unwrap();
        let tree = git_tree::GitTree::new(log, root.to_path_buf());
        tree.read_all()
    })
}
