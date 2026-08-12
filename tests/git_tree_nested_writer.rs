//! The writer flip: `.claims/<subject>/<author>.md`, v3 records.
//!
//! `.design/published-claims-format-and-wire-contract.md` REQ-1, REQ-2, REQ-11.
//! The reader shipped a release ahead of this (v0.12.0-beta.5), which is what
//! makes the flip safe: a clone one release old can already read what this
//! writes.
//!
//! kan#131 is the reason. Measured before the change, a second author's
//! `publish` silently removed the first author's records from the tracked tree
//! and re-publishing ping-ponged them back, because the file was keyed on the
//! subject alone and the kan#111 guard had nothing to object to — the subject
//! really was the same. Under this layout two authors never address the same
//! path, so the failure is unreachable rather than defended against.

use std::path::Path;

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

fn leaf(identity: &Identity) -> String {
    identity
        .did()
        .strip_prefix("did:key:")
        .expect("a did:key identity")
        .to_string()
}

fn read_back(root: &Path) -> Vec<(String, String)> {
    git_tree::GitTree::new_reader(root)
        .read_all()
        .into_iter()
        .map(|r| r.expect("every written record must read back"))
        .map(|(_, claim)| {
            (
                claim.content.author.did.clone(),
                claim.content.body.text().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[test]
fn a_write_lands_at_the_subjects_own_path_under_the_authors_name() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let claim = signed(&id, "telos/legible-process", "a finding");

    let written =
        git_tree::write_subject(dir.path(), &claim.content.subject, &[(claim.clone(), None)])
            .unwrap();

    let expected = dir
        .path()
        .join(".claims")
        .join("telos")
        .join("legible-process")
        .join(format!("{}.md", leaf(&id)));
    assert_eq!(written.paths, vec![expected.clone()]);
    assert!(expected.exists(), "no digest, no flattening");
}

#[test]
fn two_authors_in_one_log_get_one_file_each() {
    // A workspace can sign with several identities — role keys all append to
    // one log — so `publish` hands the writer every live claim on the subject
    // regardless of who signed it. The flat layout put them in one file. Here
    // they must not: one author's records overwriting another's is the failure
    // this layout removes for peers, and it would be no better inside a
    // workspace.
    let dir = tempfile::tempdir().unwrap();
    let director = Identity::generate();
    let prover = Identity::generate();
    let subject = SubjectRef::Local(Rkey::from("work"));

    let written = git_tree::write_subject(
        dir.path(),
        &subject,
        &[
            (signed(&director, "work", "the director's claim"), None),
            (signed(&prover, "work", "the prover's claim"), None),
        ],
    )
    .unwrap();

    assert_eq!(written.paths.len(), 2, "one file per author: {written:?}");
    let mut got = read_back(dir.path());
    got.sort();
    assert_eq!(got.len(), 2);
    assert!(got.iter().any(|(_, t)| t == "the director's claim"));
    assert!(got.iter().any(|(_, t)| t == "the prover's claim"));
}

#[test]
fn a_second_author_publishing_cannot_touch_the_first_authors_file() {
    // kan#131, made unreachable rather than guarded.
    let dir = tempfile::tempdir().unwrap();
    let alice = Identity::generate();
    let bob = Identity::generate();
    let subject = SubjectRef::Local(Rkey::from("work"));

    let a = git_tree::write_subject(
        dir.path(),
        &subject,
        &[(signed(&alice, "work", "alice's finding"), None)],
    )
    .unwrap();
    let alice_bytes = std::fs::read(a.path()).unwrap();

    git_tree::write_subject(
        dir.path(),
        &subject,
        &[(signed(&bob, "work", "bob's finding"), None)],
    )
    .unwrap();

    assert_eq!(
        std::fs::read(a.path()).unwrap(),
        alice_bytes,
        "alice's file must be byte-identical after bob publishes"
    );
    assert_eq!(read_back(dir.path()).len(), 2, "both readable");
}

#[test]
fn the_writer_now_emits_v3() {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let claim = signed(&id, "work", "a finding");
    let subject = claim.content.subject.clone();
    let written = git_tree::write_subject(dir.path(), &subject, &[(claim, None)]).unwrap();

    let text = std::fs::read_to_string(written.path()).unwrap();
    assert!(text.contains("\"v\": 3"), "records are v3 now");
    assert!(
        !text.contains(r#"Local(""#),
        "and carry no Debug-shaped subject"
    );
}

#[test]
fn a_flat_file_of_this_authors_own_records_is_retired() {
    // The migration: an author's own records move to the new layout on their
    // next publish, and the file they came from goes, so a subject does not
    // end up with two files that diverge.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let subject = SubjectRef::Local(Rkey::from("work"));
    let claim = signed(&id, "work", "written under the old layout");

    let flat = dir
        .path()
        .join(".claims")
        .join(git_tree::file_name(&subject));
    std::fs::create_dir_all(flat.parent().unwrap()).unwrap();
    std::fs::write(
        &flat,
        git_tree::to_record_at(&claim, None, Some((0, 1))).unwrap(),
    )
    .unwrap();

    let written = git_tree::write_subject(dir.path(), &subject, &[(claim, None)]).unwrap();
    assert_eq!(written.retired.as_deref(), Some(flat.as_path()));
    assert!(!flat.exists(), "the superseded flat file is gone");
    assert_eq!(read_back(dir.path()).len(), 1, "and nothing was lost");
}

#[test]
fn a_flat_file_holding_a_peers_records_is_never_retired() {
    // THE DANGEROUS CASE. Under the flat layout a subject had one file that
    // `publish` rewrote whole, so a peer's records can be sitting in it right
    // now — the multi-actor probe measured exactly that. Deleting it while
    // migrating would destroy claims this author never wrote and cannot
    // re-create, which is the act the non-negotiable invariant forbids.
    let dir = tempfile::tempdir().unwrap();
    let alice = Identity::generate();
    let bob = Identity::generate();
    let subject = SubjectRef::Local(Rkey::from("work"));

    let flat = dir
        .path()
        .join(".claims")
        .join(git_tree::file_name(&subject));
    std::fs::create_dir_all(flat.parent().unwrap()).unwrap();
    std::fs::write(
        &flat,
        git_tree::to_record_at(
            &signed(&bob, "work", "bob's published claim"),
            None,
            Some((0, 1)),
        )
        .unwrap(),
    )
    .unwrap();
    let bob_bytes = std::fs::read(&flat).unwrap();

    // Alice publishes the same subject. Her records move to the new layout;
    // Bob's file is not hers to delete.
    let written = git_tree::write_subject(
        dir.path(),
        &subject,
        &[(signed(&alice, "work", "alice's claim"), None)],
    )
    .unwrap();

    assert_eq!(written.retired, None, "a peer's file must not be retired");
    assert_eq!(
        std::fs::read(&flat).unwrap(),
        bob_bytes,
        "and must be left byte-identical"
    );
    assert_eq!(
        read_back(dir.path()).len(),
        2,
        "both authors still readable, one per layout"
    );
}

#[test]
fn a_subject_that_cannot_be_a_path_is_refused_rather_than_escaping() {
    // Containment: a subject name must never decide where a write lands.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate();
    let subject = SubjectRef::Local(Rkey::from("../../etc/passwd"));
    let claim = signed(&id, "../../etc/passwd", "hostile");

    let err = git_tree::write_subject(dir.path(), &subject, &[(claim, None)])
        .expect_err("a traversing subject must not be written");
    assert!(
        err.to_string().contains("cannot be expressed as a path"),
        "and should say why: {err}"
    );
}
