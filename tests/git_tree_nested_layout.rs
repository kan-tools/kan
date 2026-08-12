//! The nested `.claims/<subject>/<author>.md` layout, reader side.
//!
//! `.design/published-claims-format-and-wire-contract.md` REQ-1..REQ-4, REQ-9,
//! REQ-14. **The writer still emits the flat layout** — same reader-before-writer
//! ordering as the v3 record format: a tree written in a layout no released kan
//! can discover is unreadable by every clone that has not upgraded.
//!
//! Why the layout changes at all, measured rather than argued: with one file per
//! subject, a second author's `kan publish` silently removed the first author's
//! records from the tracked tree, and re-publishing ping-ponged them back
//! (kan#131). The existing kan#111 guard cannot object, because the file really
//! is that subject's — the subject is the same, only the author differs. Under
//! this layout two authors never address the same path, so the failure is
//! unreachable rather than defended against.

use std::path::Path;

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    transport::git_tree::{self, GitTree},
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

/// Place a record at an explicit path under `.claims/`, which is what the
/// writer will eventually do and does not do yet.
fn place(root: &Path, relative: &str, claim: &kan::claim::Claim) {
    let path = root.join(".claims").join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = git_tree::to_record_at(claim, None, Some((0, 1))).unwrap();
    std::fs::write(path, record).unwrap();
}

fn read_subjects(root: &Path) -> Vec<String> {
    GitTree::new_reader(root)
        .read_all()
        .into_iter()
        .filter_map(|r| r.ok())
        .map(|(_, claim)| match claim.content.subject {
            SubjectRef::Local(rkey) => rkey,
            other => format!("{other:?}"),
        })
        .collect()
}

fn errors(root: &Path) -> Vec<String> {
    GitTree::new_reader(root)
        .read_all()
        .into_iter()
        .filter_map(|r| r.err())
        .map(|e| e.to_string())
        .collect()
}

#[test]
fn a_nested_record_is_discovered_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let claim = signed(&identity, "work", "a finding");
    place(dir.path(), &format!("work/{}.md", leaf(&identity)), &claim);

    assert_eq!(read_subjects(dir.path()), vec!["work".to_string()]);
    assert!(errors(dir.path()).is_empty(), "{:?}", errors(dir.path()));
}

#[test]
fn a_subject_with_slashes_nests_rather_than_flattening() {
    // The collision the digest existed to repair: `telos/legible-process` and
    // `telos_legible-process` shared one flat file, and `telos/<slug>` is
    // day's own naming convention (ADR-42).
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let a = signed(&identity, "telos/legible-process", "the real one");
    let b = signed(&identity, "telos_legible-process", "the impostor");
    place(
        dir.path(),
        &format!("telos/legible-process/{}.md", leaf(&identity)),
        &a,
    );
    place(
        dir.path(),
        &format!("telos_legible-process/{}.md", leaf(&identity)),
        &b,
    );

    let mut subjects = read_subjects(dir.path());
    subjects.sort();
    assert_eq!(
        subjects,
        vec![
            "telos/legible-process".to_string(),
            "telos_legible-process".to_string()
        ],
        "both must survive, in distinct paths, with no digest to tell them apart"
    );
}

#[test]
fn two_authors_on_one_subject_do_not_share_a_path() {
    // kan#131, made unreachable. Both files exist simultaneously; neither
    // write could have addressed the other.
    let dir = tempfile::tempdir().unwrap();
    let alice = Identity::generate();
    let bob = Identity::generate();
    place(
        dir.path(),
        &format!("work/{}.md", leaf(&alice)),
        &signed(&alice, "work", "alice's finding"),
    );
    place(
        dir.path(),
        &format!("work/{}.md", leaf(&bob)),
        &signed(&bob, "work", "bob's finding"),
    );

    assert_eq!(read_subjects(dir.path()).len(), 2, "both authors readable");
    assert!(errors(dir.path()).is_empty(), "{:?}", errors(dir.path()));
}

#[test]
fn a_record_under_the_wrong_subject_directory_is_refused() {
    // REQ-14's first half. Without it the directory name is decorative and a
    // `.claims/x/…` full of subject-`y` claims folds as `y` in silence.
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let claim = signed(&identity, "work", "a finding");
    place(
        dir.path(),
        &format!("something-else/{}.md", leaf(&identity)),
        &claim,
    );

    let errs = errors(dir.path());
    assert!(
        errs.iter()
            .any(|e| e.contains("does not describe its contents")),
        "a misplaced record must be reported. got: {errs:?}"
    );
    assert!(
        read_subjects(dir.path()).is_empty(),
        "and must not be folded"
    );
}

#[test]
fn a_record_under_another_authors_leaf_is_refused() {
    // REQ-14's second half, which the design did not originally state and the
    // build surfaced: the nested path carries the author too, so a file
    // bearing one author's name must not hold another's records.
    let dir = tempfile::tempdir().unwrap();
    let alice = Identity::generate();
    let bob = Identity::generate();
    place(
        dir.path(),
        &format!("work/{}.md", leaf(&bob)),
        &signed(&alice, "work", "alice's claim under bob's name"),
    );

    let errs = errors(dir.path());
    assert!(
        errs.iter()
            .any(|e| e.contains("does not describe its contents")),
        "an author mismatch must be reported. got: {errs:?}"
    );
    assert!(read_subjects(dir.path()).is_empty());
}

#[test]
fn a_subject_and_its_child_subject_coexist() {
    // `a` is a directory holding author files; `a/b` is a directory beside
    // them. Nothing about the layout forbids a subject that is also a prefix
    // of another.
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    place(
        dir.path(),
        &format!("a/{}.md", leaf(&identity)),
        &signed(&identity, "a", "the parent"),
    );
    place(
        dir.path(),
        &format!("a/b/{}.md", leaf(&identity)),
        &signed(&identity, "a/b", "the child"),
    );

    let mut subjects = read_subjects(dir.path());
    subjects.sort();
    assert_eq!(subjects, vec!["a".to_string(), "a/b".to_string()]);
    assert!(errors(dir.path()).is_empty(), "{:?}", errors(dir.path()));
}

#[test]
fn the_flat_layout_still_reads_alongside_the_nested_one() {
    // Not a deprecation window. An author cannot rewrite a peer's file under
    // the new layout, so the flat one is a contract to keep reading.
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();

    let flat = signed(&identity, "legacy", "written by an older kan");
    let flat_path = dir
        .path()
        .join(".claims")
        .join(git_tree::file_name(&flat.content.subject));
    std::fs::create_dir_all(flat_path.parent().unwrap()).unwrap();
    std::fs::write(
        &flat_path,
        git_tree::to_record_at(&flat, None, Some((0, 1))).unwrap(),
    )
    .unwrap();

    place(
        dir.path(),
        &format!("modern/{}.md", leaf(&identity)),
        &signed(&identity, "modern", "written by a newer kan"),
    );

    let mut subjects = read_subjects(dir.path());
    subjects.sort();
    assert_eq!(
        subjects,
        vec!["legacy".to_string(), "modern".to_string()],
        "every claim from both layouts, exactly once"
    );
    assert!(errors(dir.path()).is_empty(), "{:?}", errors(dir.path()));
}

#[test]
fn a_subject_that_would_escape_the_claims_directory_has_no_path() {
    // Containment, not tidiness. The writer does not use `subject_path` yet;
    // the guard lands with the mapping so that whichever call site adopts it
    // cannot let a subject name decide where a write goes.
    for hostile in [
        "../../etc/passwd",
        "..",
        ".",
        "/absolute",
        "a//b",
        "",
        "a/../../b",
        "a/./b",
    ] {
        assert!(
            git_tree::subject_path(&SubjectRef::Local(Rkey::from(hostile))).is_none(),
            "{hostile:?} must not map to a path"
        );
    }
}

#[test]
fn an_ordinary_subject_maps_to_its_own_name() {
    for (subject, expected) in [
        ("work", "work"),
        ("telos/legible-process", "telos/legible-process"),
        ("agents/handoff/main", "agents/handoff/main"),
    ] {
        let path = git_tree::subject_path(&SubjectRef::Local(Rkey::from(subject)))
            .unwrap_or_else(|| panic!("{subject} should map"));
        assert_eq!(path, Path::new(expected), "no digest, no flattening");
    }
}

#[test]
fn an_anchor_subject_gets_a_declared_path_not_a_debug_one() {
    // REQ-7: `format!("{anchor:?}")` in a PATH is the same wire-contract
    // defect one layer over — a variant rename orphans every published file.
    let path = git_tree::subject_path(&SubjectRef::Anchor(Anchor::Commit("abc123".into())))
        .expect("an anchor subject should map");
    let rendered = path.to_string_lossy().to_string();
    assert!(
        rendered.starts_with("anchor/"),
        "anchors are namespaced: {rendered}"
    );
    assert!(
        !rendered.contains("Commit("),
        "no Debug output in a path: {rendered}"
    );
}
