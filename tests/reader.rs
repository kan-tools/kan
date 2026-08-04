//! `.design/v0.8-milestone.md` REQ-1/REQ-2, AC-1/AC-2 — kan reading a
//! published claim tree, which through v0.7 it could not do.
//!
//! `GitTree::subscribe` and `read_all` existed with no caller outside their
//! own tests (#97), so three of v0.6's acceptance criteria were demonstrable
//! only by linking the crate. These exercise the shipped binary against a
//! `.claims/` tree written by *another* identity, which is the case the
//! research loop needs and the shape a durability restore reuses.

use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan_as(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir);
    match key {
        Some(k) => {
            cmd.env("KAN_IDENTITY_FILE", k);
        }
        None => {
            cmd.env_remove("KAN_IDENTITY_FILE");
        }
    }
    let output = cmd.output().expect("failed to run kan binary");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ok: output.status.success(),
    }
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

/// A "clone": a fresh repo holding another author's published `.claims/`
/// tree and no log of its own for those claims.
///
/// Built by publishing in one repo and copying `.claims/` across, which is
/// exactly what `git clone` delivers — kan runs no git commands, it reads
/// the tree it is handed.
///
/// Note the published tree holds **two** records per subject, not one:
/// `kan publish` records a `Publication` claim alongside the narrative,
/// because publishing is a decision about a subject and therefore a claim
/// (ADR-43). Assertions below name the claim they mean rather than counting.
fn publisher_then_clone(subject: &str, text: &str) -> (tempfile::TempDir, String) {
    let author_dir = git_repo();
    let author_key = author_dir.path().join("author-key");
    let write = kan_as(
        author_dir.path(),
        Some(&author_key),
        &["observe", subject, text],
    );
    assert!(write.ok, "author write failed: {}", write.stderr);
    let published = kan_as(author_dir.path(), Some(&author_key), &["publish", subject]);
    assert!(published.ok, "publish failed: {}", published.stderr);
    let author_did = kan_as(author_dir.path(), Some(&author_key), &["identity", "did"]).stdout;

    let clone = git_repo();
    let src = author_dir.path().join(".claims");
    let dst = clone.path().join(".claims");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    (clone, author_did)
}

/// AC-1: with a published `.claims/` tree in a clone, a read surfaces its
/// claims — a tree the local log never wrote, folded, with no crate-internal
/// linking. This is #97's three unreachable ACs made reachable.
#[test]
fn a_clone_reads_claims_its_own_log_never_wrote() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");

    // The reader's own identity trusts only itself by default, so the
    // foreign claim is present but not trusted — and the read says so
    // rather than reporting an empty subject as complete.
    let solo = kan_as(clone.path(), None, &["show", "finding", "--json"]);
    assert!(solo.ok, "show failed: {}", solo.stderr);
    let solo: serde_json::Value = serde_json::from_str(&solo.stdout).unwrap();
    assert_eq!(solo["claims"].as_array().unwrap().len(), 0);
    assert_eq!(
        solo["excluded_by_trust"], 2,
        "ingested-but-untrusted claims were invisible AND undisclosed: {solo}"
    );

    // Trusting the publishing author surfaces it, text and attribution
    // intact.
    let trusted = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(trusted.ok, "trusted show failed: {}", trusted.stderr);
    let trusted: serde_json::Value = serde_json::from_str(&trusted.stdout).unwrap();
    let claims = trusted["claims"].as_array().unwrap();
    let observation = claims
        .iter()
        .find(|c| c["kind"] == "Observation")
        .unwrap_or_else(|| panic!("the published observation never arrived: {trusted}"));
    assert_eq!(observation["text"], "the other actor's claim");
    assert_eq!(observation["author"], author_did);
    // The Publication claim rides along, which is how a reader can tell the
    // author *chose* to share this subject rather than inferring it.
    assert!(claims.iter().any(|c| c["kind"] == "Publication"));
}

/// AC-2, the half that matters most: a foreign record lands in the overlay
/// and leaves `log/repo.car` **byte-unchanged**.
///
/// `log/repo.car` is *claims I authored*, which is what atproto repo
/// semantics require and what a future HostedRelay/AppView reads from.
/// Mixing another actor's records into it would make the local log
/// unshippable as a repo, and would do so invisibly.
#[test]
fn ingesting_a_foreign_claim_leaves_the_local_log_byte_unchanged() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");

    // Give the clone a log of its own first, so there is something to leave
    // unchanged.
    let mine = kan_as(clone.path(), None, &["observe", "mine", "my own claim"]);
    assert!(mine.ok, "local write failed: {}", mine.stderr);

    let car = clone.path().join(".kan/log/repo.car");
    let before = std::fs::read(&car).expect("local log should exist");

    // A read that ingests the foreign tree.
    let read = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(read.ok);
    let read: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    assert!(
        read["claims"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "Observation"),
        "the foreign claim was not ingested, so this proves nothing: {read}"
    );

    let after = std::fs::read(&car).unwrap();
    assert_eq!(
        before, after,
        "ingesting a foreign claim rewrote log/repo.car -- the local log is no longer \
         `claims I authored`"
    );

    // And it did land somewhere: the overlay exists and is non-empty.
    let overlay = clone.path().join(".kan/overlay/repo.car");
    assert!(
        overlay.exists() && std::fs::metadata(&overlay).unwrap().len() > 0,
        "the foreign claim was readable but the overlay is empty -- where did it go?"
    );
}

/// AC-2: the ingested record verifies against **its own** author, not the
/// local identity, and its content CID is unchanged by the round trip.
///
/// This is what `Log::append` structurally could not do: it re-signs with
/// the local identity, reproducing the CID and replacing the signature, so
/// the record's own-author verification would then reject it. A round trip
/// that silently invalidates what it stored is worse than a missing feature.
#[test]
fn an_ingested_record_keeps_its_own_signature_and_cid() {
    let author_dir = git_repo();
    let author_key = author_dir.path().join("author-key");
    let write = kan_as(
        author_dir.path(),
        Some(&author_key),
        &["observe", "finding", "signed by the author"],
    );
    assert!(write.ok);
    let original_cid = write.stdout.clone();
    assert!(
        original_cid.starts_with("bafy"),
        "expected a CID: {original_cid}"
    );
    assert!(
        kan_as(
            author_dir.path(),
            Some(&author_key),
            &["publish", "finding"]
        )
        .ok
    );
    let author_did = kan_as(author_dir.path(), Some(&author_key), &["identity", "did"]).stdout;

    let clone = git_repo();
    std::fs::create_dir_all(clone.path().join(".claims")).unwrap();
    for entry in std::fs::read_dir(author_dir.path().join(".claims")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(
            entry.path(),
            clone.path().join(".claims").join(entry.file_name()),
        )
        .unwrap();
    }

    let read = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(read.ok, "{}", read.stderr);
    let read: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    let claim = &read["claims"].as_array().unwrap()[0];

    // Same CID: the content survived the round trip through the tree
    // byte-for-byte. Had anything re-signed or re-stamped it, this differs.
    assert_eq!(
        claim["cid"], original_cid,
        "the ingested claim's CID changed in transit"
    );
    // Attributed to the signing author, not to the reader.
    assert_eq!(claim["author"], author_did);
    let reader_did = kan_as(clone.path(), None, &["identity", "did"]).stdout;
    assert_ne!(
        claim["author"], reader_did,
        "the ingested claim was re-attributed to the reading identity"
    );
}

/// Ingest is idempotent: reading twice does not duplicate a claim — and as
/// of v0.11 a read leaves **no overlay at all**.
///
/// The byte-comparison this used to make is gone because the thing it
/// compared is gone. A read resolves no signing identity (REQ-2), so it
/// cannot write `.kan/overlay` — whose commits that identity signs — and
/// instead projects verified `.claims/` records straight into the disposable
/// index. Asserting the overlay is *absent* is the stronger statement, and it
/// is the property the old one was reaching for: a read that runs on every
/// single invocation must not accumulate anything.
#[test]
fn re_reading_a_published_tree_changes_nothing() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");

    let first = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(first.ok);
    let first_value: serde_json::Value = serde_json::from_str(&first.stdout).unwrap();
    let claim_count = first_value["claims"].as_array().unwrap().len();
    assert!(claim_count > 0, "nothing was ingested: {first_value}");
    let overlay = clone.path().join(".kan/overlay/repo.car");
    assert!(
        !overlay.exists(),
        "a read wrote an overlay, which it has no identity to sign the commits of"
    );

    for _ in 0..3 {
        let again = kan_as(
            clone.path(),
            None,
            &["show", "finding", "--trust", &author_did, "--json"],
        );
        assert!(again.ok);
        let again: serde_json::Value = serde_json::from_str(&again.stdout).unwrap();
        assert_eq!(
            again["claims"].as_array().unwrap().len(),
            claim_count,
            "re-reading duplicated the ingested claims: {again}"
        );
    }

    assert!(
        !overlay.exists(),
        "a re-read created an overlay -- a read acquired a write it should not have"
    );
}

/// A tampered record in `.claims/` is refused, and the workspace still
/// works.
///
/// `.claims/` is *tracked*, so anyone can hand-edit it and a bad merge can
/// mangle it. Two properties matter and they pull in opposite directions:
/// the altered claim must never enter a view, and one broken record must not
/// take out every `kan` command in the repo.
#[test]
fn a_tampered_published_record_is_refused_without_bricking_the_repo() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");

    // Edit the prose a human reads — which is the point of keeping it in the
    // body rather than the frontmatter.
    let claims_dir = clone.path().join(".claims");
    let file = std::fs::read_dir(&claims_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        text.replace("the other actor's claim", "a claim nobody made"),
    )
    .unwrap();

    let read = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(
        read.ok,
        "one tampered record bricked the workspace: {}",
        read.stderr
    );
    let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    assert_eq!(
        value["claims"].as_array().unwrap().len(),
        0,
        "a tampered record was folded into the view: {value}"
    );
    assert!(
        read.stderr.contains("warning"),
        "the tampered record was dropped silently: {}",
        read.stderr
    );
}
