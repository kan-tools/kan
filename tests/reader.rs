//! `.design/v0.8-milestone.md` REQ-1/REQ-2, AC-1/AC-2 — kan reading a
//! published claim tree, which through v0.7 it could not do.
//!
//! `GitTree::subscribe` and `read_all` existed with no caller outside their
//! own tests (#97), so three of v0.6's acceptance criteria were demonstrable
//! only by linking the crate. These exercise the shipped binary against a
//! `.claims/` tree written by *another* identity, which is the case the
//! research loop needs and the shape a durability restore reuses.

use std::process::Command;

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn first_file(root: &std::path::Path) -> std::path::PathBuf {
    if let Some(entry) = std::fs::read_dir(root).unwrap().next() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            return first_file(&entry.path());
        }
        return entry.path();
    }
    panic!("no published file under {}", root.display());
}

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
    {
        std::fs::create_dir_all(author_key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&author_key).unwrap();
    }
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
    copy_tree(&src, &dst);
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
    {
        std::fs::create_dir_all(author_key.parent().unwrap()).unwrap();
        kan::sign::Identity::generate().save(&author_key).unwrap();
    }
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
    copy_tree(
        &author_dir.path().join(".claims"),
        &clone.path().join(".claims"),
    );

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
    let file = first_file(&claims_dir);
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
    let claims = value["claims"].as_array().unwrap();
    assert!(
        claims.iter().all(|claim| claim["kind"] != "Observation"),
        "the tampered observation was folded into the view: {value}"
    );
    assert!(
        claims.iter().any(|claim| claim["kind"] == "Publication"),
        "an intact sibling record was discarded with the tampered one: {value}"
    );
    assert!(
        read.stderr.contains("warning"),
        "the tampered record was dropped silently: {}",
        read.stderr
    );
    assert_eq!(value["published_read_error_count"], 1);
    let errors = value["published_read_errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    let error = errors[0].as_object().unwrap();
    assert_eq!(error.len(), 3);
    assert_eq!(error["kind"], "cid_mismatch");
    let path = error["path"].as_str().unwrap();
    assert!(path.starts_with(".claims/"), "not repo-relative: {path}");
    assert!(!std::path::Path::new(path).is_absolute());
    assert!(error["message"].as_str().unwrap().contains(path));
}

/// kan#211: degradation happens while opening the workspace, so every JSON
/// read surface must disclose it. Choosing `status` instead of `show` cannot
/// turn the same partial source into an apparently complete response.
#[test]
fn every_json_read_surface_discloses_a_bad_published_record() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");
    let file = first_file(&clone.path().join(".claims"));
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        text.replace("the other actor's claim", "a claim nobody made"),
    )
    .unwrap();

    let invocations: &[&[&str]] = &[
        &["show", "finding", "--trust", &author_did, "--json"],
        &["show", "--all", "--trust", &author_did, "--json"],
        &[
            "show",
            "--json",
            "--subject",
            "finding",
            "--trust",
            &author_did,
        ],
        &["status", "--trust", &author_did, "--json"],
        &["issues", "--trust", &author_did, "--json"],
        &[
            "context",
            "--budget",
            "100",
            "--trust",
            &author_did,
            "--json",
        ],
    ];

    let mut expected = None;
    for args in invocations {
        let read = kan_as(clone.path(), None, args);
        assert!(read.ok, "{args:?} failed: {}", read.stderr);
        assert!(read.stderr.contains("warning: skipping a published record"));
        let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
        assert_eq!(value["published_read_error_count"], 1, "{args:?}: {value}");
        let errors = value["published_read_errors"].clone();
        assert_eq!(errors.as_array().unwrap().len(), 1);
        if let Some(prior) = &expected {
            assert_eq!(&errors, prior, "diagnostics changed across read surfaces");
        } else {
            expected = Some(errors);
        }

        if args.starts_with(&["show", "--all"])
            || (args.first() == Some(&"show") && value.get("matched_subjects").is_some())
        {
            for subject in value["subjects"].as_array().unwrap() {
                assert!(subject.get("published_read_error_count").is_none());
                assert!(subject.get("published_read_errors").is_none());
            }
        }
    }
}

#[test]
fn published_read_errors_are_clone_stable_and_path_ordered() {
    let publisher = git_repo();
    let key = publisher.path().join("author-key");
    kan::sign::Identity::generate().save(&key).unwrap();
    for (subject, text) in [("zeta", "zeta text"), ("alpha", "alpha text")] {
        let write = kan_as(publisher.path(), Some(&key), &["observe", subject, text]);
        assert!(write.ok, "{}", write.stderr);
        let publish = kan_as(publisher.path(), Some(&key), &["publish", subject]);
        assert!(publish.ok, "{}", publish.stderr);
    }

    let source = publisher.path().join(".claims");
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        let subject_dir = entry.path();
        if !subject_dir.is_dir() {
            continue;
        }
        let file = first_file(&subject_dir);
        let text = std::fs::read_to_string(&file).unwrap();
        let tampered = text
            .replace("alpha text", "altered alpha")
            .replace("zeta text", "altered zeta");
        std::fs::write(file, tampered).unwrap();
    }

    let mut diagnostics = Vec::new();
    for _ in 0..2 {
        let clone = git_repo();
        copy_tree(&source, &clone.path().join(".claims"));
        let read = kan_as(clone.path(), None, &["show", "--all", "--json"]);
        assert!(read.ok, "{}", read.stderr);
        let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
        assert_eq!(value["published_read_error_count"], 2, "{value}");
        diagnostics.push(value["published_read_errors"].clone());
    }

    assert_eq!(diagnostics[0], diagnostics[1]);
    let paths: Vec<&str> = diagnostics[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|error| error["path"].as_str().unwrap())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted, "diagnostics do not follow sorted tree order");
}

#[cfg(unix)]
#[test]
fn an_unreadable_claims_subdirectory_is_disclosed_as_an_incomplete_read() {
    use std::os::unix::fs::PermissionsExt;

    let repo = git_repo();
    let hidden = repo.path().join(".claims/hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    std::fs::write(hidden.join("bad.md"), "not a claim").unwrap();

    let original = std::fs::metadata(&hidden).unwrap().permissions();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
    let read = kan_as(repo.path(), None, &["show", "--all", "--json"]);
    std::fs::set_permissions(&hidden, original).unwrap();

    assert!(read.ok, "a degraded read remains nonfatal: {}", read.stderr);
    assert!(
        read.stderr.contains("warning: skipping a published record"),
        "{}",
        read.stderr
    );
    let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    assert_eq!(value["published_read_error_count"], 1, "{value}");
    let errors = value["published_read_errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{value}");
    assert_eq!(errors[0]["kind"], "io");
    assert_eq!(errors[0]["path"], ".claims/hidden");
    assert!(
        errors[0]["message"]
            .as_str()
            .unwrap()
            .starts_with("io error under .claims/hidden:"),
        "{value}"
    );
}

#[test]
fn a_non_directory_claims_root_keeps_the_claims_path_prefix() {
    let repo = git_repo();
    std::fs::write(repo.path().join(".claims"), "not a directory").unwrap();

    let read = kan_as(repo.path(), None, &["show", "--all", "--json"]);
    assert!(read.ok, "a degraded read remains nonfatal: {}", read.stderr);
    let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    assert_eq!(value["published_read_error_count"], 1, "{value}");
    assert_eq!(value["published_read_errors"][0]["kind"], "io");
    assert_eq!(value["published_read_errors"][0]["path"], ".claims/");
    assert!(
        value["published_read_errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains(".claims/"),
        "{value}"
    );
}

/// A read-open and a write-open must agree about index freshness, or every
/// alternation between them rebuilds the whole projection.
///
/// Caught by reviewing the v0.11 diff rather than by any test: the read path
/// computed a `.claims/` content hash into the index fingerprint and the
/// write path did not, so the two computed different fingerprints over the
/// same unchanged workspace. Nothing was *wrong* — every view stayed correct
/// — which is exactly why nothing failed. It would simply have rebuilt the
/// whole projection on every command in any repo with a published tree.
///
/// **The signal is the first read after a write, not two reads in a row.**
/// The first attempt at this test compared two consecutive reads, which
/// agree with each other whatever the write path does — a test that could
/// not fail, confirmed by mutating the write path and watching it pass. What
/// discriminates is whether a read *accepts the projection a write just
/// built*.
#[test]
fn a_read_accepts_the_projection_a_write_just_built() {
    let (clone, author_did) = publisher_then_clone("finding", "the other actor's claim");

    let built_from = || -> Option<String> {
        let conn = rusqlite::Connection::open(clone.path().join(".kan/index.sqlite")).ok()?;
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'built_from_root_v2'",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
    };

    // A write, which maintains `.kan/overlay` and rebuilds the projection.
    let wrote = kan_as(
        clone.path(),
        None,
        &["observe", "a claim of my own", "--subject", "mine"],
    );
    assert!(wrote.ok, "setup write failed: {}", wrote.stderr);
    let after_write = built_from();
    assert!(
        after_write.is_some(),
        "the write recorded nothing for a later read to be fresh against"
    );

    // Nothing has changed, so the read must find that projection fresh and
    // leave it exactly as it is.
    let read = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did],
    );
    assert!(read.ok, "read failed: {}", read.stderr);

    assert_eq!(
        built_from(),
        after_write,
        "a read rebuilt a projection a write had just built over an unchanged workspace, \
         so the two paths disagree about the freshness key -- every alternation between \
         them pays a full rebuild"
    );
}

/// `review/full-pass-v0.12` F3 (REQ-3): a crafted record in the tracked
/// `.claims/` directory — arriving via any merged PR — ran arithmetic and
/// byte-index slicing on untrusted bytes inside `Workspace::open`, before
/// any signature check, and a panic there aborted every kan command in
/// every clone. The module's contract is warn-and-skip; hold it against the
/// three shapes that aborted: an overflowing `text_len`, a frame endpoint
/// inside a multibyte character, and non-ASCII hex.
#[test]
fn a_crafted_record_in_claims_does_not_brick_the_workspace() {
    let (clone, author_did) = publisher_then_clone("finding", "the honest claim");
    let claims_dir = clone.path().join(".claims");

    let crafted = [
        (
            "huge-text-len.md",
            "---\n{\"v\":2,\"cid\":\"bafyreib\",\"sig\":\"aa\",\"author\":\"did:key:z\",\
             \"subject\":\"x\",\"kind\":\"Observation\",\"cites\":[],\
             \"text_len\":18446744073709551615}\n---\n\nbody\n",
        ),
        (
            "mid-char-frame.md",
            "---\n{\"v\":2,\"cid\":\"bafyreib\",\"sig\":\"aa\",\"author\":\"did:key:z\",\
             \"subject\":\"x\",\"kind\":\"Observation\",\"cites\":[],\"text_len\":1}\n---\n\naéb\n",
        ),
        (
            "non-ascii-hex.md",
            "---\n{\"v\":2,\"cid\":\"bafyreib\",\"sig\":\"aéb\",\"author\":\"did:key:z\",\
             \"subject\":\"x\",\"kind\":\"Observation\",\"cites\":[],\"text_len\":4}\n---\n\nbody\n",
        ),
    ];
    for (name, content) in crafted {
        std::fs::write(claims_dir.join(name), content).unwrap();
    }

    // Every command used to abort with exit 101 before any signature check.
    let status = kan_as(clone.path(), None, &["status"]);
    assert!(
        status.ok,
        "a crafted .claims/ record bricked `kan status`: {}",
        status.stderr
    );
    let read = kan_as(
        clone.path(),
        None,
        &["show", "finding", "--trust", &author_did, "--json"],
    );
    assert!(
        read.ok,
        "a crafted .claims/ record bricked `kan show`: {}",
        read.stderr
    );
    let value: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    let claims = value["claims"].as_array().unwrap();
    assert!(
        claims
            .iter()
            .any(|c| c["text"].as_str() == Some("the honest claim")),
        "the honest, verified claim must still fold while the crafted \
         records are skipped: {value}"
    );
    assert!(
        claims.iter().all(|c| c["subject"] == "finding"),
        "nothing from the crafted records may enter the view: {value}"
    );
}
