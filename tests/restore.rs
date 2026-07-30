//! `.design/v0.9-milestone.md` REQ-1/REQ-2, AC-1/AC-2 — rebuilding a log
//! from the published tree, and refusing to when the identity is wrong.
//!
//! kan's source of truth is one gitignored directory with exactly one copy on
//! one machine (#88). `.claims/` holds whatever was published, as complete
//! signed records — so it can be rebuilt from rather than merely read. This
//! is the inverse of `publish`, using v0.8's `Log::ingest` pointed at
//! `log/repo.car` instead of the overlay.

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

fn copy_claims(from: &std::path::Path, to: &std::path::Path) {
    let dst = to.join(".claims");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(from.join(".claims")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
}

/// AC-1: with `.kan/` deleted, `kan restore` rebuilds the log from
/// `.claims/`, and every restored claim reads back with its original CID and
/// author.
///
/// The deletion is the point. This is #88's scenario — one gitignored
/// directory, one copy, one machine — and until now the answer to losing it
/// was that the claims were visible in git and unusable by kan.
#[test]
fn a_deleted_log_is_rebuilt_from_the_published_tree() {
    let dir = git_repo();
    let key = dir.path().join("mykey");

    let first = kan_as(dir.path(), Some(&key), &["observe", "task", "the finding"]);
    assert!(first.ok, "{}", first.stderr);
    let original_cid = first.stdout.clone();
    assert!(kan_as(dir.path(), Some(&key), &["publish", "task"]).ok);
    let did = kan_as(dir.path(), Some(&key), &["identity", "did"]).stdout;

    // Lose the store, keep the tracked tree and the key.
    std::fs::remove_dir_all(dir.path().join(".kan")).unwrap();
    let gone = kan_as(dir.path(), Some(&key), &["show", "task", "--json"]);
    assert!(gone.ok);
    let gone: serde_json::Value = serde_json::from_str(&gone.stdout).unwrap();
    assert_eq!(
        gone["claims"].as_array().unwrap().len(),
        0,
        "the log was not actually lost, so this proves nothing"
    );

    let restored = kan_as(dir.path(), Some(&key), &["restore"]);
    assert!(restored.ok, "restore failed: {}", restored.stderr);
    assert!(
        restored.stdout.contains("restored"),
        "restore said nothing about what it did: {}",
        restored.stdout
    );

    let back = kan_as(dir.path(), Some(&key), &["show", "task", "--json"]);
    assert!(back.ok, "{}", back.stderr);
    let back: serde_json::Value = serde_json::from_str(&back.stdout).unwrap();
    let observation = back["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "Observation")
        .unwrap_or_else(|| panic!("the restored claim is missing: {back}"));
    assert_eq!(observation["text"], "the finding");
    assert_eq!(observation["author"], did);
    assert_eq!(
        observation["cid"], original_cid,
        "the restored claim's CID changed -- it was re-signed, not restored"
    );
}

/// AC-1's **negative control**: the restored `log/repo.car` holds only this
/// identity's records. A foreign-authored record in the same tree goes to the
/// overlay, exactly as it does on a normal read.
///
/// Without this the test above would pass just as well against a restore that
/// hoovered up everything in the tree — which would quietly make `log/` stop
/// meaning "claims I authored" and break the atproto repo semantics ADR-59
/// went to some trouble to preserve.
#[test]
fn restore_takes_only_this_identitys_claims_into_the_log() {
    // Another actor publishes.
    let other = git_repo();
    let other_key = other.path().join("otherkey");
    assert!(
        kan_as(
            other.path(),
            Some(&other_key),
            &["observe", "their-task", "their finding"]
        )
        .ok
    );
    assert!(kan_as(other.path(), Some(&other_key), &["publish", "their-task"]).ok);
    let other_did = kan_as(other.path(), Some(&other_key), &["identity", "did"]).stdout;

    // I publish into my own repo, then take their tree too. Distinct
    // subjects on purpose: a published file is named per *subject*, so two
    // actors publishing the SAME subject into one tree collide on one
    // filename, which is a tree-merge question rather than a restore one.
    let mine = git_repo();
    let my_key = mine.path().join("mykey");
    assert!(
        kan_as(
            mine.path(),
            Some(&my_key),
            &["observe", "my-task", "my finding"]
        )
        .ok
    );
    assert!(kan_as(mine.path(), Some(&my_key), &["publish", "my-task"]).ok);
    let my_did = kan_as(mine.path(), Some(&my_key), &["identity", "did"]).stdout;
    copy_claims(other.path(), mine.path());

    std::fs::remove_dir_all(mine.path().join(".kan")).unwrap();
    let restored = kan_as(mine.path(), Some(&my_key), &["restore"]);
    assert!(restored.ok, "{}", restored.stderr);

    // Mine came back through the log.
    let solo = kan_as(mine.path(), Some(&my_key), &["show", "my-task", "--json"]);
    let solo: serde_json::Value = serde_json::from_str(&solo.stdout).unwrap();
    let authors: Vec<&str> = solo["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["author"].as_str().unwrap())
        .collect();
    assert!(
        !authors.is_empty() && authors.iter().all(|a| *a == my_did),
        "the default view should hold only my restored claims: {solo}"
    );

    // Theirs is readable, but from the overlay — `log/repo.car` never took
    // it. Asserted structurally rather than by counting: the overlay exists
    // and their claim is visible only when their DID is trusted.
    let theirs = kan_as(
        mine.path(),
        Some(&my_key),
        &["show", "their-task", "--trust", &other_did, "--json"],
    );
    let theirs: serde_json::Value = serde_json::from_str(&theirs.stdout).unwrap();
    assert!(
        theirs["claims"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["text"] == "their finding"),
        "the other actor's claim should still be readable: {theirs}"
    );
    let overlay = mine.path().join(".kan/overlay/repo.car");
    assert!(
        overlay.exists() && std::fs::metadata(&overlay).unwrap().len() > 0,
        "their claim was readable but the overlay is empty -- it went into my log"
    );
}

/// AC-2: restore against a tree authored entirely by a different DID exits
/// non-zero, writes nothing, and names the recovery phrase.
///
/// This is the case REQ-2 exists for, and it is not hypothetical: it is what
/// a lost signing key looks like from the inside. You point restore at a tree
/// full of your own past work, a freshly-minted identity reads it as someone
/// else's, and a silently-empty restore would confirm the data is gone rather
/// than reveal that the *identity* is what went missing.
#[test]
fn restore_refuses_when_nothing_in_the_tree_is_mine() {
    let other = git_repo();
    let other_key = other.path().join("otherkey");
    assert!(
        kan_as(
            other.path(),
            Some(&other_key),
            &["observe", "task", "their finding"]
        )
        .ok
    );
    assert!(kan_as(other.path(), Some(&other_key), &["publish", "task"]).ok);

    let mine = git_repo();
    let my_key = mine.path().join("mykey");
    copy_claims(other.path(), mine.path());
    // Mint my identity without writing anything, so the log is empty.
    assert!(kan_as(mine.path(), Some(&my_key), &["identity", "did"]).ok);

    let refused = kan_as(mine.path(), Some(&my_key), &["restore"]);
    assert!(
        !refused.ok,
        "restore accepted a tree with none of my claims in it: {}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("kan identity restore"),
        "the refusal must name the recovery path: {}",
        refused.stderr
    );

    // Nothing written: the log is still absent or empty.
    let car = mine.path().join(".kan/log/repo.car");
    let empty = !car.exists() || std::fs::metadata(&car).unwrap().len() == 0;
    assert!(empty, "a refused restore still wrote to the log");
}

/// Restore is idempotent: running it twice restores nothing the second time
/// and says so, rather than duplicating or erroring.
#[test]
fn restoring_twice_is_a_no_op_the_second_time() {
    let dir = git_repo();
    let key = dir.path().join("mykey");
    assert!(kan_as(dir.path(), Some(&key), &["observe", "task", "the finding"]).ok);
    assert!(kan_as(dir.path(), Some(&key), &["publish", "task"]).ok);
    std::fs::remove_dir_all(dir.path().join(".kan")).unwrap();

    let first = kan_as(dir.path(), Some(&key), &["restore"]);
    assert!(first.ok, "{}", first.stderr);
    let car = dir.path().join(".kan/log/repo.car");
    let after_first = std::fs::read(&car).unwrap();

    let second = kan_as(dir.path(), Some(&key), &["restore"]);
    assert!(second.ok, "{}", second.stderr);
    assert!(
        second.stdout.contains("already in the log"),
        "a second restore should say it found nothing new: {}",
        second.stdout
    );
    assert_eq!(
        after_first,
        std::fs::read(&car).unwrap(),
        "a second restore rewrote the log"
    );
}

/// Restoring where there is no `.claims/` at all says so plainly, rather than
/// reporting a successful restore of nothing.
#[test]
fn restore_without_a_published_tree_says_so() {
    let dir = git_repo();
    let key = dir.path().join("mykey");
    assert!(kan_as(dir.path(), Some(&key), &["observe", "task", "unpublished"]).ok);

    let run = kan_as(dir.path(), Some(&key), &["restore"]);
    assert!(!run.ok, "restore reported success with nothing to restore");
    assert!(
        run.stderr.contains(".claims"),
        "the message should name what is missing: {}",
        run.stderr
    );
}
