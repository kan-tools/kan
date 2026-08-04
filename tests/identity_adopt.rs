//! `.design/v0.9-milestone.md` REQ-8/AC-6 — `kan identity adopt`, the
//! supported way back from a lost identity (issue #90).
//!
//! v0.8 made this state *visible*: a workspace whose claims belong to an
//! identity it can no longer act as reports `excluded_by_trust` instead of
//! looking empty (ADR-57). It did not make it *recoverable* — the documented
//! way out was still editing `.kan/identity-id` from a stack trace. This is
//! the other half.

use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan(dir: &std::path::Path, key: Option<&std::path::Path>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir).env("KAN_NO_KEYCHAIN", "1");
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

/// A workspace in #90's end state: claims authored by a key the workspace's
/// *current* identity is not.
///
/// Built the way it actually happens — the log is written under one key, and
/// the identity kan would resolve is a different one — rather than by
/// corrupting anything.
fn orphaned_workspace() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = git_repo();
    let real_key = dir.path().join("the-real-key");
    let other_key = dir.path().join("some-other-key");
    let stranger = dir.path().join("stranger");
    // All minted while the log is empty. Minting later would trip the #90
    // guard -- correctly, but that is a different test than this one.
    for key in [&real_key, &other_key, &stranger] {
        assert!(kan(dir.path(), Some(key), &["identity", "did"]).ok);
    }

    for i in 1..=3 {
        let run = kan(
            dir.path(),
            Some(&real_key),
            &["observe", "work", &format!("claim {i}")],
        );
        assert!(run.ok, "{}", run.stderr);
    }
    // The workspace's own resolved identity is the *other* key.
    std::fs::copy(&other_key, dir.path().join(".kan/identity")).unwrap();
    (dir, real_key)
}

/// v0.11 AC-10, and the inversion of what this test used to assert.
///
/// **Until v0.11 this test read "adopting the right key brings the claims
/// back", because under `Solo` a re-minted identity took the entire log out
/// of every read** — the claims were on disk, verifiable, and invisible, and
/// `adopt` was the way back. Under `Local` there is nothing to bring back:
/// the claims are authored by an author *in the log*, so the default read
/// shows them before `adopt` runs at all. #90's failure mode disappeared
/// rather than being guarded against (`.design/identity-surface.md`, the
/// consequence it states first).
///
/// So the test now pins both halves of that: the log stays visible through
/// the re-mint, and `adopt` still does the job it still has — repointing the
/// workspace at the key it should be *writing* under. Minting a second
/// identity is still wrong; it just stopped being a data-visibility event.
#[test]
fn a_re_minted_identity_no_longer_hides_the_log_and_adopt_still_repoints_writes() {
    let (dir, real_key) = orphaned_workspace();
    let real_did = kan(dir.path(), Some(&real_key), &["identity", "did"]).stdout;
    let orphan_did = kan(dir.path(), None, &["identity", "did"]).stdout;
    assert_ne!(
        real_did, orphan_did,
        "the fixture is not in #90's shape: the workspace resolves the same key that \
         wrote the log, so there is nothing to test"
    );

    // Before adopt: visible, and nothing excluded. This is the assertion that
    // used to read `0` claims and `3` excluded.
    let before = kan(dir.path(), None, &["show", "work", "--json"]);
    assert!(before.ok, "{}", before.stderr);
    let before: serde_json::Value = serde_json::from_str(&before.stdout).unwrap();
    assert_eq!(
        before["claims"].as_array().unwrap().len(),
        3,
        "a re-minted identity hid the log, which is exactly what `Local` exists to stop: \
         {before}"
    );
    assert_eq!(
        before["excluded_by_trust"], 0,
        "nothing authored in this log should be excluded from a default read: {before}"
    );

    let adopted = kan(
        dir.path(),
        None,
        &["identity", "adopt", "--key", real_key.to_str().unwrap()],
    );
    assert!(adopted.ok, "adopt failed: {}", adopted.stderr);
    assert!(
        adopted.stdout.contains("authored 3 of the"),
        "adopt did not say what it checked against: {}",
        adopted.stdout
    );

    // After adopt: the reads are unchanged -- they were already right -- and
    // the *writing* identity is now the log's own.
    let after = kan(dir.path(), None, &["show", "work", "--json"]);
    assert!(after.ok, "{}", after.stderr);
    let after: serde_json::Value = serde_json::from_str(&after.stdout).unwrap();
    assert_eq!(after["claims"].as_array().unwrap().len(), 3);
    assert_eq!(after["excluded_by_trust"], 0);
    assert_eq!(
        kan(dir.path(), None, &["identity", "did"]).stdout,
        real_did,
        "adopt did not repoint the workspace at the adopted key"
    );
}

/// AC-6's **negative control**: adopting a key that authored nothing here is
/// refused, and nothing is changed.
///
/// This is the property that makes `adopt` a recovery path rather than a
/// faster way to make the problem worse. Someone reaching for it has already
/// lost track of which key is theirs; letting them adopt the wrong one would
/// leave the log invisible under a *second* identity and give them every
/// reason to conclude the data is gone.
#[test]
fn adopting_a_key_that_authored_nothing_is_refused() {
    let (dir, _real_key) = orphaned_workspace();
    let stranger = dir.path().join("stranger");

    let identity_before = std::fs::read(dir.path().join(".kan/identity")).unwrap();

    let refused = kan(
        dir.path(),
        None,
        &["identity", "adopt", "--key", stranger.to_str().unwrap()],
    );
    assert!(
        !refused.ok,
        "adopted a key with no claims in this log: {}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("authored none"),
        "the refusal did not say why: {}",
        refused.stderr
    );
    // It names what the log *does* have, which is the actionable part.
    assert!(
        refused.stderr.contains("did:key:"),
        "the refusal did not name the log's real authors: {}",
        refused.stderr
    );
    assert_eq!(
        identity_before,
        std::fs::read(dir.path().join(".kan/identity")).unwrap(),
        "a refused adopt changed the workspace's identity anyway"
    );
}

/// Adopt names a key that already exists; it never creates one.
///
/// `load_or_create`'s contract is to produce a key one way or another, which
/// is exactly wrong here — quietly minting the identity someone is trying to
/// recover from losing is the failure this command exists to end.
#[test]
fn adopting_a_path_with_no_key_fails_rather_than_creating_one() {
    let (dir, _) = orphaned_workspace();
    let nothing = dir.path().join("no-key-here");

    let run = kan(
        dir.path(),
        None,
        &["identity", "adopt", "--key", nothing.to_str().unwrap()],
    );
    assert!(!run.ok, "adopt succeeded against a path holding no key");
    assert!(
        !nothing.exists(),
        "adopt created the key file it was supposed to be reading"
    );
}

/// Adopting into an empty log is allowed: there is nothing to contradict.
#[test]
fn adopting_into_an_empty_log_is_allowed() {
    let dir = git_repo();
    let key = dir.path().join("some-key");
    let did = kan(dir.path(), Some(&key), &["identity", "did"]).stdout;
    assert!(did.starts_with("did:key:"));

    // Opening without KAN_IDENTITY_FILE mints a seed-rooted identity, so this
    // also exercises adopt displacing a seed.
    let seeded = kan(dir.path(), None, &["identity", "did"]).stdout;
    assert_ne!(seeded, did);
    assert!(kan::sign::Identity::is_seed_rooted(
        &dir.path().join(".kan")
    ));

    let run = kan(
        dir.path(),
        None,
        &["identity", "adopt", "--key", key.to_str().unwrap()],
    );
    assert!(run.ok, "{}", run.stderr);
    assert!(run.stdout.contains("this log is empty"));
    assert!(
        run.stdout.contains("seed-rooted"),
        "adopt displaced a seed without saying so: {}",
        run.stdout
    );
    assert_eq!(
        kan(dir.path(), None, &["identity", "did"]).stdout,
        did,
        "the seed still decides the identity -- adopt reported success and changed nothing"
    );
}

/// Retiring a seed never destroys it: the previous root is moved aside, not
/// deleted. Someone reaching for `adopt` has already lost one identity, and a
/// command that silently discards a root secret while recovering from that is
/// not a recovery command.
#[test]
fn adopt_moves_a_displaced_seed_aside_rather_than_deleting_it() {
    let dir = git_repo();
    let key = dir.path().join("some-key");
    assert!(kan(dir.path(), Some(&key), &["identity", "did"]).ok);
    assert!(kan(dir.path(), None, &["identity", "did"]).ok);

    let seed_before = std::fs::read(dir.path().join(".kan/seed")).unwrap();
    assert!(
        kan(
            dir.path(),
            None,
            &["identity", "adopt", "--key", key.to_str().unwrap()]
        )
        .ok
    );

    let kept: Vec<_> = std::fs::read_dir(dir.path().join(".kan"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("seed.replaced-")
        })
        .collect();
    assert_eq!(kept.len(), 1, "the displaced seed was not preserved");
    assert_eq!(
        std::fs::read(kept[0].path()).unwrap(),
        seed_before,
        "the preserved seed is not the one that was displaced"
    );
}
