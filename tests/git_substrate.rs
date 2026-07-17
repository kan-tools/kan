//! Direct coverage of `GitSubstrate` edge cases found during the software
//! review pass: a shallow clone must be rejected rather than silently
//! producing a wrong-but-different genesis hash, and a repo with zero
//! commits must fail cleanly, not panic.

use std::process::Command;

use kan::git::GitSubstrate;

fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run git")
}

fn git_ok(dir: &std::path::Path, args: &[&str]) {
    let output = git(dir, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn genesis_rejects_a_shallow_clone() {
    let origin = tempfile::tempdir().unwrap();
    git_ok(origin.path(), &["init", "-q"]);
    for msg in ["first", "second", "third"] {
        git_ok(
            origin.path(),
            &[
                "-c",
                "user.email=kan-test@example.com",
                "-c",
                "user.name=kan-test",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                msg,
            ],
        );
    }

    let shallow = tempfile::tempdir().unwrap();
    // `--no-local`: git silently ignores `--depth` for local-filesystem
    // clones ("--depth is ignored in local clones") unless forced off the
    // fast local-copy path, so a plain local `git clone --depth 1` here
    // would produce a full (non-shallow) clone and this test would pass
    // for the wrong reason.
    let clone = Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--no-local",
            "-q",
            origin.path().to_str().unwrap(),
            shallow.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to run git clone");
    assert!(
        clone.status.success(),
        "git clone --depth 1 failed: {}",
        String::from_utf8_lossy(&clone.stderr)
    );

    let substrate = GitSubstrate::open(shallow.path()).unwrap();
    let err = substrate.genesis().unwrap_err();
    assert!(
        matches!(err, kan::git::Error::ShallowClone),
        "expected ShallowClone, got {err:?}"
    );
}

#[test]
fn genesis_fails_cleanly_on_a_repo_with_no_commits() {
    let dir = tempfile::tempdir().unwrap();
    git_ok(dir.path(), &["init", "-q"]);

    let substrate = GitSubstrate::open(dir.path()).unwrap();
    // Must return a clean Err, not panic -- HEAD doesn't resolve to
    // anything yet.
    assert!(substrate.genesis().is_err());
}
