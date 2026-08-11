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

/// `review/full-pass-v0.12` (git argument surface): a `Sha` reaching
/// `is_ancestor` is untrusted claim text. A `-`-prefixed value must be
/// refused at the boundary — treated as no ancestry edge — never handed to
/// git where it could be read as an option.
#[test]
fn a_dash_prefixed_sha_is_refused_at_the_boundary() {
    let dir = tempfile::tempdir().unwrap();
    git_ok(dir.path(), &["init", "-q"]);
    git_ok(
        dir.path(),
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "first",
        ],
    );
    let sha1 = String::from_utf8(git(dir.path(), &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let substrate = GitSubstrate::open(dir.path()).unwrap();

    // A crafted option-shaped SHA participates in no edge and does not error.
    for hostile in ["--output=/tmp/pwned", "-oops", "--all"] {
        let edge = substrate
            .is_ancestor(&hostile.to_string(), &sha1)
            .expect("a malformed sha must be a clean no-edge, not an error");
        assert!(
            !edge,
            "a dash-prefixed sha must not be treated as a real revision"
        );
    }
    // A non-hex but harmless value is likewise no edge.
    assert!(!substrate
        .is_ancestor(&"not-a-sha".to_string(), &sha1)
        .unwrap());
}

/// REQ-10: opening outside a git repo gives an actionable message, not
/// git's raw `fatal: not a git repository` plumbing.
#[test]
fn opening_outside_a_repo_names_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    let err = match GitSubstrate::open(dir.path()) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a non-repo directory must not open as a git substrate"),
    };
    assert!(
        err.contains("not inside a git repository") && err.contains("git init"),
        "the error must name the fix, got: {err}"
    );
    assert!(
        !err.contains("fatal:") && !err.contains("rev-parse"),
        "raw git plumbing must not be the operator-facing message: {err}"
    );
}
