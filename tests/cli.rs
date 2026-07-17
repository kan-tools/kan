//! M3 golden path: the `kan` binary, invoked as a real subprocess (not
//! library calls), proving the CLI wiring — argument parsing, `.kan/`
//! resolution, and persistence across separate process invocations — works
//! end to end, not just the library code it calls into.
//!
//! M4b's workspace anchor is a real git-genesis hash (`crate::git`), so
//! every fixture needs an actual git repo with at least one commit — `kan`
//! now genuinely requires running inside one (`docs/SPEC.md` §5).

use std::process::Command;

fn kan(dir: &std::path::Path, args: &[&str]) -> (String, String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run kan binary");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
        output.status.success(),
    )
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

#[test]
fn golden_path_across_separate_invocations() {
    let dir = git_repo();

    let (cid_a, _, ok) = kan(
        dir.path(),
        &["observe", "the build is green", "--subject", "ci"],
    );
    assert!(ok);
    assert!(!cid_a.is_empty());

    let (_, _, ok) = kan(
        dir.path(),
        &[
            "plan",
            "add a retry wrapper",
            "--subject",
            "ci",
            "--cites",
            &cid_a,
        ],
    );
    assert!(ok);

    let (_, _, ok) = kan(
        dir.path(),
        &["decide", "use 3x retry with backoff", "--subject", "ci"],
    );
    assert!(ok);

    // Each invocation above was a separate process — persistence across
    // process boundaries, not just within one long-lived run.
    let (show_out, _, ok) = kan(dir.path(), &["show", "ci"]);
    assert!(ok);
    assert!(show_out.contains("3 live claim(s)"));
    assert!(show_out.contains("the build is green"));
    assert!(show_out.contains("add a retry wrapper"));
    assert!(show_out.contains("use 3x retry with backoff"));

    let (status_out, _, ok) = kan(dir.path(), &["status", "ci"]);
    assert!(ok);
    assert!(status_out.contains("Decision"));
    assert!(status_out.contains("use 3x retry with backoff"));
}

#[test]
fn session_start_and_end() {
    let dir = git_repo();
    let (_, _, ok) = kan(dir.path(), &["session", "start"]);
    assert!(ok);
    let (_, _, ok) = kan(
        dir.path(),
        &["session", "end", "--notes", "wrapped up for the day"],
    );
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "session"]);
    assert!(ok);
    assert!(show_out.contains("session started"));
    assert!(show_out.contains("session ended: wrapped up for the day"));
}

#[test]
fn show_on_unknown_subject_is_not_an_error() {
    let dir = git_repo();
    let (out, _, ok) = kan(dir.path(), &["show", "does-not-exist"]);
    assert!(ok);
    assert!(out.contains("no claims"));
}

#[test]
fn invalid_cites_is_a_clean_error() {
    let dir = git_repo();
    let (_, err, ok) = kan(dir.path(), &["observe", "x", "--cites", "not-a-cid"]);
    assert!(!ok);
    assert!(err.contains("invalid CID"));
}

#[test]
fn same_merges_two_subjects_into_one_view() {
    let dir = git_repo();
    let (_, _, ok) = kan(
        dir.path(),
        &["observe", "crashes on startup", "--subject", "bug-42"],
    );
    assert!(ok);
    let (_, _, ok) = kan(
        dir.path(),
        &["observe", "reported by a user", "--subject", "issue-7"],
    );
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("1 live claim(s)"));

    let (_, _, ok) = kan(dir.path(), &["same", "bug-42", "issue-7"]);
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("merged with"));
    assert!(show_out.contains("crashes on startup"));
    assert!(show_out.contains("reported by a user"));
}
