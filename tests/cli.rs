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

/// AC-1 (`.design/agent-ax-and-tool-boundary.md`): `session` was removed
/// from kan's CLI vocabulary entirely (ADR-18) — it's now the companion
/// tool's job to build a session convention on top of `observe`/`cites`.
#[test]
fn session_is_not_a_recognized_subcommand() {
    let dir = git_repo();
    let (_, err, ok) = kan(dir.path(), &["session", "start"]);
    assert!(!ok);
    assert!(err.contains("session") || err.to_lowercase().contains("unrecognized"));
}

#[test]
fn show_on_unknown_subject_is_not_an_error() {
    let dir = git_repo();
    let (out, _, ok) = kan(dir.path(), &["show", "does-not-exist"]);
    assert!(ok);
    assert!(out.contains("no claims"));
}

/// AC-5: a subject-lookup miss lists the subjects that actually exist,
/// instead of just "no claims" — the concrete fix for a silent typo
/// silently reading as "never mentioned."
#[test]
fn show_on_unknown_subject_hints_at_real_subjects() {
    let dir = git_repo();
    kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    kan(dir.path(), &["observe", "y", "--subject", "issue-7"]);

    let (out, _, ok) = kan(dir.path(), &["show", "bug-43"]);
    assert!(ok);
    assert!(out.contains("bug-42"));
    assert!(out.contains("issue-7"));

    let (out, _, ok) = kan(dir.path(), &["status", "bug-43"]);
    assert!(ok);
    assert!(out.contains("bug-42"));
    assert!(out.contains("issue-7"));
}

/// AC-6: bare stdout stays exactly the CID (load-bearing for `--cites`
/// piping); `--verbose` switches to a human-readable confirmation that
/// still contains the CID.
#[test]
fn verbose_flag_changes_stdout_default_stays_bare_cid() {
    let dir = git_repo();
    let (cid, _, ok) = kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    assert!(ok);
    assert!(
        !cid.contains(' '),
        "default stdout should be exactly the bare CID: {cid:?}"
    );

    let (verbose_out, _, ok) = kan(
        dir.path(),
        &["observe", "y", "--subject", "bug-42", "--verbose"],
    );
    assert!(ok);
    assert!(verbose_out.contains("bug-42"));
    assert!(verbose_out.contains("Observation"));
    assert!(
        verbose_out.len() > cid.len(),
        "--verbose output should be more than just the bare CID: {verbose_out:?}"
    );
}

/// AC-4: `kan mcp install` prints both registration paths without mutating
/// any config.
#[test]
fn mcp_install_prints_both_registration_paths() {
    let dir = git_repo();
    let (out, _, ok) = kan(dir.path(), &["mcp", "install"]);
    assert!(ok);
    assert!(out.contains("claude mcp add"));
    assert!(out.contains(env!("CARGO_BIN_EXE_kan")));
    assert!(out.contains("/plugin install"));
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

/// Issue #3: `kan` walks upward to find the repo root (`.git/`), the same
/// search `git` itself does, so `.kan/` always lands beside `.git/`
/// (ADR-3) regardless of which subdirectory it's invoked from.
#[test]
fn kan_dir_resolves_upward_from_a_subdirectory() {
    let dir = git_repo();
    let nested = dir.path().join("src").join("deep");
    std::fs::create_dir_all(&nested).unwrap();

    let (cid, _, ok) = kan(&nested, &["observe", "found from a subdirectory"]);
    assert!(ok);
    assert!(!cid.is_empty());

    assert!(
        dir.path().join(".kan").is_dir(),
        ".kan/ should be created at the repo root, not the invoking subdirectory"
    );
    assert!(!nested.join(".kan").exists());

    // And it's visible from the root too — same workspace, same claim.
    let (show_out, _, ok) = kan(dir.path(), &["show", "general"]);
    assert!(ok);
    assert!(show_out.contains("found from a subdirectory"));
}
