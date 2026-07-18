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

/// AC-11: `kan show` on a merged subject names at least one witness
/// (author + direction), not just the flat merged subject list.
#[test]
fn show_on_a_merged_subject_names_a_witness() {
    let dir = git_repo();
    kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    kan(dir.path(), &["observe", "y", "--subject", "issue-7"]);
    kan(dir.path(), &["same", "bug-42", "issue-7"]);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("merged by"));
    assert!(show_out.contains("did:key:"));
    assert!(show_out.contains("bug-42"));
    assert!(show_out.contains("issue-7"));
}

/// AC-12: `kan show` on a subject sharing a file-anchor with another
/// subject lists it as related.
#[test]
fn show_lists_a_subject_sharing_a_file_anchor_as_related() {
    let dir = git_repo();
    kan(
        dir.path(),
        &[
            "observe",
            "x",
            "--subject",
            "bug-42",
            "--file",
            "src/foo.rs",
        ],
    );
    kan(
        dir.path(),
        &[
            "observe",
            "y",
            "--subject",
            "issue-7",
            "--file",
            "src/foo.rs",
        ],
    );

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("related subjects (same file)"));
    assert!(show_out.contains("issue-7"));
}

/// AC-1: `kan resolve` produces two claims (a `Resolution` and a
/// `Status{Resolved}` citing it) and `kan status` reflects the settled
/// resolved state.
#[test]
fn resolve_pair_writes_resolution_and_status() {
    let dir = git_repo();
    kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);

    let (cid, _, ok) = kan(dir.path(), &["resolve", "bug-42", "fixed"]);
    assert!(ok);
    assert!(!cid.is_empty(), "bare stdout should be the Resolution CID");

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("Resolution"));
    assert!(show_out.contains("Status"));
    assert!(show_out.contains("Resolved"));

    let (status_out, _, ok) = kan(dir.path(), &["status", "bug-42"]);
    assert!(ok);
    assert!(status_out.contains("Settled"));
    assert!(status_out.contains("Resolved"));
}

/// AC-2: `kan block` produces a `Blocker` + `Status{Blocked}` pair, same
/// shape as AC-1.
#[test]
fn block_pair_writes_blocker_and_status() {
    let dir = git_repo();
    kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);

    let (cid, _, ok) = kan(dir.path(), &["block", "bug-42", "waiting on upstream"]);
    assert!(ok);
    assert!(!cid.is_empty());

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains("Blocker"));
    assert!(show_out.contains("waiting on upstream"));
    assert!(show_out.contains("Blocked"));

    let (status_out, _, ok) = kan(dir.path(), &["status", "bug-42"]);
    assert!(ok);
    assert!(status_out.contains("Settled"));
    assert!(status_out.contains("Blocked"));
}

/// AC-3 (first half): `kan retract` on the caller's own claim excludes it
/// from the live set on the next fold. The second half — rejecting another
/// author's claim at write time — needs a genuinely different signing
/// identity, which the CLI's single-identity-per-repo model can't produce;
/// see `retract_rejects_another_authors_claim_at_write_time` in
/// `tests/write_surface.rs` for that half, at the library level.
#[test]
fn retract_excludes_own_claim_from_the_live_set() {
    let dir = git_repo();
    let (cid, _, ok) = kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    assert!(ok);

    let (_, _, ok) = kan(dir.path(), &["retract", &cid]);
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(!show_out.contains("Observation"));

    // Retracting a CID that was never written should fail cleanly, not panic.
    let (_, err, ok) = kan(
        dir.path(),
        &[
            "retract",
            "bafyreif4au544xcim6pd62nvks5vhgdj5u3tdkqecg4zvjsfqxfj66lnai",
        ],
    );
    assert!(!ok);
    assert!(err.contains("no such claim"));
}

/// AC-4: `kan mark` writes a bare `Status{InProgress}` claim.
#[test]
fn mark_writes_a_bare_status_claim() {
    let dir = git_repo();
    kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);

    let (cid, _, ok) = kan(dir.path(), &["mark", "bug-42", "in-progress"]);
    assert!(ok);
    assert!(!cid.is_empty());

    let (status_out, _, ok) = kan(dir.path(), &["status", "bug-42"]);
    assert!(ok);
    assert!(status_out.contains("InProgress"));
}

/// AC-5: `kan resolve --cites` round-trips a citation the same way
/// `observe --cites` already does.
#[test]
fn resolve_cites_round_trips() {
    let dir = git_repo();
    let (prior_cid, _, ok) = kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    assert!(ok);

    let (_, _, ok) = kan(
        dir.path(),
        &["resolve", "bug-42", "fixed", "--cites", &prior_cid],
    );
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains(&prior_cid));
}

/// `kan same --cites` round-trips too (the other half of AC-5).
#[test]
fn same_cites_round_trips() {
    let dir = git_repo();
    let (prior_cid, _, ok) = kan(dir.path(), &["observe", "x", "--subject", "bug-42"]);
    assert!(ok);
    kan(dir.path(), &["observe", "y", "--subject", "issue-7"]);

    let (_, _, ok) = kan(
        dir.path(),
        &["same", "bug-42", "issue-7", "--cites", &prior_cid],
    );
    assert!(ok);

    let (show_out, _, ok) = kan(dir.path(), &["show", "bug-42"]);
    assert!(ok);
    assert!(show_out.contains(&prior_cid));
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
