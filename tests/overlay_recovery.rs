//! Issue #150 — a workspace already poisoned by the log/overlay duplication
//! must *recover*, not merely stop getting worse.
//!
//! The distinction is the whole issue. Skipping log-resident records at ingest
//! (#146 part 2) stops the state being created. It does nothing for a
//! workspace that already has it — and there, one read under a role identity
//! had made every subsequent command fail, as the primary identity too,
//! permanently. Verified against the released v0.9.1-beta.1 binary: it bricks
//! such a workspace, and a build carrying only the ingest fix still refused to
//! open it, with a clearer message and the same dead workspace.
//!
//! Recovery is safe because the overlay is *disposable* by design: everything
//! in it is reconstructible from `.claims/`, which is why the issue's reporter
//! could repair it by hand with `rm -rf .kan/overlay .kan/index.sqlite`. This
//! does that automatically, and says so.

use std::path::Path;
use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan(dir: &Path, key: Option<&Path>, args: &[&str]) -> Run {
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

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git {args:?} failed");
}

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );
    dir
}

/// A workspace in the #150 state: the overlay holds claims the log also has.
///
/// Built by copying the log's own CAR over the overlay's rather than by
/// replaying the defect, because the defect is fixed — the point here is a
/// workspace that *arrives* in this state, however it got there, which is
/// exactly the situation of anyone who ran a released v0.9.1.
fn poisoned_workspace() -> tempfile::TempDir {
    let dir = git_repo();

    let wrote = kan(
        dir.path(),
        None,
        &["observe", "a claim of my own", "--subject", "test/a"],
    );
    assert!(wrote.ok, "setup write failed: {}", wrote.stderr);

    let published = kan(dir.path(), None, &["publish", "test/a"]);
    assert!(published.ok, "setup publish failed: {}", published.stderr);
    git(dir.path(), &["add", "-A"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-qm",
            "publish",
        ],
    );

    let kan_dir = dir.path().join(".kan");
    let overlay = kan_dir.join("overlay");
    std::fs::create_dir_all(&overlay).unwrap();
    for f in ["repo.car", "HEAD"] {
        std::fs::copy(kan_dir.join("log").join(f), overlay.join(f))
            .unwrap_or_else(|e| panic!("could not seed the overlay with {f}: {e}"));
    }
    // The index must not be able to skip its rebuild, or nothing reads the
    // overlay at all and the test would pass without exercising anything.
    let _ = std::fs::remove_file(kan_dir.join("index.sqlite"));

    dir
}

#[test]
fn a_poisoned_overlay_is_rebuilt_rather_than_bricking_the_workspace() {
    let dir = poisoned_workspace();

    let run = kan(dir.path(), None, &["show", "test/a"]);

    assert!(
        run.ok,
        "the workspace stayed unopenable:\nstdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert!(
        !run.stderr.contains("UNIQUE constraint"),
        "the sqlite constraint still leaks out: {}",
        run.stderr
    );
    // Loud, not silent: a store that rearranges itself without saying so is
    // not one anyone can reason about.
    assert!(
        run.stderr.contains("Rebuilding the overlay"),
        "recovery happened silently: {}",
        run.stderr
    );
    // And the claims are actually there afterwards.
    assert!(
        run.stdout.contains("a claim of my own"),
        "recovered, but the claim is missing: {}",
        run.stdout
    );
}

/// Healing once is a repair; healing on every open is a loop that would also
/// re-parse `.claims/` forever.
#[test]
fn recovery_happens_once_and_then_stays_quiet() {
    let dir = poisoned_workspace();

    let first = kan(dir.path(), None, &["show", "test/a"]);
    assert!(first.ok, "first open failed: {}", first.stderr);
    assert!(
        first.stderr.contains("Rebuilding the overlay"),
        "expected the first open to repair: {}",
        first.stderr
    );

    let second = kan(dir.path(), None, &["show", "test/a"]);
    assert!(second.ok, "second open failed: {}", second.stderr);
    assert!(
        !second.stderr.contains("Rebuilding the overlay"),
        "the repair did not stick -- it ran again: {}",
        second.stderr
    );
    assert!(
        second.stdout.contains("a claim of my own"),
        "claims lost on the second open: {}",
        second.stdout
    );
}

/// The log is never touched. The overlay is derived and may be rebuilt; the
/// log is the source of truth and rebuilding around it must not cost a byte.
#[test]
fn recovery_does_not_touch_the_log() {
    let dir = poisoned_workspace();
    let car = dir.path().join(".kan/log/repo.car");
    let before = std::fs::read(&car).unwrap();

    let run = kan(dir.path(), None, &["show", "test/a"]);
    assert!(run.ok, "open failed: {}", run.stderr);

    let after = std::fs::read(&car).unwrap();
    assert_eq!(
        before, after,
        "recovery rewrote the log, which is the one store it must never touch"
    );
}
