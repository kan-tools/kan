//! `.design/v0.9-milestone.md` REQ-3/AC-3 — `kan status` says which subjects
//! would survive losing `.kan/`.
//!
//! This is the half of durability that acts *before* the loss. `kan restore`
//! (REQ-1) answers "what comes back"; this answers "what wouldn't", while
//! there is still time to do something about it. The kan-native move is to
//! make the gap **data** — a column, not a nag or a hook.

use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn kan(dir: &std::path::Path, key: &std::path::Path, args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(dir)
        .env("KAN_IDENTITY_FILE", key)
        .output()
        .expect("failed to run kan binary");
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

/// A workspace holding one subject in each of the three states.
fn three_states() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = git_repo();
    let key = dir.path().join("key");

    // unpublished: written, never published.
    assert!(kan(dir.path(), &key, &["observe", "never-shared", "local only"]).ok);

    // published: written, published, untouched since.
    assert!(kan(dir.path(), &key, &["observe", "fully-shared", "shared"]).ok);
    assert!(kan(dir.path(), &key, &["publish", "fully-shared"]).ok);

    // stale: published, then written to again.
    assert!(kan(dir.path(), &key, &["observe", "drifted", "first"]).ok);
    assert!(kan(dir.path(), &key, &["publish", "drifted"]).ok);
    assert!(
        kan(
            dir.path(),
            &key,
            &["observe", "drifted", "second, after publishing"]
        )
        .ok
    );

    (dir, key)
}

fn durability_by_subject(dir: &std::path::Path, key: &std::path::Path) -> Vec<(String, String)> {
    let run = kan(dir, key, &["status", "--json"]);
    assert!(run.ok, "status --json failed: {}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    value["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["subject"].as_str().unwrap().to_string(),
                s["durability"]
                    .as_str()
                    .unwrap_or_else(|| panic!("no durability field: {s}"))
                    .to_string(),
            )
        })
        .collect()
}

/// AC-3: all three states reported correctly in `--json`.
#[test]
fn the_three_durability_states_are_reported() {
    let (dir, key) = three_states();
    let states = durability_by_subject(dir.path(), &key);
    let get = |name: &str| -> String {
        states
            .iter()
            .find(|(s, _)| s == name)
            .unwrap_or_else(|| panic!("{name} missing from status: {states:?}"))
            .1
            .clone()
    };

    assert_eq!(get("never-shared"), "unpublished");
    assert_eq!(get("fully-shared"), "published");
    assert_eq!(
        get("drifted"),
        "stale",
        "a subject written to after publishing must read as stale: {states:?}"
    );
}

/// AC-3: the same three states in the rendered output, for all three —
/// including the healthy one.
///
/// A column that appears only when something is wrong is a nag, and the
/// point of REQ-5 is to make the gap legible as data rather than to scold.
#[test]
fn the_rendered_status_carries_the_column_for_every_subject() {
    let (dir, key) = three_states();
    let run = kan(dir.path(), &key, &["status"]);
    assert!(run.ok, "{}", run.stderr);

    for (subject, expected) in [
        ("never-shared", "[unpublished]"),
        ("fully-shared", "[published]"),
        ("drifted", "[stale]"),
    ] {
        let line = run
            .stdout
            .lines()
            .find(|l| l.starts_with(subject))
            .unwrap_or_else(|| panic!("no line for {subject}:\n{}", run.stdout));
        assert!(
            line.contains(expected),
            "expected {expected} on {subject}'s line, got: {line}"
        );
    }
}

/// Publishing again clears `stale` — the column tracks the actual gap, not
/// a timestamp.
///
/// This is the case that decided the implementation. `kan publish --all`
/// refreshes a subject's file **without** appending a new `Publication`
/// claim, so a staleness check comparing against that claim's timestamp
/// would keep reporting a gap the operator had just closed. Nothing teaches
/// someone to ignore a column faster.
#[test]
fn republishing_clears_stale() {
    let (dir, key) = three_states();
    assert_eq!(
        durability_by_subject(dir.path(), &key)
            .iter()
            .find(|(s, _)| s == "drifted")
            .unwrap()
            .1,
        "stale"
    );

    // `--all` specifically, since that is the path that writes no new
    // Publication claim.
    let refreshed = kan(dir.path(), &key, &["publish", "--all"]);
    assert!(refreshed.ok, "{}", refreshed.stderr);

    assert_eq!(
        durability_by_subject(dir.path(), &key)
            .iter()
            .find(|(s, _)| s == "drifted")
            .unwrap()
            .1,
        "published",
        "republishing did not clear stale -- the column is tracking the wrong thing"
    );
}

/// A repo that has never published anything reports every subject
/// `unpublished`, and does not fail for want of a `.claims/` directory.
#[test]
fn a_repo_that_never_published_reports_every_subject_unpublished() {
    let dir = git_repo();
    let key = dir.path().join("key");
    assert!(kan(dir.path(), &key, &["observe", "a", "one"]).ok);
    assert!(kan(dir.path(), &key, &["observe", "b", "two"]).ok);

    let states = durability_by_subject(dir.path(), &key);
    assert_eq!(states.len(), 2);
    assert!(
        states.iter().all(|(_, d)| d == "unpublished"),
        "expected everything unpublished: {states:?}"
    );
}

/// The column survives losing the log and coming back: after `rm -rf .kan`
/// and `kan restore`, restored subjects read as `published` — they are, by
/// construction, exactly the ones that were in the tree.
///
/// Ties the two halves of the milestone together: the column's promise is
/// that `published` means restorable, and this is that promise checked
/// against the actual restore rather than against its own bookkeeping.
#[test]
fn what_the_column_called_published_is_what_restore_brings_back() {
    let (dir, key) = three_states();
    std::fs::remove_dir_all(dir.path().join(".kan")).unwrap();
    assert!(kan(dir.path(), &key, &["restore"]).ok);

    let states = durability_by_subject(dir.path(), &key);
    let names: Vec<&str> = states.iter().map(|(s, _)| s.as_str()).collect();

    // The unpublished subject is simply gone -- it was never in the tree.
    assert!(
        !names.contains(&"never-shared"),
        "an unpublished subject came back from a restore: {states:?}"
    );
    // Everything that did come back is fully in the tree, by construction.
    for (subject, durability) in &states {
        assert_eq!(
            durability, "published",
            "{subject} came back from a restore but does not read as published: {states:?}"
        );
    }
}
