//! #181: `kan show` computed `GitAncestry` edges and then discarded every one
//! of them.
//!
//! `related_subjects_by_file` exists to surface REQ-20's same-file relations.
//! It called `relations::compute_default`, which is `[&GitAncestry,
//! &GitSameFile]`, and then kept only `SameFile` edges. `GitAncestry` spawns
//! `git merge-base --is-ancestor` per distinct commit pair, over **every live
//! claim in the workspace** — a same-file relation is inherently
//! cross-subject — so the whole cost bought edges the next loop threw away.
//!
//! Measured on `kan-tools/day`'s 12 MB log: **141 seconds**, against 72 ms for
//! `show --json`, which never calls this at all. That asymmetry is why it
//! survived — it is invisible to `day`, to agents, and to every automated
//! consumer, and hits only the person typing.
//!
//! **The assertion is "zero", not a count.** `tests/git_ancestry_cache.rs`
//! asserted an exact number against a property that is only probabilistic and
//! flaked at roughly 1.4%. "This code path makes no ancestry calls at all" is
//! a property rather than a measurement, so it cannot flake.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn run_git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("git")
        .success();
    assert!(ok, "git {args:?} failed");
}

fn commit(dir: &Path, msg: &str) {
    run_git(
        dir,
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            msg,
        ],
    );
}

/// A `git` ahead of the real one on `PATH` that logs each invocation, then
/// execs the real binary so behaviour is unchanged — only observable.
fn install_git_shim(bin_dir: &Path, log: &Path) {
    let real = String::from_utf8_lossy(
        &Command::new("/usr/bin/which")
            .arg("git")
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let shim = bin_dir.join("git");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            real
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim, perms).unwrap();
}

#[test]
fn show_makes_no_ancestry_calls_because_it_uses_no_ancestry_edges() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    kan::sign::Identity::generate().save(&key).unwrap();

    run_git(dir.path(), &["init", "-q"]);
    commit(dir.path(), "one");

    let kan = |args: &[&str], path: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
        cmd.args(args)
            .current_dir(dir.path())
            .env("KAN_NO_KEYCHAIN", "1")
            .env("KAN_IDENTITY_FILE", &key);
        if let Some(p) = path {
            cmd.env("PATH", p);
        }
        let out = cmd.output().expect("kan");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.success(),
        )
    };

    // Two claims anchored to DIFFERENT commits, so `GitAncestry` has a real
    // pair to compare. Without this the fixture cannot discriminate: one
    // commit means no distinct pairs and no subprocess either way.
    let (_, err, ok) = kan(&["observe", "first", "--subject", "alpha"], None);
    assert!(ok, "setup write failed: {err}");
    commit(dir.path(), "two");
    let (_, err, ok) = kan(&["observe", "second", "--subject", "beta"], None);
    assert!(ok, "setup write failed: {err}");

    let bin = dir.path().join("shim-bin");
    fs::create_dir_all(&bin).unwrap();
    let log = dir.path().join("git-calls.log");
    install_git_shim(&bin, &log);
    let shimmed = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());

    let (out, err, ok) = kan(&["show", "alpha"], Some(&shimmed));
    assert!(ok, "show failed: {err}");
    assert!(out.contains("alpha"), "show produced nothing useful: {out}");

    let calls = fs::read_to_string(&log).unwrap_or_default();
    let ancestry: Vec<&str> = calls
        .lines()
        .filter(|l| l.contains("merge-base") || l.contains("is-ancestor"))
        .collect();
    assert!(
        ancestry.is_empty(),
        "`kan show` made {} ancestry call(s) whose edges it then discards (#181):\n  {}",
        ancestry.len(),
        ancestry.join("\n  ")
    );
}
